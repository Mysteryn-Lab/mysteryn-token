use mysteryn_crypto::result::Error;
use serde::{
    Deserialize, Serialize,
    de::Deserializer,
    ser::{SerializeMap, Serializer},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, btree_map::Iter as BTreeMapIter},
    fmt::Debug,
    iter::FlatMap,
    ops::Deref,
};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents a single, flattened capability containing a resource and action.
pub struct Capability {
    pub resource: String,
    pub action: String,
}

impl Capability {
    pub fn new(resource: String, action: String) -> Self {
        Capability { resource, action }
    }
}

impl From<&Capability> for Capability {
    fn from(value: &Capability) -> Self {
        value.to_owned()
    }
}

impl From<(String, String)> for Capability {
    fn from(value: (String, String)) -> Self {
        Capability::new(value.0, value.1)
    }
}

impl From<(&str, &str)> for Capability {
    fn from(value: (&str, &str)) -> Self {
        Capability::new(value.0.to_owned(), value.1.to_owned())
    }
}

impl From<Capability> for (String, String) {
    fn from(value: Capability) -> Self {
        (value.resource, value.action)
    }
}

type MapImpl<K, V> = BTreeMap<K, V>;
type MapIter<'a, K, V> = BTreeMapIter<'a, K, V>;
type CapabilitiesImpl = MapImpl<String, Vec<String>>;
type CapabilitiesIterator<'a> = FlatMap<
    MapIter<'a, String, Vec<String>>,
    Vec<Capability>,
    fn((&'a std::string::String, &'a Vec<std::string::String>)) -> Vec<Capability>,
>;

/// The [Capabilities] struct contains capability data as a map-of-maps.
/// See `iter()` to deconstruct this map into a sequence of [Capability] datas.
///
/// ```
/// use mysteryn_token::capability::Capabilities;
/// use serde_json::json;
///
/// let capabilities = Capabilities::try_from(&json!({
///   "mailto:username@example.com": [
///     "msg/receive",
///     "msg/send"
///   ]
/// })).unwrap();
///
/// let resource = capabilities.get("mailto:username@example.com").unwrap();
/// assert_eq!(resource.get(0).unwrap(), "msg/receive");
/// assert_eq!(resource.get(1).unwrap(), "msg/send");
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Capabilities(CapabilitiesImpl);

impl Serialize for Capabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Capabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let t: BTreeMap<String, Vec<String>> = Deserialize::deserialize(deserializer)?;
        Ok(Capabilities(t))
    }
}

impl Capabilities {
    /// Using a [`FlatMap`] implementation, iterate over a [`Capabilities`] map-of-map
    /// as a sequence of [`Capability`] datas.
    ///
    /// ```
    /// use mysteryn_token::capability::{Capabilities, Capability};
    /// use serde_json::json;
    ///
    /// let capabilities = Capabilities::try_from(&json!({
    ///   "example://example.com/private/84MZ7aqwKn7sNiMGsSbaxsEa6EPnQLoKYbXByxNBrCEr": [
    ///     "wnfs/append"
    ///   ],
    ///   "mailto:username@example.com": [
    ///     "msg/receive",
    ///     "msg/send"
    ///   ]
    /// })).unwrap();
    ///
    /// assert_eq!(capabilities.iter().collect::<Vec<Capability>>(), vec![
    ///   Capability::from(("example://example.com/private/84MZ7aqwKn7sNiMGsSbaxsEa6EPnQLoKYbXByxNBrCEr", "wnfs/append")),
    ///   Capability::from(("mailto:username@example.com", "msg/receive")),
    ///   Capability::from(("mailto:username@example.com", "msg/send")),
    /// ]);
    /// ```
    pub fn iter(&self) -> CapabilitiesIterator {
        self.0.iter().flat_map(|(resource, actions)| {
            actions
                .iter()
                .map(|action: &String| Capability::from((resource.to_owned(), action.to_owned())))
                .collect()
        })
    }
}

impl<'a> IntoIterator for &'a Capabilities {
    type Item = Capability;
    type IntoIter = std::iter::FlatMap<
        std::collections::btree_map::Iter<
            'a,
            std::string::String,
            std::vec::Vec<std::string::String>,
        >,
        std::vec::Vec<Capability>,
        fn(
            (
                &'a std::string::String,
                &'a std::vec::Vec<std::string::String>,
            ),
        ) -> std::vec::Vec<Capability>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Deref for Capabilities {
    type Target = CapabilitiesImpl;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<Capability>> for Capabilities {
    type Error = Error;

    fn try_from(value: Vec<Capability>) -> Result<Self, Self::Error> {
        let mut resources: CapabilitiesImpl = BTreeMap::new();
        for resource in value {
            let (resource_name, action) = <(String, String)>::from(resource);

            let resource = if let Some(resource) = resources.get_mut(&resource_name) {
                resource
            } else {
                let resource: Vec<String> = Vec::new();
                resources.insert(resource_name.clone(), resource);
                resources.get_mut(&resource_name).unwrap()
            };

            if !resource.contains(&action) {
                resource.push(action);
            }
        }
        Capabilities::try_from(resources)
    }
}

impl From<Capabilities> for Vec<Capability> {
    fn from(capabilities: Capabilities) -> Self {
        let mut res: Vec<Capability> = vec![];
        for c in &capabilities {
            res.push(c);
        }
        res
    }
}

impl TryFrom<CapabilitiesImpl> for Capabilities {
    type Error = Error;

    fn try_from(value: CapabilitiesImpl) -> Result<Self, Self::Error> {
        for (resource, actions) in &value {
            if actions.is_empty() {
                // One or more abilities MUST be given for each resource.
                return Err(Error::ValidationError(format!(
                    "No abilities given for resource: {resource}"
                )));
            }
        }
        Ok(Capabilities(value))
    }
}

impl TryFrom<&Value> for Capabilities {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let map = value
            .as_object()
            .ok_or_else(|| Error::ValidationError("Capabilities must be an object.".to_string()))?;
        let mut resources: CapabilitiesImpl = BTreeMap::new();

        for (key, value) in map {
            let resource = key.to_owned();
            let actions_array = value
                .as_array()
                .ok_or_else(|| Error::ValidationError("Actions must be an array.".to_string()))?;

            let actions = {
                let mut actions: Vec<String> = Vec::new();
                for value in actions_array {
                    let action = value.as_str();
                    if let Some(action) = action {
                        actions.push(action.to_owned());
                    }
                }
                actions
            };

            resources.insert(resource, actions);
        }

        Capabilities::try_from(resources)
    }
}

impl TryFrom<&[(&str, &str)]> for Capabilities {
    type Error = Error;

    fn try_from(value: &[(&str, &str)]) -> Result<Self, Self::Error> {
        let mut resources: CapabilitiesImpl = BTreeMap::new();
        for (resource_name, action) in value {
            let resource = if let Some(resource) = resources.get_mut(*resource_name) {
                resource
            } else {
                let resource: Vec<String> = Vec::new();
                resources.insert((*resource_name).to_string(), resource);
                resources.get_mut(*resource_name).unwrap()
            };

            if !resource.contains(&(*action).to_string()) {
                resource.push((*action).to_string());
            }
        }
        Capabilities::try_from(resources)
    }
}
