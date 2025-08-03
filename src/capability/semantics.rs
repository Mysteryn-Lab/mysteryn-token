use super::Capability;
use std::convert::TryFrom;
use std::fmt::Debug;

const ACTION_DELIMITER: &str = "; ";

pub trait Resource: ToString + TryFrom<String> + PartialEq + Clone {
    fn contains(&self, other: &Self) -> bool;
}

pub trait Action: Ord + TryFrom<String> + ToString + Clone {}

pub trait CapabilitySemantics<R, A>
where
    R: Resource,
    A: Action,
{
    fn parse_resource(&self, resource: &str) -> Option<R> {
        let res = resource.trim();
        if res.is_empty() {
            None
        } else {
            R::try_from(res.to_owned()).ok()
        }
    }

    fn parse_action(&self, action: &str) -> Option<(A, Option<String>)> {
        let s = String::from(action).trim().to_string();
        if let Some((act, att)) = s.split_once(ACTION_DELIMITER) {
            let act = act.trim();
            let att = att.trim();
            if act.is_empty() {
                return None;
            }
            let Ok(act) = A::try_from(act.to_string()) else {
                return None;
            };
            if att.is_empty() {
                return Some((act, None));
            }
            return Some((act, Some(att.to_string())));
        }
        if let Ok(a) = A::try_from(s.to_string()) {
            Some((a, None))
        } else {
            None
        }
    }

    /// Parse a resource and action string.
    fn parse(&self, resource: &str, action: &str) -> Option<CapabilityView<R, A>> {
        let parsed_resource = self.parse_resource(resource)?;
        let parsed_action = self.parse_action(action)?;

        Some(CapabilityView::new(
            parsed_resource,
            parsed_action.0,
            parsed_action.1,
        ))
    }

    fn parse_capability(&self, value: &Capability) -> Option<CapabilityView<R, A>> {
        self.parse(&value.resource, &value.action)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityView<R, A>
where
    R: Resource,
    A: Action,
{
    pub resource: R,
    pub action: A,
    pub attenuation: Option<String>,
}

impl<R, A> Debug for CapabilityView<R, A>
where
    R: Resource,
    A: Action,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action = if let Some(attenuation) = self.attenuation.as_ref() {
            self.action.to_string() + ACTION_DELIMITER + attenuation
        } else {
            self.action.to_string()
        };
        f.debug_struct("Capability")
            .field("resource", &self.resource.to_string())
            .field("action", &action)
            .finish()
    }
}

impl<R, A> CapabilityView<R, A>
where
    R: Resource,
    A: Action,
{
    /// Creates a new [`CapabilityView`] semantics view over a capability.
    pub fn new(resource: R, action: A, attenuation: Option<String>) -> Self {
        Self {
            resource,
            action,
            attenuation,
        }
    }

    pub fn enables(&self, other: &CapabilityView<R, A>) -> bool {
        self.resource.contains(&other.resource) && self.action >= other.action
    }

    pub fn resource(&self) -> &R {
        &self.resource
    }

    pub fn action(&self) -> &A {
        &self.action
    }
}

impl<R, A> From<&CapabilityView<R, A>> for Capability
where
    R: Resource,
    A: Action,
{
    fn from(value: &CapabilityView<R, A>) -> Self {
        if let Some(att) = value.attenuation.as_ref() {
            Capability::new(
                value.resource.to_string(),
                value.action.to_string() + ACTION_DELIMITER + att,
            )
        } else {
            Capability::new(value.resource.to_string(), value.action.to_string())
        }
    }
}

impl<R, A> From<CapabilityView<R, A>> for Capability
where
    R: Resource,
    A: Action,
{
    fn from(value: CapabilityView<R, A>) -> Self {
        if let Some(att) = value.attenuation.as_ref() {
            Capability::new(
                value.resource.to_string(),
                value.action.to_string() + ACTION_DELIMITER + att,
            )
        } else {
            Capability::new(value.resource.to_string(), value.action.to_string())
        }
    }
}
