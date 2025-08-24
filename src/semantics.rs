/**
 * This semantics realizes a general comparizon of capabilities.
 *
 * 1. Resource: "<scheme>:<path>"
 *    
 *    The resource is an URL-like path to resource (it can be a real URL).
 *    "scheme" is any application specific scheme, like "api", "docs".
 *    "path" is an URL-like path, like "user/1", "user/1/post/2". The path
 *    includes access to all its sub-paths, for example "user/1" includes any of
 *    "user/1/post/1", "user/1/post/2", etc. Verification is performed by first
 *    by comparing schemes, then comparing each part of paths between "/"
 *    sequentally.
 *    The special path "*" means all in a capability, and "some" in the
 *    requirement resource, for example the requirement "user/ *" allows
 *    "user/1", compared to the requirement "user" which doesn't allow it
 *    (as in this context "user" means all users, but "user/ *" means some user,
 *    but not all users).
 *
 *    Examples:
 *
 *    | Capability resource | Required resource | Includes                     |
 *    |---------------------|-------------------|------------------------------|
 *    | user                | user/1            | Yes                          |
 *    | user/1              | user              | No (required is higher)      |
 *    | user/1              | user/1            | Yes (are equal)              |
 *    | user/1              | user/1/doc/1      | Yes (required is included)   |
 *    | user/1              | user/2            | No (are not equal)           |
 *    | user/1              | doc/1             | No (are not equal)           |
 *    | *                   | user/1            | Yes (requred is included)    |
 *    | user/1              | *                 | No (reqired is higher level) |
 *    | user/1              | user/ *           | Yes                          |
 *    | user/ *             | user/1            | Yes                          |
 *    | user/1/post/1       | user/ * /post/2   | No                           |
 *
 * 2. Ability: "<namespace>/ability[/sub-ability]"
 *
 *    The ability is an action allowed for the resource.
 *    Its format is "namespace/ability[/sub-ability]". The special ability "*"
 *    always means "all" (in difference to its meaning for resource). It
 *    can be used at the end to include all sub-actions ("user/post/ *"), but
 *    not in the middle.
 *
 *    Examples:
 *
 *    | Capability ability  | Required ability  | Enables |
 *    |---------------------|-------------------|---------|
 *    | user/post           | user/post         | Yes     |
 *    | user/post           | user/post/draft   | Yes     |
 *    | user/post/draft     | user/post         | No      |
 *    | *                   | user/post         | Yes     |
 *    | user/post           | *                 | No      |
 *    | user/ *             | user/post         | Yes     |
 *    | user/post           | user/ *           | No      |
 *
 */
use crate::capability::{Action, CapabilitySemantics, Resource};
use mysteryn_crypto::result::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, fmt::Display};

/// Walk two path iterators (`self` and `other`) and return an ordering or `None`
fn walk_paths<'a, I>(mut self_it: I, mut other_it: I) -> Option<Ordering>
where
    I: Iterator<Item = &'a str>,
{
    loop {
        match (self_it.next(), other_it.next()) {
            // Both iterators have a part → compare
            (Some(s), Some(o)) => {
                if s == "*" || o == "*" {
                    continue; // wildcard matches anything
                }
                if s != o {
                    return Some(Ordering::Less);
                }
            }

            // `self` finished but `other` still has parts → self is a prefix
            (None, Some(o)) => {
                if o.is_empty() && other_it.next().is_none() {
                    // it was a trailing slash after the last part - treat as equal
                    return Some(Ordering::Equal);
                }
                return Some(Ordering::Greater); // e.g. "user" > "user/1"
            }

            // `other` finished but `self` still has parts → self may be a sub‑path
            (Some(s), None) => {
                if s.is_empty() && self_it.next().is_none() {
                    // it was a trailing slash after the last part - treat as equal
                    return Some(Ordering::Equal);
                }
                return Some(Ordering::Less);
            }

            // Both finished → paths are identical
            (None, None) => return Some(Ordering::Equal),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct GeneralAction {
    action: String,
}

impl Action for GeneralAction {}

impl TryFrom<String> for GeneralAction {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Ok(GeneralAction { action: value })
    }
}

impl Display for GeneralAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.action)
    }
}

impl PartialOrd for GeneralAction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GeneralAction {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.action == other.action {
            return Ordering::Equal;
        }

        walk_paths(self.action.split('/'), other.action.split('/')).unwrap()
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GeneralResource {
    resource: String,
}

impl Resource for GeneralResource {
    fn contains(&self, other: &Self) -> bool {
        matches!(
            walk_paths(self.resource.split('/'), other.resource.split('/')),
            Some(ord) if ord != Ordering::Less
        )
    }
}

impl TryFrom<String> for GeneralResource {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Ok(GeneralResource { resource: value })
    }
}

impl Display for GeneralResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.resource)
    }
}

pub struct GeneralSemantics {}

impl CapabilitySemantics<GeneralResource, GeneralAction> for GeneralSemantics {}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_general_resource() {
        let file = include_str!("../tests/fixtures/resource.csv");
        let mut rdr = csv::Reader::from_reader(file.as_bytes());

        for result in rdr.records() {
            let record = result.expect("CSV record deserialization failed");
            if record.len() != 3 {
                panic!("Expected 3 columns, got {}", record.len());
            }
            let row = record[0].to_string();
            if row.trim().is_empty() || row.trim().starts_with("#") {
                continue;
            }
            let required = GeneralResource::try_from(record[0].to_string())
                .expect("Failed to parse requirement");
            let provided =
                GeneralResource::try_from(record[1].to_string()).expect("Failed to parse resource");
            let pass = record[2].to_string().to_lowercase() == "true"
                || record[2].to_string().to_lowercase() == "yes";
            let result = provided.contains(&required);
            assert_eq!(
                result,
                pass,
                "required: {}, provided: {}, pass: {}, got result: {}",
                required,
                provided,
                record[2].to_string(),
                result
            );
        }
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_general_action() {
        let file = include_str!("../tests/fixtures/action.csv");
        let mut rdr = csv::Reader::from_reader(file.as_bytes());

        for result in rdr.records() {
            let record = result.expect("CSV record deserialization failed");
            if record.len() != 3 {
                panic!("Expected 3 columns, got {}", record.len());
            }
            let row = record[0].to_string();
            if row.trim().is_empty() || row.trim().starts_with("#") {
                continue;
            }
            let required = GeneralAction::try_from(record[0].to_string())
                .expect("Failed to parse requirement");
            let provided =
                GeneralAction::try_from(record[1].to_string()).expect("Failed to parse resource");
            let pass = record[2].to_string().to_lowercase() == "true"
                || record[2].to_string().to_lowercase() == "yes";
            let result = provided >= required;
            assert_eq!(
                result,
                pass,
                "required: {}, provided: {}, pass: {}, got result: {}",
                required,
                provided,
                record[2].to_string(),
                result
            );
        }
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_walk_paths() {
        // Equal paths
        let a = "a/b/c";
        let b = "a/b/c";
        assert_eq!(
            walk_paths(a.split('/'), b.split('/')),
            Some(Ordering::Equal)
        );

        // Prefix path
        let a = "a/b";
        let b = "a/b/c";
        assert_eq!(
            walk_paths(a.split('/'), b.split('/')),
            Some(Ordering::Greater)
        );

        // Sub-path
        let a = "a/b/c";
        let b = "a/b";
        assert_eq!(walk_paths(a.split('/'), b.split('/')), Some(Ordering::Less));

        // Wildcard
        let a = "a/*";
        let b = "a/b";
        assert_eq!(
            walk_paths(a.split('/'), b.split('/')),
            Some(Ordering::Equal)
        );

        // Trailing slash
        let a = "a/b/";
        let b = "a/b";
        assert_eq!(
            walk_paths(a.split('/'), b.split('/')),
            Some(Ordering::Equal)
        );
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_general_action_cmp() {
        let a = GeneralAction::try_from("a/b".to_string()).unwrap();
        let b = GeneralAction::try_from("a/b/c".to_string()).unwrap();
        assert_eq!(a.cmp(&b), Ordering::Greater);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_general_resource_contains() {
        let a = GeneralResource::try_from("a/b".to_string()).unwrap();
        let b = GeneralResource::try_from("a/b/c".to_string()).unwrap();
        assert!(a.contains(&b));
    }
}
