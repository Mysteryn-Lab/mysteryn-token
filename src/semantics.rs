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
use std::fmt::Display;

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
        let content = &self.action;
        write!(f, "{content}")
    }
}

impl PartialOrd for GeneralAction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GeneralAction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.action == other.action {
            return std::cmp::Ordering::Equal;
        }

        let self_path_parts = self.action.split('/');
        let mut other_path_parts = other.action.split('/');
        let self_parts_len = self_path_parts.clone().count();
        let other_parts_len = other_path_parts.clone().count();
        let mut result = std::cmp::Ordering::Equal;

        for part in self_path_parts {
            match other_path_parts.next() {
                Some(other_part) => {
                    if part == "*" || other_part == "*" {
                        result = std::cmp::Ordering::Equal;
                    } else if part != other_part {
                        return std::cmp::Ordering::Less;
                    }
                }
                None => {
                    return if part.is_empty() && self_parts_len == other_parts_len + 1 {
                        std::cmp::Ordering::Equal
                    } else {
                        std::cmp::Ordering::Less
                    };
                }
            }
        }

        if self_parts_len == other_parts_len {
            return result;
        }

        if let Some(p) = other_path_parts.next() {
            if p.is_empty() && self_parts_len + 1 == other_parts_len {
                std::cmp::Ordering::Equal
            } else {
                std::cmp::Ordering::Greater
            }
        } else {
            result
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GeneralResource {
    resource: String,
}

impl Resource for GeneralResource {
    fn contains(&self, other: &Self) -> bool {
        let self_path_parts = self.resource.split('/');
        let mut other_path_parts = other.resource.split('/');

        let parts_len = self_path_parts.clone().count();
        let other_parts_len = other_path_parts.clone().count();
        for part in self_path_parts {
            match other_path_parts.next() {
                Some(other_part) => {
                    if part == "*" || other_part == "*" {
                        continue;
                    }
                    if part != other_part {
                        return false;
                    }
                }
                None => {
                    return part.is_empty() && parts_len == other_parts_len + 1;
                }
            }
        }

        true
    }
}

impl TryFrom<String> for GeneralResource {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Ok(Self { resource: value })
    }
}

impl Display for GeneralResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content = &self.resource;
        write!(f, "{content}")
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
}
