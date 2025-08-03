use super::{Action, CapabilitySemantics, Resource};
use cid::Cid;
use mysteryn_crypto::result::{Error, Result};
use std::fmt::Display;

#[derive(Ord, Eq, PartialEq, PartialOrd, Clone)]
pub enum ProofAction {
    Delegate,
}

impl Action for ProofAction {}

impl TryFrom<String> for ProofAction {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        match value.as_str() {
            "delegate" => Ok(ProofAction::Delegate),
            unsupported => Err(Error::ValidationError(format!(
                "Unsupported action for proof resource ({unsupported})"
            ))),
        }
    }
}

impl Display for ProofAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action_content = match self {
            ProofAction::Delegate => "delegate",
        };

        write!(f, "{action_content}")
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ProofSelection {
    Cid(Cid),
    Did(String),
}

impl Resource for ProofSelection {
    /// Assumed all CIDs belong to the issuer own or received tokens
    fn contains(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }
        // TODO
        false
    }
}

impl TryFrom<String> for ProofSelection {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        let selection = value.as_str();
        if selection.starts_with("did:") {
            Ok(ProofSelection::Did(selection.to_owned()))
        } else {
            Ok(ProofSelection::Cid(
                Cid::try_from(selection.to_string())
                    .map_err(|e| Error::EncodingError(e.to_string()))?,
            ))
        }
    }
}

impl Display for ProofSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proof_content = match self {
            ProofSelection::Cid(cid) => cid.to_string(),
            ProofSelection::Did(did) => did.to_string(),
        };

        write!(f, "{proof_content}")
    }
}

/// Allowed to delegate:
/// 1. own received tokens by CID (`aud` must match)
/// 2. own issued tokens by CID (`iss` must match)
/// 3. all of own received tokens by DID (`aud` must match)
/// 4. all of own issued tokens by DID (`iss` must match)
///
/// The delegation is actual only in the context of the current token, where it is included.
/// Users cannot copy delegations or apply them to some other token.
pub struct ProofDelegationSemantics {}

impl CapabilitySemantics<ProofSelection, ProofAction> for ProofDelegationSemantics {}
