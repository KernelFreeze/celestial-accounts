use serde::Serialize;

pub mod password;
pub mod session;
pub mod token;
pub mod totp;
pub mod verifier;

/// The type of token, describing proper usage.
///
/// There is one other interesting type that is not yet formally specified: The
/// MAC token, see `draft-ietf-oauth-v2-http-mac-02`. The draft has long been
/// expired but for the unlikely case there are others, the enum exist. You
/// might patch this to try out another token type before proposing it for
/// standardization.
///
/// In other context (RFC 8693) the explicitly non-access-token kind `N_A` also
/// exists but this is not a possible response.
#[non_exhaustive]
#[derive(Clone, Debug, Serialize)]
pub enum TokenType {
    /// A bearer token used on its own in an Authorization header.
    ///
    /// For this variant and its usage see RFC 6750.
    Bearer,
}
