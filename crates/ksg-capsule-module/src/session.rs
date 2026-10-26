//! A session of presses over one opened capsule (`Spec_kapsula` §10 п. 3).
//! Nothing is written unless the session closes: a refusal leaves the capsule
//! as it was (§14 Б-6).

/// A request at the panel's level (§13, §12 Л-2): the five commands of the
/// demo scene, and the network's answer for a Pro anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// E-4: the client's key is born; the maps' public halves come with it.
    Initiate,
    /// E-5: one step of the agent's work becomes a page.
    Work(String),
    /// A pointwise export of one page.
    ExportPage(u64),
    /// The keys a verifier checks the pages with.
    Keys,
    /// The container's state, one line per fact.
    Status,
    /// The network's attestation for the anchor the module asked for.
    Reanchor(Vec<u8>),
}

/// What a request answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Done; the bytes are the output, if any.
    Done(Vec<u8>),
    /// The module needs a memo anchored: the reader sends it, then `Reanchor`.
    NeedsAnchor(Vec<u8>),
    /// The module needs a party's signature over these bytes (§14 Б-3).
    NeedsSignature {
        /// Which party: `owner`, `buyer`, `issuer`.
        party: String,
        /// What it signs.
        bytes: Vec<u8>,
    },
    /// Refused; nothing is written.
    Refused(String),
}

/// Handles one request. Skeleton: 29.10.
#[must_use]
pub fn call(_request: &Request) -> Answer {
    Answer::Refused("not implemented yet (capsule skeleton 26.10)".into())
}
