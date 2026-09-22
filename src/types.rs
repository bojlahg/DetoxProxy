use serde::{Deserialize, Serialize};

/// Identifier of a PII type from the registry, e.g. "fio", "card_number".
pub type TypeId = String;

/// A detected span of personal data. Offsets are byte offsets into the original text (UTF-8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    pub type_id: TypeId,
    pub start: usize,
    pub end: usize,
    /// 0.0..=1.0; validator passed => >= 0.9, pattern only => ~0.6, context only => ~0.4
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskMode { Token, Stars, Synthetic, Pseudonym, Remove, Off }

/// One replacement performed during masking; kept in the store for unmasking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mapping {
    pub type_id: TypeId,
    pub original: String,
    pub masked: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaskResult {
    pub text: String,
    pub entities: Vec<Entity>,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction { Mask, Unmask }