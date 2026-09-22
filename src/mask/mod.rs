use crate::{
    morph,
    registry::Registry,
    types::{Entity, Mapping, MaskMode, MaskResult},
};
use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Token numbering scheme for `token` masking mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Numbering {
    /// `<<LABEL_N>>` numbered sequentially per type in order of first appearance.
    Sequential,
    /// `<<LABEL_xxxxxx>>` where xxxxxx is the first 6 hex of SHA-256(salt + "\0" + normalized value).
    Hash(String),
}

pub struct MaskOptions<'a> {
    pub default_mode: MaskMode,
    /// Per-type overrides (type_id -> mode).
    pub overrides: &'a std::collections::HashMap<String, MaskMode>,
    /// Enforce `requires_companion` from the registry.
    pub combination_rule: bool,
}

static TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)<<\s*([A-Za-z_]+)_(\d+)\s*(?::\s*([A-Za-zа-яё]+)\s*)?>>").expect("valid token regex")
});

/// Street prefixes used to decide whether an `address` value inflects as a street.
const STREET_MARKERS: [&str; 4] = ["ул.", "улица", "проспект", "пр."];

/// Maps a PII type to the morphological kind used for inflection. Returns `None` for types
/// that are never inflected (their case suffix is ignored and the original is returned).
fn kind_for_type(type_id: &str, original: &str) -> Option<morph::Kind> {
    match type_id {
        "fio" | "card_holder" => Some(morph::Kind::Person),
        "birth_place" => Some(morph::Kind::Place),
        "citizenship" => Some(morph::Kind::Country),
        "address" => {
            let lower = original.trim().to_lowercase();
            if STREET_MARKERS.iter().any(|m| lower.starts_with(m)) {
                Some(morph::Kind::Street)
            } else {
                Some(morph::Kind::Place)
            }
        }
        _ => None,
    }
}

const SEPARATORS: [char; 8] = [' ', '-', '.', '(', ')', '+', '@', '/'];

const FIO_LIST: [&str; 20] = [
    "Смирнов Алексей Петрович",
    "Кузнецова Мария Ивановна",
    "Попов Дмитрий Сергеевич",
    "Васильева Ольга Андреевна",
    "Соколов Николай Викторович",
    "Михайлова Елена Юрьевна",
    "Новиков Павел Александрович",
    "Фёдорова Наталья Владимировна",
    "Морозов Игорь Олегович",
    "Волкова Татьяна Геннадьевна",
    "Алексеев Роман Борисович",
    "Лебедева Светлана Николаевна",
    "Семёнов Артём Ильич",
    "Егорова Ксения Дмитриевна",
    "Павлов Максим Романович",
    "Козлова Анна Сергеевна",
    "Степанов Виктор Анатольевич",
    "Николаева Ирина Павловна",
    "Орлов Григорий Фёдорович",
    "Андреева Юлия Максимовна",
];

/// Replaces entity spans right-to-left; identical originals of the same type share one token.
/// Deterministic for the same (text, entities, options).
pub fn mask(text: &str, entities: &[Entity], registry: &Registry, opts: &MaskOptions<'_>) -> MaskResult {
    mask_with(text, entities, registry, opts, Numbering::Sequential)
}

/// Like `mask` but with an explicit token numbering scheme (sequential or hash).
pub fn mask_with(
    text: &str,
    entities: &[Entity],
    registry: &Registry,
    opts: &MaskOptions<'_>,
    numbering: Numbering,
) -> MaskResult {
    mask_with_seed(text, entities, registry, opts, numbering, &[])
}

/// Like `mask_with` but seeds the token map from existing mappings so that identical values
/// reuse their prior tokens and sequential numbering continues (stateful sessions).
pub fn mask_with_seed(
    text: &str,
    entities: &[Entity],
    registry: &Registry,
    opts: &MaskOptions<'_>,
    numbering: Numbering,
    seed: &[Mapping],
) -> MaskResult {
    let mut active = collect_active(entities, registry, opts);
    active.sort_by_key(|(_, e, _)| e.start);

    let mut token_state = build_token_state(seed);
    let plan = build_plan(&active, text, registry, opts, numbering, &mut token_state);

    let result = apply_plan(text, &plan);
    let mappings = build_mappings(&plan);
    let out_entities = filter_entities(entities, &active);

    MaskResult {
        text: result,
        entities: out_entities,
        mappings,
    }
}

/// Selects entities that are not masked with `Off` and applies the combination rule.
fn collect_active<'a>(
    entities: &'a [Entity],
    registry: &Registry,
    opts: &MaskOptions<'_>,
) -> Vec<(usize, &'a Entity, MaskMode)> {
    let mut active: Vec<(usize, &Entity, MaskMode)> = Vec::new();
    for (i, e) in entities.iter().enumerate() {
        let spec = registry.get(&e.type_id);
        let mode = opts
            .overrides
            .get(&e.type_id)
            .copied()
            .or_else(|| spec.and_then(|s| if s.mask != MaskMode::Token { Some(s.mask) } else { None }))
            .unwrap_or(opts.default_mode);
        if mode == MaskMode::Off {
            continue;
        }
        active.push((i, e, mode));
    }

    if opts.combination_rule {
        let has_companion = entities.iter().any(|e| {
            let requires = registry.get(&e.type_id).map(|s| s.requires_companion).unwrap_or(false);
            !requires && e.confidence >= 0.9
        });
        if !has_companion {
            active.retain(|(_, e, _)| {
                !registry.get(&e.type_id).map(|s| s.requires_companion).unwrap_or(false)
            });
        }
    }
    active
}

/// Mutable token bookkeeping shared across the replacement plan.
struct TokenState {
    map: HashMap<(String, String), String>,
    counters: HashMap<String, usize>,
}

/// Seeds the token map and per-type counters from existing mappings.
fn build_token_state(seed: &[Mapping]) -> TokenState {
    let mut map: HashMap<(String, String), String> = HashMap::new();
    let mut counters: HashMap<String, usize> = HashMap::new();
    for m in seed {
        let key = (m.type_id.clone(), normalize(&m.original));
        map.insert(key, m.masked.clone());
        if let Some((_, num)) = parse_token_number(&m.masked) {
            let entry = counters.entry(m.type_id.clone()).or_insert(0);
            if num > *entry {
                *entry = num;
            }
        }
    }
    TokenState { map, counters }
}

/// Computes the replacement for a single entity, reusing or minting a token.
fn replacement_for(
    e: &Entity,
    original: &str,
    norm: &str,
    registry: &Registry,
    opts: &MaskOptions<'_>,
    numbering: &Numbering,
    token_state: &mut TokenState,
) -> String {
    let mode = opts
        .overrides
        .get(&e.type_id)
        .copied()
        .or_else(|| registry.get(&e.type_id).and_then(|s| if s.mask != MaskMode::Token { Some(s.mask) } else { None }))
        .unwrap_or(opts.default_mode);
    let key = (e.type_id.clone(), norm.to_string());
    token_state
        .map
        .entry(key)
        .or_insert_with(|| match mode {
            MaskMode::Token => {
                let label = registry
                    .get(&e.type_id)
                    .map(|s| s.token_label.clone())
                    .unwrap_or_else(|| e.type_id.to_uppercase());
                match numbering {
                    Numbering::Sequential => {
                        let n = token_state.counters.entry(e.type_id.clone()).or_insert(0);
                        *n += 1;
                        format!("<<{}_{}>>", label, *n)
                    }
                    Numbering::Hash(ref salt) => {
                        let digest = hash_token(salt, norm);
                        format!("<<{}_{}>>", label, digest)
                    }
                }
            }
            MaskMode::Stars => {
                let spec = registry.get(&e.type_id);
                stars(
                    original,
                    &e.type_id,
                    spec.map(|s| s.stars_keep_prefix).unwrap_or(0),
                    spec.map(|s| s.stars_keep_suffix).unwrap_or(0),
                )
            }
            MaskMode::Synthetic => synthetic(original, &e.type_id),
            MaskMode::Remove => "[removed]".to_string(),
            MaskMode::Off => unreachable!(),
        })
        .clone()
}

/// Builds the ordered replacement plan for all active entities.
fn build_plan(
    active: &[(usize, &Entity, MaskMode)],
    text: &str,
    registry: &Registry,
    opts: &MaskOptions<'_>,
    numbering: Numbering,
    token_state: &mut TokenState,
) -> Vec<(usize, usize, String, String, String)> {
    let mut plan: Vec<(usize, usize, String, String, String)> = Vec::new();
    for (_, e, _) in active {
        let original = text[e.start..e.end].to_string();
        let norm = normalize(&original);
        let replacement = replacement_for(e, &original, &norm, registry, opts, &numbering, token_state);
        plan.push((e.start, e.end, replacement, e.type_id.clone(), original));
    }
    plan
}

/// Applies the plan right-to-left so earlier byte offsets stay valid.
fn apply_plan(text: &str, plan: &[(usize, usize, String, String, String)]) -> String {
    let mut result = text.to_string();
    let mut sorted = plan.to_vec();
    sorted.sort_by_key(|(start, _, _, _, _)| *start);
    for (start, end, replacement, _, _) in sorted.iter().rev() {
        result.replace_range(*start..*end, replacement);
    }
    result
}

/// Builds deduplicated mappings from the plan.
fn build_mappings(plan: &[(usize, usize, String, String, String)]) -> Vec<Mapping> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut mappings = Vec::new();
    for (_, _, replacement, type_id, original) in plan {
        let norm = normalize(original);
        if seen.insert((type_id.clone(), norm)) {
            mappings.push(Mapping {
                type_id: type_id.clone(),
                original: original.clone(),
                masked: replacement.clone(),
            });
        }
    }
    mappings
}

/// Filters the original entities down to those that were actually masked.
fn filter_entities(entities: &[Entity], active: &[(usize, &Entity, MaskMode)]) -> Vec<Entity> {
    let active_indices: HashSet<usize> = active.iter().map(|(i, _, _)| *i).collect();
    entities
        .iter()
        .enumerate()
        .filter(|(i, _)| active_indices.contains(i))
        .map(|(_, e)| e.clone())
        .collect()
}

/// First 6 hex chars of SHA-256(salt + "\0" + normalized value).
fn hash_token(salt: &str, normalized: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update([0u8]);
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(6);
    for b in digest.iter().take(3) {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Restores originals using mappings. Tokens `{LABEL_N}` are located by regex anywhere in the text
/// (any order, any surrounding); stars/synthetic masks are located as substrings, longest first.
/// A token may carry a grammatical-case suffix (`<<FIO_1:дат>>`); when the suffix is a recognized
/// case and the type is inflectable, the original is inflected to that case. Unknown tokens are
/// left untouched.
pub fn unmask(text: &str, mappings: &[Mapping]) -> String {
    let mut result = TOKEN_RE
        .replace_all(text, |caps: &regex::Captures| {
            let token = &caps[0];
            let base_token = format!("<<{}_{}>>", &caps[1], &caps[2]);
            let matched = mappings
                .iter()
                .find(|m| norm_compare(&m.masked) == norm_compare(&base_token));
            match (matched, caps.get(3)) {
                (Some(m), Some(suffix)) => {
                    if let Some(case) = morph::Case::parse(suffix.as_str()) {
                        if let Some(kind) = kind_for_type(&m.type_id, &m.original) {
                            return morph::inflect(&m.original, kind, case)
                                .unwrap_or_else(|| m.original.clone());
                        }
                        return m.original.clone();
                    }
                    token.to_string()
                }
                (Some(m), None) => m.original.clone(),
                (None, _) => token.to_string(),
            }
        })
        .to_string();

    let mut non_token: Vec<&Mapping> = mappings
        .iter()
        .filter(|m| !TOKEN_RE.is_match(&m.masked))
        .collect();
    non_token.sort_by_key(|m| std::cmp::Reverse(m.masked.len()));
    for m in non_token {
        result = result.replace(&m.masked, &m.original);
    }
    result
}

/// Counts token-format substrings (`<<LABEL_N>>`, case/whitespace tolerant as in `unmask`) in `text`
/// that have no matching mapping. A token with a case suffix (`<<FIO_1:дат>>`) is resolved when its
/// base token is present in the mappings. Used for the `pii_unmask_unresolved_tokens_total` metric.
pub fn count_unresolved_tokens(text: &str, mappings: &[Mapping]) -> usize {
    let mut count = 0;
    for caps in TOKEN_RE.captures_iter(text) {
        let base_token = format!("<<{}_{}>>", &caps[1], &caps[2]);
        let matched = mappings
            .iter()
            .any(|m| norm_compare(&m.masked) == norm_compare(&base_token));
        if !matched {
            count += 1;
        }
    }
    count
}

/// Renders the stars mask for a value: keeps prefix/suffix chars, keeps separators (space, '-', '.', '(', ')', '+', '@'),
/// replaces the rest with '*'. For FIO renders initials "И. И. И.".
pub fn stars(value: &str, type_id: &str, keep_prefix: usize, keep_suffix: usize) -> String {
    if type_id == "fio" {
        return stars_fio(value);
    }
    if type_id == "email" {
        if let Some(masked) = stars_email(value, keep_prefix) {
            return masked;
        }
    }
    stars_generic(value, keep_prefix, keep_suffix)
}

/// Renders the FIO stars mask as initials "И. И. И.".
fn stars_fio(value: &str) -> String {
    value
        .split_whitespace()
        .map(|w| {
            let first = w.chars().next().unwrap_or('*');
            format!("{}.", first)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Renders the email stars mask: keeps the local prefix and the domain.
fn stars_email(value: &str, keep_prefix: usize) -> Option<String> {
    let at = value.rfind('@')?;
    let local = &value[..at];
    let domain = &value[at..];
    let mut out = String::new();
    for (i, c) in local.chars().enumerate() {
        if i < keep_prefix {
            out.push(c);
        } else {
            out.push('*');
        }
    }
    out.push_str(domain);
    Some(out)
}

/// Renders the generic stars mask: keeps prefix/suffix chars and separators.
fn stars_generic(value: &str, keep_prefix: usize, keep_suffix: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    let keep_prefix = keep_prefix.min(chars.len());
    let keep_suffix = keep_suffix.min(chars.len().saturating_sub(keep_prefix));
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if i < keep_prefix || i >= chars.len() - keep_suffix || SEPARATORS.contains(c) {
            out.push(*c);
        } else {
            out.push('*');
        }
    }
    out
}

fn synthetic(value: &str, type_id: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    match type_id {
        "fio" => FIO_LIST[rng.gen_range(0..FIO_LIST.len())].to_string(),
        "card_number" => synthetic_card_number(value, &mut rng),
        "email" => synthetic_email(value, &mut rng),
        _ => synthetic_digits(value, &mut rng),
    }
}

/// Replaces the digits of a card number with a valid Luhn number, keeping separators.
fn synthetic_card_number(value: &str, rng: &mut impl rand::Rng) -> String {
    let mut digits = Vec::with_capacity(16);
    for _ in 0..15 {
        digits.push(rng.gen_range(0..10));
    }
    digits.push(luhn_check(&digits) as u32);
    let mut it = digits.into_iter();
    let mut out = String::new();
    for c in value.chars() {
        if c.is_ascii_digit() {
            out.push(char::from_digit(it.next().unwrap_or(0), 10).unwrap());
        } else {
            out.push(c);
        }
    }
    out
}

/// Replaces the local part of an email with random letters, keeping the domain.
fn synthetic_email(value: &str, rng: &mut impl rand::Rng) -> String {
    let Some(at) = value.rfind('@') else {
        return value.to_string();
    };
    let domain = &value[at..];
    let len = value[..at].chars().count().max(1);
    let mut local = String::new();
    for _ in 0..len {
        local.push(rng.gen_range(b'a'..=b'z') as char);
    }
    format!("{}{}", local, domain)
}

/// Replaces every digit with a random digit, keeping non-digit characters.
fn synthetic_digits(value: &str, rng: &mut impl rand::Rng) -> String {
    let mut out = String::new();
    for c in value.chars() {
        if c.is_ascii_digit() {
            out.push(char::from_digit(rng.gen_range(0..10), 10).unwrap());
        } else {
            out.push(c);
        }
    }
    out
}

fn luhn_check(digits: &[u32]) -> u8 {
    let mut sum = 0;
    for (i, d) in digits.iter().enumerate() {
        let mut v = *d;
        if i % 2 == 0 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    ((10 - (sum % 10)) % 10) as u8
}

fn normalize(s: &str) -> String {
    s.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extracts the numeric suffix from a token like `<<LABEL_3>>`; returns None for non-token masks.
fn parse_token_number(masked: &str) -> Option<(String, usize)> {
    let caps = TOKEN_RE.captures(masked)?;
    let num: usize = caps.get(2)?.as_str().parse().ok()?;
    Some((caps[1].to_string(), num))
}

fn norm_compare(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}