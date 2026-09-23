use crate::{
    morph,
    morph::{Gender, Kind},
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

/// Lowercase marker words without the trailing dot.
const ADDRESS_MARKERS: &[&str] = &[
    "г", "гор", "город", "городе", "города", "ул", "улица", "улице", "улицы", "улицу",
    "пр", "пр-т", "пр-кт", "просп", "проспект", "проспекте", "проспекта", "пер", "переулок",
    "переулке", "переулка", "б-р", "бульвар", "бульваре", "ш", "шоссе", "наб", "набережная",
    "набережной", "пл", "площадь", "площади", "проезд", "проезде", "аллея", "тупик", "линия",
    "мкр", "мкрн", "микрорайон", "микрорайоне", "обл", "область", "области", "р-н", "район",
    "районе", "респ", "республика", "край", "пос", "п", "поселок", "посёлок", "поселке",
    "посёлке", "с", "село", "селе", "дер", "деревня", "деревне", "д", "дом", "доме", "дома",
    "кв", "квартира", "квартире", "квартиры", "корп", "корпус", "корпусе", "к", "стр",
    "строение", "строении", "лит", "литера", "пом", "помещение", "оф", "офис", "эт", "этаж",
    "индекс",
];

/// All six grammatical cases, used for per-part person inflection.
const ALL_CASES: [morph::Case; 6] = [
    morph::Case::Nom,
    morph::Case::Gen,
    morph::Case::Dat,
    morph::Case::Acc,
    morph::Case::Ins,
    morph::Case::Prep,
];

/// Oblique cases (all but nominative), used for full-value inflection.
const OBLIQUE_CASES: [morph::Case; 5] = [
    morph::Case::Gen,
    morph::Case::Dat,
    morph::Case::Acc,
    morph::Case::Ins,
    morph::Case::Prep,
];

/// Maps a PII type to the morphological kind used for inflection. Returns `None` for types
/// that are never inflected (their case suffix is ignored and the original is returned).
fn kind_for_type(type_id: &str, original: &str) -> Option<morph::Kind> {
    match type_id {
        "fio" | "card_holder" => Some(morph::Kind::Person),
        "birth_place" => Some(morph::Kind::Place),
        "citizenship" => Some(morph::Kind::Country),
        "address" => {
            if original.chars().any(|c| c.is_ascii_digit()) {
                None
            } else {
                let lower = original.trim().to_lowercase();
                if STREET_MARKERS.iter().any(|m| lower.starts_with(m)) {
                    Some(morph::Kind::Street)
                } else {
                    Some(morph::Kind::Place)
                }
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
    let mut active = collect_active(text, entities, registry, opts);
    active = expand_split_components(text, active, registry);
    active.sort_by_key(|(_, e, _)| e.start);

    let mut token_state = build_token_state(seed, text);
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
fn collect_active(
    text: &str,
    entities: &[Entity],
    registry: &Registry,
    opts: &MaskOptions<'_>,
) -> Vec<(usize, Entity, MaskMode)> {
    let mut active: Vec<(usize, Entity, MaskMode)> = Vec::new();
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
        active.push((i, e.clone(), mode));
    }

    if opts.combination_rule {
        active.retain(|(_, e, _)| {
            let Some(spec) = registry.get(&e.type_id) else {
                return true;
            };
            if !spec.requires_companion {
                return true;
            }
            let companions = registry.companions(&e.type_id);
            entities.iter().any(|c| {
                c.type_id != e.type_id
                    && companions.contains(&c.type_id)
                    && c.confidence >= 0.9
                    && same_sentence(text, e.start, c.start)
            })
        });
    }
    active
}

/// Expands token-mode entities whose type has `split_components` into per-value sub-entities,
/// keeping the original entity index on every part so `filter_entities` still returns the
/// original entities. Other modes are left untouched.
fn expand_split_components(
    text: &str,
    active: Vec<(usize, Entity, MaskMode)>,
    registry: &Registry,
) -> Vec<(usize, Entity, MaskMode)> {
    let mut out: Vec<(usize, Entity, MaskMode)> = Vec::with_capacity(active.len());
    for (i, e, mode) in active {
        let split = mode == MaskMode::Token
            && registry.get(&e.type_id).is_some_and(|s| s.split_components);
        if split {
            for part in split_components(text, &e) {
                out.push((i, part, mode));
            }
        } else {
            out.push((i, e, mode));
        }
    }
    out
}

/// True if `word` is an address marker: its lowercase form without one trailing dot is in
/// `ADDRESS_MARKERS` (e.g. "г.", "ул.", "дом", "проспект").
fn is_marker_word(word: &str) -> bool {
    let lower = word.to_lowercase();
    let stripped = lower.strip_suffix('.').unwrap_or(&lower);
    ADDRESS_MARKERS.contains(&stripped)
}

/// For a word of the form `<marker>.<value>` without a space (e.g. "д.10А", "кв.8", "ул.Ленина"),
/// returns `(byte_end_of_marker_including_dot, byte_start_of_value)`. Returns `None` when the
/// word is not such a marker+value pair.
fn marker_dot_value(word: &str) -> Option<(usize, usize)> {
    let dot = word.find('.')?;
    let marker = word[..dot].to_lowercase();
    if !ADDRESS_MARKERS.contains(&marker.as_str()) {
        return None;
    }
    let value_start = dot + 1;
    if value_start >= word.len() {
        return None;
    }
    Some((dot + 1, value_start))
}

/// Token kinds produced by `tokenize_span`.
#[derive(Clone, Copy, PartialEq)]
enum SpanKind { Marker, Value, Space, Comma }

/// Byte index of the first char at or after `i` for which `stop` is true (or `span.len()`).
fn scan_until(span: &str, i: usize, stop: impl Fn(char) -> bool) -> usize {
    span[i..].char_indices().find(|&(_, c)| stop(c)).map_or(span.len(), |(k, _)| i + k)
}

fn is_separator(c: char) -> bool {
    c == ',' || c == ';'
}

/// Classifies one word and appends its token(s): marker, value, or marker+value ("д.10А").
fn push_word(tokens: &mut Vec<(SpanKind, usize, usize)>, span: &str, start: usize, end: usize) {
    let word = &span[start..end];
    if is_marker_word(word) {
        tokens.push((SpanKind::Marker, start, end));
    } else if let Some((m_end, v_start)) = marker_dot_value(word) {
        tokens.push((SpanKind::Marker, start, start + m_end));
        tokens.push((SpanKind::Value, start + v_start, end));
    } else {
        tokens.push((SpanKind::Value, start, end));
    }
}

/// Splits a span into tokens: marker words, value words, whitespace runs and `,`/`;` separators.
/// A word of the form `<marker>.<value>` (e.g. "д.10А") yields a marker token followed by a value
/// token. All offsets are relative to the start of `span`.
fn tokenize_span(span: &str) -> Vec<(SpanKind, usize, usize)> {
    let mut tokens = Vec::new();
    let mut i = 0;
    while let Some(c) = span[i..].chars().next() {
        let start = i;
        if c.is_whitespace() {
            i = scan_until(span, i, |c| !c.is_whitespace());
            tokens.push((SpanKind::Space, start, i));
        } else if is_separator(c) {
            i += c.len_utf8();
            tokens.push((SpanKind::Comma, start, i));
        } else {
            i = scan_until(span, i, |c| c.is_whitespace() || is_separator(c));
            push_word(&mut tokens, span, start, i);
        }
    }
    tokens
}

/// Collects one value group starting at token `idx`: the byte range `[gs, ge)` of the group and
/// the index of the first token after it. Trailing dots are trimmed from the group end.
fn value_group(tokens: &[(SpanKind, usize, usize)], idx: usize, span: &str) -> (usize, usize, usize) {
    let gs = tokens[idx].1;
    let mut ge = tokens[idx].2;
    let mut i = idx + 1;
    while i < tokens.len() {
        match tokens[i].0 {
            SpanKind::Value => {
                ge = tokens[i].2;
                i += 1;
            }
            SpanKind::Space => {
                i += 1;
            }
            _ => break,
        }
    }
    while ge > gs && span.as_bytes()[ge - 1] == b'.' {
        ge -= 1;
    }
    (gs, ge, i)
}

/// Splits an address span into value sub-spans; marker words and separators stay outside.
/// Returns the entity unchanged (one element) when the span has no marker words or no values.
fn split_components(text: &str, e: &Entity) -> Vec<Entity> {
    let span = &text[e.start..e.end];
    let tokens = tokenize_span(span);
    let has_marker = tokens.iter().any(|(k, _, _)| *k == SpanKind::Marker);
    if !has_marker {
        return vec![e.clone()];
    }

    let mut parts: Vec<Entity> = Vec::new();
    let mut idx = 0;
    while idx < tokens.len() {
        if tokens[idx].0 != SpanKind::Value {
            idx += 1;
            continue;
        }
        let (gs, ge, next) = value_group(&tokens, idx, span);
        parts.push(Entity {
            type_id: e.type_id.clone(),
            start: e.start + gs,
            end: e.start + ge,
            confidence: e.confidence,
        });
        idx = next;
    }

    if parts.is_empty() {
        return vec![e.clone()];
    }
    parts
}

/// True if two byte offsets are in the same sentence (no '.', '!', '?' or newline between them).
fn same_sentence(text: &str, a: usize, b: usize) -> bool {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    !text[lo..hi].contains(['.', '!', '?', '\n'])
}

/// Mutable token bookkeeping shared across the replacement plan.
struct TokenState<'a> {
    map: HashMap<(String, String), String>,
    counters: HashMap<String, usize>,
    /// Pseudonym values already emitted in this request, to avoid collisions.
    used_pseudonyms: HashSet<String>,
    /// The full source text, used to avoid pseudonyms that appear verbatim.
    text: &'a str,
}

/// Seeds the token map and per-type counters from existing mappings.
fn build_token_state<'a>(seed: &[Mapping], text: &'a str) -> TokenState<'a> {
    let mut map: HashMap<(String, String), String> = HashMap::new();
    let mut counters: HashMap<String, usize> = HashMap::new();
    let mut used_pseudonyms: HashSet<String> = HashSet::new();
    for m in seed {
        let key = (m.type_id.clone(), normalize(&m.original));
        map.insert(key, m.masked.clone());
        if let Some((_, num)) = parse_token_number(&m.masked) {
            let entry = counters.entry(m.type_id.clone()).or_insert(0);
            if num > *entry {
                *entry = num;
            }
        }
        used_pseudonyms.insert(m.masked.clone());
    }
    TokenState { map, counters, used_pseudonyms, text }
}

/// Computes the replacement for a single entity, reusing or minting a token.
fn replacement_for(
    e: &Entity,
    original: &str,
    norm: &str,
    registry: &Registry,
    opts: &MaskOptions<'_>,
    numbering: &Numbering,
    token_state: &mut TokenState<'_>,
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
            MaskMode::Synthetic => synthetic(
                original,
                &e.type_id,
                registry,
                numbering,
                token_state.text,
                &mut token_state.used_pseudonyms,
            ),
            MaskMode::Pseudonym => pseudonym(
                original,
                &e.type_id,
                token_state.text,
                registry,
                numbering,
                &mut token_state.used_pseudonyms,
            ),
            MaskMode::Remove => "[removed]".to_string(),
            MaskMode::Off => unreachable!(),
        })
        .clone()
}

/// Builds the ordered replacement plan for all active entities.
fn build_plan(
    active: &[(usize, Entity, MaskMode)],
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
fn filter_entities(entities: &[Entity], active: &[(usize, Entity, MaskMode)]) -> Vec<Entity> {
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
    let mut result = replace_tokens(text, mappings);
    let (mut pairs, mut exact) = build_non_token_pairs(mappings);
    pairs.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    for (from, to) in pairs {
        result = replace_inflected(&result, &from, &to);
    }
    exact.sort_by_key(|m| std::cmp::Reverse(m.masked.len()));
    for m in exact {
        result = result.replace(&m.masked, &m.original);
    }
    result
}

/// Resolves a token with a grammatical-case suffix (`<<FIO_1:дат>>`) to the restored original.
/// Returns `None` when the suffix is not a recognized case or the type is not inflectable.
/// When the original already stands in the requested case it is returned as-is; otherwise it is
/// inflected. Case matching is kind-aware: persons use `detect_person_case`, places and countries
/// use `detect_place_case`, streets are always inflected.
fn resolve_case_suffix(m: &Mapping, suffix: &str) -> Option<String> {
    let case = morph::Case::parse(suffix)?;
    let Some(kind) = kind_for_type(&m.type_id, &m.original) else {
        return Some(m.original.clone());
    };
    let matches_case = match kind {
        morph::Kind::Person => morph::detect_person_case(&m.original) == case,
        morph::Kind::Place | morph::Kind::Country => morph::detect_place_case(&m.original) == case,
        morph::Kind::Street => false,
    };
    if matches_case {
        return Some(m.original.clone());
    }
    Some(morph::inflect(&m.original, kind, case).unwrap_or_else(|| m.original.clone()))
}

/// Replaces token-format masks (`<<LABEL_N>>`, with optional case suffix) in `text` using the
/// token mappings. Unknown tokens are left untouched.
fn replace_tokens(text: &str, mappings: &[Mapping]) -> String {
    let token_map: HashMap<String, &Mapping> = mappings
        .iter()
        .filter(|m| TOKEN_RE.is_match(&m.masked))
        .map(|m| (norm_compare(&m.masked), m))
        .collect();
    TOKEN_RE
        .replace_all(text, |caps: &regex::Captures| {
            let token = &caps[0];
            let base_token = format!("<<{}_{}>>", &caps[1], &caps[2]);
            let matched = token_map.get(&norm_compare(&base_token)).copied();
            match (matched, caps.get(3)) {
                (Some(m), Some(suffix)) => {
                    if let Some(restored) = resolve_case_suffix(m, suffix.as_str()) {
                        return restored;
                    }
                    token.to_string()
                }
                (Some(m), None) => m.original.clone(),
                (None, _) => token.to_string(),
            }
        })
        .to_string()
}

/// Builds the substitution pairs for non-token mappings: inflectable masks produce inflection
/// pairs, everything else is restored by exact match.
fn build_non_token_pairs(mappings: &[Mapping]) -> (Vec<(String, String)>, Vec<&Mapping>) {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut exact: Vec<&Mapping> = Vec::new();
    for m in mappings {
        if TOKEN_RE.is_match(&m.masked) || m.masked == "[removed]" {
            continue;
        }
        if is_inflectable_mask(&m.masked) {
            pairs.extend(unmask_pairs(m));
        } else {
            exact.push(m);
        }
    }
    (pairs, exact)
}

/// Builds (substitution, original) pairs for an inflectable non-token mapping: the exact
/// nominative form, the oblique cases of the full value, and for persons the individual name
/// parts in all cases.
fn unmask_pairs(m: &Mapping) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let Some(kind) = kind_for_type(&m.type_id, &m.original) else {
        pairs.push((m.masked.clone(), m.original.clone()));
        return pairs;
    };
    pairs.push((m.masked.clone(), m.original.clone()));
    for case in OBLIQUE_CASES {
        if let (Some(masked_inf), Some(orig_inf)) =
            (morph::inflect(&m.masked, kind, case), morph::inflect(&m.original, kind, case))
        {
            pairs.push((masked_inf, orig_inf));
        }
    }
    if kind == morph::Kind::Person {
        pairs.extend(person_part_pairs(m));
    }
    pairs
}

/// True if a masked value is eligible for the inflection path: every word is at least 3 letters
/// long and contains neither `*` nor `.`. Initials ("С. П. И."), stars masks and `[removed]`
/// are rejected so they are restored only by exact match.
fn is_inflectable_mask(masked: &str) -> bool {
    masked.split_whitespace().all(|w| {
        w.chars().count() >= 3 && !w.contains('*') && !w.contains('.')
    })
}

/// Builds (substitution, original) pairs for the individual parts of a person's name:
/// surname, given name, patronymic, and "given name patronymic", each in all six cases.
/// Parts shorter than 3 letters are skipped.
fn person_part_pairs(m: &Mapping) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let (Some(mp), Some(op)) = (morph::parse_person(&m.masked), morph::parse_person(&m.original)) else {
        return pairs;
    };
    let m_parts = [mp.surname.clone(), mp.name.clone(), mp.patronymic.clone()];
    let o_parts = [op.surname.clone(), op.name.clone(), op.patronymic.clone()];
    for (m_part, o_part) in m_parts.iter().zip(o_parts.iter()) {
        if m_part.chars().count() < 3 || o_part.chars().count() < 3 {
            continue;
        }
        pairs.extend(case_pairs(m_part, o_part));
    }
    if !mp.name.is_empty() && !mp.patronymic.is_empty() && !op.name.is_empty() && !op.patronymic.is_empty() {
        let m_np = format!("{} {}", mp.name, mp.patronymic);
        let o_np = format!("{} {}", op.name, op.patronymic);
        pairs.extend(case_pairs(&m_np, &o_np));
    }
    pairs
}

/// Builds (substitution, original) pairs for a single person part in all six grammatical cases.
fn case_pairs(masked_part: &str, original_part: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for case in ALL_CASES {
        if let (Some(mi), Some(oi)) = (
            morph::inflect(masked_part, morph::Kind::Person, case),
            morph::inflect(original_part, morph::Kind::Person, case),
        ) {
            pairs.push((mi, oi));
        }
    }
    pairs
}

/// Replaces whole-word occurrences of `from` in `text` (case-insensitive, Cyrillic-aware) with
/// `to`, transferring the per-word case style of the matched text onto `to`.
fn replace_inflected(text: &str, from: &str, to: &str) -> String {
    if from.is_empty() {
        return text.to_string();
    }
    let from_lower: Vec<char> = from.chars().map(|c| c.to_lowercase().next().unwrap_or(c)).collect();
    let text_chars: Vec<char> = text.chars().collect();
    let mut result = String::with_capacity(text.len());
    let mut i = 0;
    while i < text_chars.len() {
        let matches = text_chars.len() - i >= from_lower.len()
            && text_chars[i..i + from_lower.len()]
                .iter()
                .zip(from_lower.iter())
                .all(|(tc, fc)| tc.to_lowercase().next().unwrap_or(*tc) == *fc);
        if matches {
            let before_ok = i == 0 || !is_word_char(text_chars[i - 1]);
            let after_ok = i + from_lower.len() >= text_chars.len()
                || !is_word_char(text_chars[i + from_lower.len()]);
            if before_ok && after_ok {
                let found: String = text_chars[i..i + from_lower.len()].iter().collect();
                result.push_str(&morph::apply_original_styles(&found, to));
                i += from_lower.len();
                continue;
            }
        }
        result.push(text_chars[i]);
        i += 1;
    }
    result
}

/// True if `c` is a word character (Cyrillic/Latin letter or digit).
fn is_word_char(c: char) -> bool {
    c.is_alphabetic() || c.is_ascii_digit()
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

fn synthetic(
    value: &str,
    type_id: &str,
    registry: &Registry,
    numbering: &Numbering,
    text: &str,
    used: &mut HashSet<String>,
) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    match type_id {
        "fio" => FIO_LIST[rng.gen_range(0..FIO_LIST.len())].to_string(),
        "card_number" => synthetic_card_number(value, &mut rng),
        "email" => synthetic_email(value, &mut rng),
        "card_holder" | "birth_place" | "citizenship" | "address" | "passport_issuer" => {
            pseudonym(value, type_id, text, registry, numbering, used)
        }
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

// ---------------------------------------------------------------------------
// Pseudonym masking
// ---------------------------------------------------------------------------

/// Male surnames grouped by morphological group, loaded once from the dictionary.
static MALE_SURNAMES_BY_GROUP: Lazy<HashMap<morph::SurnameGroup, Vec<String>>> = Lazy::new(|| {
    let mut map: HashMap<morph::SurnameGroup, Vec<String>> = HashMap::new();
    for line in include_str!("../../data/dict/surnames.txt").lines() {
        let s = line.trim().to_lowercase();
        if s.is_empty() || s.starts_with('#') || is_female_surname(&s) {
            continue;
        }
        map.entry(morph::surname_group(&s)).or_default().push(s);
    }
    map
});

/// Male given names, loaded once from the dictionary.
static MALE_NAMES: Lazy<Vec<String>> = Lazy::new(|| {
    include_str!("../../data/dict/first_names.txt")
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && morph::is_male_name(l))
        .collect()
});

/// Female given names, loaded once from the dictionary.
static FEMALE_NAMES: Lazy<Vec<String>> = Lazy::new(|| {
    include_str!("../../data/dict/first_names.txt")
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !morph::is_male_name(l))
        .collect()
});

/// Cities, loaded once from the dictionary.
static CITIES: Lazy<Vec<String>> = Lazy::new(|| {
    include_str!("../../data/dict/cities.txt")
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

/// Countries, loaded once from the dictionary.
static COUNTRIES: Lazy<Vec<String>> = Lazy::new(|| {
    include_str!("../../data/dict/countries.txt")
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

/// Street names, loaded once from the dictionary.
static STREETS: Lazy<Vec<String>> = Lazy::new(|| {
    include_str!("../../data/dict/streets.txt")
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

/// True if a surname is a feminine form (ends in a feminine ending).
fn is_female_surname(s: &str) -> bool {
    s.ends_with("ова")
        || s.ends_with("ева")
        || s.ends_with("ёва")
        || s.ends_with("ина")
        || s.ends_with("ына")
        || s.ends_with("ская")
        || s.ends_with("цкая")
        || s.ends_with("ая")
        || s.ends_with("яя")
}

/// Deterministic 64-bit hash of a string (SHA-256 prefix).
fn hash_index(s: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

/// Salt used to seed deterministic pseudonym picks; `None` for sequential numbering.
fn salt_of(numbering: &Numbering) -> Option<&str> {
    match numbering {
        Numbering::Hash(ref salt) => Some(salt.as_str()),
        Numbering::Sequential => None,
    }
}

/// Deterministically pick a male surname of the given group, differing from `original`.
fn pick_surname(group: &morph::SurnameGroup, original: &str, salt: Option<&str>, attempt: usize) -> String {
    let list = MALE_SURNAMES_BY_GROUP.get(group).cloned().unwrap_or_default();
    if list.is_empty() {
        return "Иванов".to_string();
    }
    let idx = hash_index(&format!("surname\0{original}\0{}\0{attempt}", salt.unwrap_or(""))) as usize % list.len();
    list[idx].clone()
}

/// Deterministically pick a given name of the given gender.
fn pick_name(gender: Gender, original: &str, salt: Option<&str>, attempt: usize) -> String {
    let list = match gender {
        Gender::Female => &*FEMALE_NAMES,
        _ => &*MALE_NAMES,
    };
    if list.is_empty() {
        return "Иван".to_string();
    }
    let idx = hash_index(&format!("name\0{original}\0{}\0{attempt}", salt.unwrap_or(""))) as usize % list.len();
    list[idx].clone()
}

/// Deterministically pick a value from a list, differing from `original`.
fn pick_from(list: &[String], original: &str, salt: Option<&str>, attempt: usize) -> String {
    if list.is_empty() {
        return original.to_string();
    }
    let idx = hash_index(&format!("pick\0{original}\0{}\0{attempt}", salt.unwrap_or(""))) as usize % list.len();
    list[idx].clone()
}

/// Build a plausible pseudonym for a full name, preserving gender, surname group, case and style.
fn pseudonym_fio(original: &str, salt: Option<&str>, attempt: usize) -> String {
    let parts = match morph::parse_person(original) {
        Some(p) => p,
        None => return original.to_string(),
    };
    let group = morph::surname_group(&parts.surname);
    let male_surname = pick_surname(&group, &parts.surname, salt, attempt);
    let surname = if parts.gender == Gender::Female {
        morph::female_surname(&male_surname)
    } else {
        male_surname
    };
    let name = if parts.name.is_empty() {
        String::new()
    } else {
        pick_name(parts.gender, &parts.name, salt, attempt)
    };
    let patronymic = if parts.patronymic.is_empty() {
        String::new()
    } else {
        let male_name = pick_name(Gender::Male, &parts.patronymic, salt, attempt);
        morph::patronymic_from_name(&male_name, parts.gender)
    };
    let nom = [surname, name, patronymic]
        .iter()
        .filter(|s| !s.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let inflected = if parts.case == morph::Case::Nom {
        nom
    } else {
        morph::inflect(&nom, Kind::Person, parts.case).unwrap_or(nom)
    };
    morph::apply_original_styles(original, &inflected)
}

/// Build a plausible pseudonym for a place/country value from a dictionary.
fn pseudonym_place(original: &str, list: &[String], salt: Option<&str>, attempt: usize) -> String {
    let (prefix, name) = split_place_prefix(original);
    let picked = pick_from(list, &name, salt, attempt);
    let case = morph::detect_place_case(&name);
    let inflected = if case == morph::Case::Nom {
        picked
    } else {
        morph::inflect(&picked, Kind::Place, case).unwrap_or(picked)
    };
    let styled = morph::apply_original_styles(&name, &inflected);
    if prefix.is_empty() {
        styled
    } else {
        format!("{prefix} {styled}")
    }
}

/// Place prefixes preserved verbatim before a toponym (г., город, с., пос., д.).
const PLACE_PREFIXES: [&str; 5] = ["г.", "город", "с.", "пос.", "д."];

/// Split a place value into a preserved prefix and the toponym name.
fn split_place_prefix(value: &str) -> (String, String) {
    let ws: Vec<&str> = value.split_whitespace().collect();
    if ws.is_empty() {
        return (String::new(), value.to_string());
    }
    let lower_first = ws[0].to_lowercase();
    if PLACE_PREFIXES.contains(&lower_first.as_str()) {
        (ws[0].to_string(), ws[1..].join(" "))
    } else {
        (String::new(), value.to_string())
    }
}

/// Address markers that introduce a city name.
const CITY_MARKERS: [&str; 2] = ["г.", "город"];
/// Address markers that introduce a street name.
const STREET_MARKERS_FULL: [&str; 9] = [
    "ул.", "улица", "пр.", "проспект", "пер.", "переулок", "ш.", "шоссе", "наб.",
];
/// Address markers that introduce a house/flat number.
const NUM_MARKERS: [&str; 6] = ["д.", "дом", "кв.", "квартира", "корп.", "стр."];

/// Split a single address part into a preserved marker and the value after it.
fn split_address_marker<'a>(trimmed: &'a str, lower: &str) -> Option<(String, &'a str)> {
    for m in CITY_MARKERS
        .iter()
        .chain(STREET_MARKERS_FULL.iter())
        .chain(NUM_MARKERS.iter())
    {
        if lower.starts_with(m) {
            let marker = &trimmed[..m.len()];
            let value = trimmed[m.len()..].trim();
            if !value.is_empty() {
                return Some((marker.to_string(), value));
            }
        }
    }
    None
}

/// Generate a random number of the same digit length as `digits`, without a leading zero.
fn random_number_same_len(digits: &str, rng: &mut impl rand::Rng) -> String {
    let len = digits.chars().filter(|c| c.is_ascii_digit()).count().max(1);
    let mut out = String::with_capacity(len);
    out.push(char::from_digit(rng.gen_range(1..10), 10).unwrap());
    for _ in 1..len {
        out.push(char::from_digit(rng.gen_range(0..10), 10).unwrap());
    }
    out
}

/// Build a plausible pseudonym for an address, replacing each part by its marker type:
/// city from `CITIES`, street from `STREETS`, house/flat number of the same length.
/// Parts without a recognized marker fall back to `pseudonym_place`.
fn pseudonym_address(original: &str, salt: Option<&str>, attempt: usize) -> String {
    let mut rng = rand::thread_rng();
    let parts: Vec<&str> = original.split(',').collect();
    let mut out: Vec<String> = Vec::with_capacity(parts.len());
    for part in parts {
        let trimmed = part.trim();
        let lower = trimmed.to_lowercase();
        let replaced = match split_address_marker(trimmed, &lower) {
            Some((marker, value)) => {
                if CITY_MARKERS.contains(&marker.as_str()) {
                    let picked = pick_from(&CITIES, value, salt, attempt);
                    let case = morph::detect_place_case(value);
                    let inflected = if case == morph::Case::Nom {
                        picked
                    } else {
                        morph::inflect(&picked, Kind::Place, case).unwrap_or(picked)
                    };
                    let styled = morph::apply_original_styles(value, &inflected);
                    format!("{marker} {styled}")
                } else if STREET_MARKERS_FULL.contains(&marker.as_str()) {
                    let picked = pick_from(&STREETS, value, salt, attempt);
                    let styled = morph::apply_original_styles(value, &picked);
                    format!("{marker} {styled}")
                } else {
                    let new_num = random_number_same_len(value, &mut rng);
                    format!("{marker} {new_num}")
                }
            }
            None => pseudonym_place(trimmed, &CITIES, salt, attempt),
        };
        out.push(replaced);
    }
    out.join(", ")
}

/// Rebuild a digit string preserving the non-digit separators of the original.
fn rebuild_digits(original: &str, digits: &[u32]) -> String {
    let mut it = digits.iter();
    let mut out = String::new();
    for c in original.chars() {
        if c.is_ascii_digit() {
            out.push(char::from_digit(*it.next().unwrap_or(&0), 10).unwrap());
        } else {
            out.push(c);
        }
    }
    out
}

/// Generate a valid INN (10 or 12 digits) preserving the original length and separators.
/// The first digit is never 0 (a real INN does not start with 0).
fn pseudonym_inn(original: &str, rng: &mut impl rand::Rng) -> String {
    let count = original.chars().filter(|c| c.is_ascii_digit()).count();
    let mut out: Vec<u32> = Vec::with_capacity(count);
    if count == 10 {
        out.push(rng.gen_range(1..10));
        for _ in 1..9 {
            out.push(rng.gen_range(0..10));
        }
        let coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8];
        let sum: u32 = coeffs.iter().zip(&out).map(|(&c, &d)| c * d).sum();
        out.push((sum % 11) % 10);
    } else if count == 12 {
        out.push(rng.gen_range(1..10));
        for _ in 1..10 {
            out.push(rng.gen_range(0..10));
        }
        let c1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
        let s1: u32 = c1.iter().zip(&out).map(|(&c, &d)| c * d).sum();
        out.push((s1 % 11) % 10);
        let c2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
        let s2: u32 = c2.iter().zip(&out).map(|(&c, &d)| c * d).sum();
        out.push((s2 % 11) % 10);
    } else {
        return original.to_string();
    }
    rebuild_digits(original, &out)
}

/// Generate a valid SNILS (11 digits) preserving the original separators.
fn pseudonym_snils(original: &str, rng: &mut impl rand::Rng) -> String {
    let mut out: Vec<u32> = Vec::with_capacity(11);
    for _ in 0..9 {
        out.push(rng.gen_range(0..10));
    }
    let sum: u32 = out.iter().zip((1..=9).rev()).map(|(&d, w)| d * w).sum();
    let control = if sum < 100 {
        sum
    } else if sum == 100 || sum == 101 {
        0
    } else {
        let m = sum % 101;
        if m == 100 { 0 } else { m }
    };
    out.push(control / 10);
    out.push(control % 10);
    rebuild_digits(original, &out)
}

/// Generate a valid Luhn card number preserving the original length and separators.
/// The first digit is 2, 4 or 5 (MIR/Visa/Mastercard).
fn pseudonym_card(original: &str, rng: &mut impl rand::Rng) -> String {
    let count = original.chars().filter(|c| c.is_ascii_digit()).count();
    if count < 2 {
        return original.to_string();
    }
    let mut out: Vec<u32> = Vec::with_capacity(count);
    out.push([2u32, 4, 5][rng.gen_range(0..3)]);
    for _ in 1..count - 1 {
        out.push(rng.gen_range(0..10));
    }
    out.push(luhn_check(&out) as u32);
    rebuild_digits(original, &out)
}

/// Generate a plausible phone number preserving the leading +7/8 and separators.
fn pseudonym_phone(original: &str, rng: &mut impl rand::Rng) -> String {
    let count = original.chars().filter(|c| c.is_ascii_digit()).count();
    if count < 11 {
        return original.to_string();
    }
    let first = original
        .chars()
        .find(|c| c.is_ascii_digit())
        .and_then(|c| c.to_digit(10))
        .unwrap_or(7);
    let mut out: Vec<u32> = Vec::with_capacity(count);
    out.push(first);
    let mut code = rng.gen_range(900..1000);
    if code == 900 {
        code = 901;
    }
    out.push(code / 100);
    out.push((code / 10) % 10);
    out.push(code % 10);
    for _ in 3..count {
        out.push(rng.gen_range(0..10));
    }
    rebuild_digits(original, &out)
}

/// Transliterate a Cyrillic string to Latin (lowercase).
fn transliterate(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let l = c.to_lowercase().next().unwrap_or(c);
        let mapped = match l {
            'а' => "a", 'б' => "b", 'в' => "v", 'г' => "g", 'д' => "d",
            'е' => "e", 'ё' => "e", 'ж' => "zh", 'з' => "z", 'и' => "i",
            'й' => "y", 'к' => "k", 'л' => "l", 'м' => "m", 'н' => "n",
            'о' => "o", 'п' => "p", 'р' => "r", 'с' => "s", 'т' => "t",
            'у' => "u", 'ф' => "f", 'х' => "kh", 'ц' => "ts", 'ч' => "ch",
            'ш' => "sh", 'щ' => "shch", 'ъ' => "", 'ы' => "y", 'ь' => "",
            'э' => "e", 'ю' => "yu", 'я' => "ya",
            _ => "",
        };
        out.push_str(mapped);
    }
    out
}

/// Build a plausible email: login from a pseudonym name+surname, domain from the YAML list.
fn pseudonym_email(original: &str, registry: &Registry, salt: Option<&str>, attempt: usize) -> String {
    let domains = registry.pseudonym_email_domains();
    let domain = if domains.is_empty() {
        "example.com".to_string()
    } else {
        let idx = hash_index(&format!("domain\0{original}\0{}\0{attempt}", salt.unwrap_or(""))) as usize % domains.len();
        domains[idx].clone()
    };
    let name = pick_name(Gender::Male, original, salt, attempt);
    let surname = pick_surname(&morph::SurnameGroup::Ov, original, salt, attempt);
    let login = transliterate(&format!("{name}.{surname}"));
    format!("{login}@{domain}")
}

/// Generate a plausible date preserving the format and decade/year of the original.
fn pseudonym_date(original: &str, birth: bool, rng: &mut impl rand::Rng) -> String {
    let digits: Vec<u32> = original
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap())
        .collect();
    if digits.len() < 4 {
        return original.to_string();
    }
    let year = if digits.len() >= 4 {
        let y = digits[digits.len() - 4..].iter().fold(0u32, |acc, &d| acc * 10 + d);
        y
    } else {
        2000
    };
    let new_year = if birth {
        let decade = (year / 10) * 10;
        decade + rng.gen_range(0..10)
    } else {
        year
    };
    let month = rng.gen_range(1..=12);
    let day = rng.gen_range(1..=28);
    let mut new_digits: Vec<u32> = Vec::new();
    if digits.len() >= 8 {
        new_digits.push(day / 10);
        new_digits.push(day % 10);
        new_digits.push(month / 10);
        new_digits.push(month % 10);
        let y = new_year;
        new_digits.push((y / 1000) % 10);
        new_digits.push((y / 100) % 10);
        new_digits.push((y / 10) % 10);
        new_digits.push(y % 10);
    } else {
        let y = new_year;
        new_digits.push((y / 1000) % 10);
        new_digits.push((y / 100) % 10);
        new_digits.push((y / 10) % 10);
        new_digits.push(y % 10);
    }
    rebuild_digits(original, &new_digits)
}

/// Generate a plausible pseudonym for a value of the given PII type.
fn pseudonym(
    original: &str,
    type_id: &str,
    text: &str,
    registry: &Registry,
    numbering: &Numbering,
    used: &mut HashSet<String>,
) -> String {
    let salt = salt_of(numbering);
    let mut rng = rand::thread_rng();
    for attempt in 0..20 {
        let candidate = match type_id {
            "fio" | "card_holder" => pseudonym_fio(original, salt, attempt),
            "birth_place" => pseudonym_place(original, &CITIES, salt, attempt),
            "citizenship" => pseudonym_place(original, &COUNTRIES, salt, attempt),
            "address" => pseudonym_address(original, salt, attempt),
            "passport_issuer" => pseudonym_place(original, &CITIES, salt, attempt),
            "birth_date" => pseudonym_date(original, true, &mut rng),
            "passport_issue_date" => pseudonym_date(original, false, &mut rng),
            "inn" => pseudonym_inn(original, &mut rng),
            "snils" => pseudonym_snils(original, &mut rng),
            "card_number" => pseudonym_card(original, &mut rng),
            "phone" => pseudonym_phone(original, &mut rng),
            "email" => pseudonym_email(original, registry, salt, attempt),
            _ => synthetic_digits(original, &mut rng),
        };
        if candidate != original && !text.contains(&candidate) && !used.contains(&candidate) {
            used.insert(candidate.clone());
            return candidate;
        }
    }
    // Fallback: force a difference by appending a digit to a digit value.
    let fallback = format!("{original}0");
    used.insert(fallback.clone());
    fallback
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmask_case_suffix_matching_original_case_returns_original() {
        let mapping = Mapping {
            type_id: "fio".to_string(),
            original: "Иванову Ивану Ивановичу".to_string(),
            masked: "<<FIO_1>>".to_string(),
        };
        let restored = unmask("<<FIO_1:дат>>", &[mapping]);
        assert_eq!(restored, "Иванову Ивану Ивановичу");
    }

    #[test]
    fn unmask_place_nominative_suffix_returns_nominative() {
        let mapping = Mapping {
            type_id: "birth_place".to_string(),
            original: "Москве".to_string(),
            masked: "<<BPLACE_1>>".to_string(),
        };
        let restored = unmask("<<BPLACE_1:им>>", &[mapping]);
        assert_eq!(restored, "Москва");
    }

    #[test]
    fn unmask_place_prepositional_suffix_returns_prepositional() {
        let mapping = Mapping {
            type_id: "birth_place".to_string(),
            original: "Москве".to_string(),
            masked: "<<BPLACE_1>>".to_string(),
        };
        let restored = unmask("<<BPLACE_1:пр>>", &[mapping]);
        assert_eq!(restored, "Москве");
    }

    #[test]
    fn unmask_fio_dative_suffix_returns_dative() {
        let mapping = Mapping {
            type_id: "fio".to_string(),
            original: "Иванов Иван Иванович".to_string(),
            masked: "<<FIO_1>>".to_string(),
        };
        let restored = unmask("<<FIO_1:дат>>", &[mapping]);
        assert_eq!(restored, "Иванову Ивану Ивановичу");
    }
}