use crate::config::TrapPolicy;
use crate::registry::{Registry, TypeSpec, Validator};
use crate::types::Entity;
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};

/// Allow-list of public persons and organizations that must NOT be treated as personal data.
/// A full-name match is a negative signal (−0.3); an organization near an address is −0.3.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    /// Normalized full names (lowercased, spaces collapsed, dots removed) as sorted word multisets.
    public_persons: Vec<Vec<String>>,
    /// Organization names, lowercased.
    organizations: Vec<String>,
}

impl Allowlist {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml_ng::Error> {
        #[derive(serde::Deserialize)]
        struct Root {
            #[serde(default)]
            public_persons: Vec<String>,
            #[serde(default)]
            organizations: Vec<String>,
        }
        let root: Root = serde_yaml_ng::from_str(text)?;
        let public_persons = root
            .public_persons
            .iter()
            .map(|p| normalize_name_words(p))
            .collect();
        let organizations = root.organizations.iter().map(|o| o.to_lowercase()).collect();
        Ok(Self { public_persons, organizations })
    }

    /// True if the normalized words of a detected FIO (2+ words) are a subset of a public person's
    /// full name. A single surname alone is not a match.
    fn matches_person_subset(&self, words: &[String]) -> bool {
        if words.len() < 2 {
            return false;
        }
        let set: HashSet<&String> = words.iter().collect();
        self.public_persons.iter().any(|p| {
            let pset: HashSet<&String> = p.iter().collect();
            set.iter().all(|w| pset.contains(w))
        })
    }

    /// True if the word appears as a surname in any public person's full name.
    fn is_public_surname(&self, word: &str) -> bool {
        self.public_persons.iter().any(|p| p.iter().any(|w| w == word))
    }

    /// True if any organization name appears within `window` chars around byte range [start, end).
    /// Orgs that are also non-PII markers are excluded (the marker penalty already handles them).
    fn org_near(&self, text: &str, start: usize, end: usize, window: usize, exclude: &[String]) -> bool {
        if self.organizations.is_empty() {
            return false;
        }
        let before = context_window_before(text, start, window).to_lowercase();
        let after = context_window_after(text, end, window).to_lowercase();
        self.organizations.iter().any(|org| {
            if exclude.iter().any(|m| org.contains(m)) {
                return false;
            }
            before.contains(org) || after.contains(org)
        })
    }
}

/// Normalizes a full name: lowercase, collapse whitespace, drop dots (initials).
fn normalize_name_words(s: &str) -> Vec<String> {
    let mut words: Vec<String> = s
        .split_whitespace()
        .map(|w| w.chars().filter(|c| !matches!(c, '.' | ',')).collect::<String>().to_lowercase())
        .filter(|w| !w.is_empty())
        .collect();
    words.sort();
    words
}

/// Named word lists (surnames, first names, patronymics, cities, public persons...). Lowercased.
pub struct Dictionaries {
    pub lists: HashMap<String, HashSet<String>>,
}
impl Dictionaries {
    pub fn empty() -> Self {
        Self { lists: HashMap::new() }
    }

    pub fn load_dir(dir: &std::path::Path) -> std::io::Result<Self> {
        let mut lists = HashMap::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "txt").unwrap_or(false) {
                let name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let content = std::fs::read_to_string(&path)?;
                let mut words = HashSet::new();
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    words.insert(normalize_yo(&line.to_lowercase()));
                }
                lists.insert(name, words);
            }
        }
        Ok(Self { lists })
    }

    pub fn contains(&self, list: &str, word_lower: &str) -> bool {
        self.lists
            .get(list)
            .map(|s| {
                // `word_lower` is already lowercased, so 'Ё' never appears. Normalize only
                // when 'ё' is present to avoid allocating on the hot path.
                if word_lower.contains('ё') {
                    s.contains(&word_lower.replace('ё', "е"))
                } else {
                    s.contains(word_lower)
                }
            })
            .unwrap_or(false)
    }
}

/// Replaces 'ё'/'Ё' with 'е'/'Е' so that dictionary lookups treat them as equivalent
/// (e.g. "Королёв" matches "королев" and vice versa). The text itself is never changed.
fn normalize_yo(s: &str) -> String {
    s.replace('ё', "е").replace('Ё', "Е")
}

pub struct DetectOptions<'a> {
    /// Only these type ids are detected; None = all registry types.
    pub enabled_types: Option<&'a [String]>,
    pub min_confidence: f32,
    /// Substrings that must never be reported (bank office addresses, service phones).
    pub allow_substrings: &'a [String],
    /// How to resolve a conflict between PII and non-PII markers.
    pub trap_policy: TrapPolicy,
}

pub struct Detector {
    registry: std::sync::Arc<Registry>,
    dicts: std::sync::Arc<Dictionaries>,
    /// Birth dates older than this many years get a confidence penalty.
    historical_date_years: u32,
    /// Public persons and organizations that must not be treated as PII.
    allowlist: std::sync::Arc<Allowlist>,
    /// Combined regex of all marker-type context words (cvv, pin, passport, inn, ...).
    marker_re: Option<Regex>,
    /// Maps a lowercase marker word to the type id it belongs to.
    marker_type_of: HashMap<String, String>,
    /// Lowercased context words of every registry type except `address`, plus the document
    /// markers. A "word number" address component whose word is in this set is not a street
    /// (e.g. "Паспорт 4509", "Карта 4276", "Телефон 8..."). Built once at construction.
    non_address_context_words: HashSet<String>,
}

/// Marker types that use the nearest-left-marker rule to resolve context.
fn is_marker_type(id: &str) -> bool {
    matches!(id, "cvv" | "card_pin" | "passport" | "inn" | "subdivision_code" | "driver_license")
}

/// Kind of a single address component, used to detect full addresses by structure.
#[derive(PartialEq, Clone, Copy)]
enum AddrKind {
    City,
    Street,
    House,
    Apartment,
    Region,
    Index,
    Other,
}

/// Builds the combined marker regex and word->type map from the registry.
fn build_marker_map(registry: &Registry) -> (Option<Regex>, HashMap<String, String>) {
    let mut marker_type_of: HashMap<String, String> = HashMap::new();
    let mut words: Vec<String> = Vec::new();
    for spec in registry.types() {
        if is_marker_type(&spec.id) {
            for w in &spec.context_words {
                let wl = w.to_lowercase();
                if marker_type_of.insert(wl.clone(), spec.id.clone()).is_none() {
                    words.push(wl);
                }
            }
        }
    }
    if words.is_empty() {
        return (None, marker_type_of);
    }
    let alt = words.iter().map(|w| regex::escape(w)).collect::<Vec<_>>().join("|");
    let re = RegexBuilder::new(&format!(r"(?:{})", alt))
        .case_insensitive(true)
        .unicode(true)
        .build()
        .expect("valid marker regex");
    (Some(re), marker_type_of)
}

/// Builds the set of lowercased context words of every registry type except `address`, plus
/// the document markers. A "word number" address component whose leading word is in this set
/// is a field label of another PII type (паспорт, карта, инн, снилс, телефон, серия, номер...),
/// not a street name.
fn build_non_address_context_words(registry: &Registry) -> HashSet<String> {
    let mut set: HashSet<String> = HashSet::new();
    for spec in registry.types() {
        if spec.id == "address" {
            continue;
        }
        for w in &spec.context_words {
            set.insert(w.to_lowercase());
        }
    }
    for m in DOCUMENT_MARKERS {
        set.insert(m.to_string());
    }
    set
}

impl Detector {
    pub fn new(registry: std::sync::Arc<Registry>, dicts: std::sync::Arc<Dictionaries>) -> Self {
        let (marker_re, marker_type_of) = build_marker_map(&registry);
        let non_address_context_words = build_non_address_context_words(&registry);
        Self {
            registry,
            dicts,
            historical_date_years: 120,
            allowlist: std::sync::Arc::new(Allowlist::empty()),
            marker_re,
            marker_type_of,
            non_address_context_words,
        }
    }

    /// Like `new` but with an allow-list of public persons and organizations.
    pub fn with_allowlist(
        registry: std::sync::Arc<Registry>,
        dicts: std::sync::Arc<Dictionaries>,
        allowlist: Allowlist,
    ) -> Self {
        let (marker_re, marker_type_of) = build_marker_map(&registry);
        let non_address_context_words = build_non_address_context_words(&registry);
        Self {
            registry,
            dicts,
            historical_date_years: 120,
            allowlist: std::sync::Arc::new(allowlist),
            marker_re,
            marker_type_of,
            non_address_context_words,
        }
    }

    /// Sets the historical-date threshold (years). Defaults to 120.
    pub fn with_historical_date_years(mut self, years: u32) -> Self {
        self.historical_date_years = years;
        self
    }

    /// Runs all enabled types, validates, scores, drops allow-listed and overlapping spans
    /// (longer / more confident wins). Result sorted by start. Case-insensitive.
    ///
    /// Before detection, Latin lookalike letters inside words that contain at least one
    /// Cyrillic letter are normalized to their Cyrillic equivalents (e.g. "Иванoв" -> "Иванов").
    /// Entity offsets are translated back to the original text. When no mixed word is present
    /// the original text is used as-is (no offset table is built).
    pub fn detect(&self, text: &str, opts: &DetectOptions<'_>) -> Vec<Entity> {
        match normalize_mixed(text) {
            Some((norm, map)) => {
                let mut result = self.detect_inner(&norm, opts);
                for e in &mut result {
                    e.start = map[e.start];
                    e.end = map[e.end];
                }
                result
            }
            None => self.detect_inner(text, opts),
        }
    }

    /// Detection pipeline over a single text (already normalized when needed). Offsets are
    /// relative to `text`.
    fn detect_inner(&self, text: &str, opts: &DetectOptions<'_>) -> Vec<Entity> {
        let enabled: Option<HashSet<&str>> = opts
            .enabled_types
            .map(|ids| ids.iter().map(|s| s.as_str()).collect());

        let mut candidates: Vec<Entity> = Vec::new();

        for spec in self.registry.types() {
            if let Some(set) = &enabled {
                if !set.contains(spec.id.as_str()) {
                    continue;
                }
            }
            match spec.id.as_str() {
                "fio" => candidates.extend(self.detect_fio(text, opts, spec)),
                "birth_date" | "passport_issue_date" => {
                    candidates.extend(self.detect_date(text, opts, spec))
                }
                "birth_place" => candidates.extend(self.detect_birth_place(text, opts, spec)),
                "citizenship" => candidates.extend(self.detect_citizenship(text, opts, spec)),
                "passport_issuer" => candidates.extend(self.detect_passport_issuer(text, opts, spec)),
                "address" => candidates.extend(self.detect_address(text, opts, spec)),
                "card_holder" => candidates.extend(self.detect_card_holder(text, opts, spec)),
                _ => self.detect_regex_type(text, opts, spec, &mut candidates),
            }
        }

        self.apply_neighbor_boost(text, &mut candidates);
        self.drop_bare_public_persons(text, &mut candidates);
        let all_fios: Vec<(usize, usize)> = candidates
            .iter()
            .filter(|e| e.type_id == "fio")
            .map(|e| (e.start, e.end))
            .collect();
        let mut result = resolve_overlaps(candidates);
        self.drop_biography_fios(text, &mut result);
        self.drop_historical_dates_bound_to_biography(text, &mut result, &all_fios);
        result
    }

    /// A FIO that is a full match with a public person is masked only when a strong PII marker
    /// or a confident neighboring entity is present. Otherwise it is a biographical reference
    /// (e.g. "Александр Сергеевич Пушкин", "Лев Николаевич Толстой родился в 1828 году").
    fn drop_bare_public_persons(&self, text: &str, candidates: &mut Vec<Entity>) {
        let confident: Vec<(usize, usize)> = candidates
            .iter()
            .filter(|e| e.type_id != "fio" && e.confidence >= 0.9)
            .map(|e| (e.start, e.end))
            .collect();
        candidates.retain(|e| {
            if e.type_id != "fio" {
                return true;
            }
            let span_words = normalize_name_words(&text[e.start..e.end]);
            if !self.allowlist.matches_person_subset(&span_words) {
                return true;
            }
            if self.strong_pii_marker(text, e.start, e.end) {
                return true;
            }
            // A confident neighboring entity (passport, phone, card, ...) in the same sentence
            // marks the person as a client. Entities overlapping the FIO span itself (e.g. a
            // city homonym "Пушкин") are not neighbors. Without such a neighbor the FIO is a
            // bare biographical reference and is dropped.
            confident
                .iter()
                .any(|(cs, ce)| (*ce <= e.start || *cs >= e.end) && same_sentence(text, e.start, *cs))
        });
    }

    /// A FIO preceded by a strong biographical marker (поэт, писатель, композитор,
    /// "в биографии", памятник, музей, император) is a biographical reference, not a
    /// client, and is not masked. The FIO stays in `all_fios` so a historical date bound to
    /// it is also dropped.
    fn drop_biography_fios(&self, text: &str, result: &mut Vec<Entity>) {
        result.retain(|e| {
            if e.type_id != "fio" {
                return true;
            }
            !self.strong_biography_marker_before(text, e.start)
        });
    }

    /// A historical birth date (year older than `historical_date_years`) whose nearest FIO to
    /// the left (within 80 chars) is a biographical reference (not masked) is not masked: it
    /// belongs to a public person, not a client.
    fn drop_historical_dates_bound_to_biography(
        &self,
        text: &str,
        result: &mut Vec<Entity>,
        all_fios: &[(usize, usize)],
    ) {
        let masked_fios: Vec<(usize, usize)> = result
            .iter()
            .filter(|e| e.type_id == "fio")
            .map(|e| (e.start, e.end))
            .collect();
        result.retain(|e| {
            if e.type_id != "birth_date" {
                return true;
            }
            let span = &text[e.start..e.end];
            if !age_exceeds(span, self.historical_date_years) {
                return true;
            }
            let nearest = all_fios
                .iter()
                .filter(|(s, _)| *s < e.start && e.start - *s <= 80)
                .max_by_key(|(s, _)| *s);
            match nearest {
                // A FIO exists to the left; keep the date only when that FIO is masked (a
                // client). A biographical reference (not masked) means the date belongs to a
                // public person and is dropped.
                Some((fs, _)) => masked_fios.iter().any(|(s, _)| *s == *fs),
                None => true,
            }
        });
    }

    /// Boosts FIO confidence by +0.2 when another confident entity (passport, INN, phone, card)
    /// with confidence >= 0.9 is in the same sentence.
    fn apply_neighbor_boost(&self, text: &str, candidates: &mut [Entity]) {
        let confident: Vec<&Entity> = candidates
            .iter()
            .filter(|e| e.type_id != "fio" && e.confidence >= 0.9)
            .collect();
        if confident.is_empty() {
            return;
        }
        let boosts: Vec<(usize, bool)> = candidates
            .iter()
            .enumerate()
            .filter(|(_, e)| e.type_id == "fio")
            .map(|(i, e)| {
                let boosted = confident.iter().any(|c| same_sentence(text, e.start, c.start));
                (i, boosted)
            })
            .collect();
        for (i, boosted) in boosts {
            if boosted {
                candidates[i].confidence = (candidates[i].confidence + 0.2).min(1.0);
            }
        }
    }

    /// Generic regex-based detection used by all non-special types.
    fn detect_regex_type(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        spec: &TypeSpec,
        candidates: &mut Vec<Entity>,
    ) {
        let patterns = self.registry.patterns(&spec.id);
        if patterns.is_empty() {
            return;
        }
        for re in patterns {
            for m in re.find_iter(text) {
                if let Some(entity) = self.regex_match_entity(text, opts, spec, m.start(), m.end()) {
                    candidates.push(entity);
                }
            }
        }
    }

    /// Builds a single candidate entity for a regex match, or None when the span is rejected.
    fn regex_match_entity(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        spec: &TypeSpec,
        start: usize,
        end: usize,
    ) -> Option<Entity> {
        let span = &text[start..end];
        let has_context = self.regex_has_context(text, start, end, spec);
        if self.regex_wrong_document_type(text, start, spec) {
            return None;
        }
        // A number right after a document marker (накладная, партия, счёт-фактура, артикул,
        // инвентарный номер, тикет, заказ) is a document number, not a passport.
        if spec.id == "passport" && self.has_document_marker_before(text, start) {
            return None;
        }
        let (conf, skip_context_boost) =
            self.regex_confidence(span, spec, has_context, text, start, end)?;
        let conf = self.regex_final_confidence(span, spec, has_context, skip_context_boost, conf);
        if spec.context_required && !has_context {
            return None;
        }
        if self.has_non_pii_context(text, start, end, spec) {
            return None;
        }
        if !passes_threshold(conf, opts) {
            return None;
        }
        if self.is_allow_listed(span, opts) {
            return None;
        }
        Some(Entity { type_id: spec.id.clone(), start, end, confidence: conf })
    }

    /// True when a marker context word is present for the span.
    fn regex_has_context(&self, text: &str, start: usize, end: usize, spec: &TypeSpec) -> bool {
        if is_marker_type(&spec.id) {
            if matches!(spec.id.as_str(), "cvv" | "card_pin") {
                self.has_cvv_pin_marker(text, start, spec)
            } else {
                self.has_nearest_marker(text, start, spec)
            }
        } else if spec.context_words.is_empty() {
            false
        } else {
            let window = context_window_before(text, start, spec.context_window);
            let window_lower = window.to_lowercase();
            spec.context_words.iter().any(|w| window_lower.contains(w))
        }
    }

    /// True when the nearest document-type marker assigns the span to the other type.
    fn regex_wrong_document_type(&self, text: &str, start: usize, spec: &TypeSpec) -> bool {
        if !matches!(spec.id.as_str(), "passport" | "driver_license") {
            return false;
        }
        match self.nearest_document_type(text, start) {
            Some(is_dl) => is_dl != (spec.id == "driver_license"),
            None => false,
        }
    }

    /// Computes the base confidence for a regex match. None means the span is rejected.
    fn regex_confidence(
        &self,
        span: &str,
        spec: &TypeSpec,
        has_context: bool,
        text: &str,
        start: usize,
        end: usize,
    ) -> Option<(f32, bool)> {
        // A 15-digit number is not a bank card (cards are 16, rarely 13/14/18/19) unless a
        // card marker is present (e.g. "карта 427640003331517"). This rejects IMEI-like
        // numbers that pass Luhn.
        if spec.id == "card_number"
            && digit_count(span) == 15
            && !self.has_card_marker(text, start, end)
        {
            return None;
        }
        // A toll-free 8-800 / +7 800 number with a service marker (горячая линия, служба
        // поддержки, колл-центр) is a service line, not a personal phone.
        if spec.id == "phone"
            && phone_code_is_800(span)
            && self.has_service_marker_near(text, start, end)
        {
            return None;
        }
        let mut conf = 0.4f32;
        let mut skip_context_boost = false;
        if spec.id == "snils" {
            // SNILS: a valid control sum is confident (0.9) even without a marker;
            // an invalid sum is accepted only when a marker is present (0.7).
            if validator_passes(Validator::Snils, span) {
                conf = 0.9;
            } else if has_context {
                conf = 0.7;
            } else {
                return None;
            }
            skip_context_boost = true;
        } else if spec.validator != Validator::None {
            if validator_passes(spec.validator, span) {
                conf += 0.4;
            } else if spec.id == "card_number" && self.has_card_marker(text, start, end) {
                // A 16-digit card in 4x4 format after a card marker is masked even
                // when Luhn fails (synthetic jury numbers), at confidence 0.6.
                conf = 0.6;
                skip_context_boost = true;
            } else {
                return None;
            }
        }
        Some((conf, skip_context_boost))
    }

    /// Applies the context boost and the passport pair-pair rule, then clamps to [0, 1].
    fn regex_final_confidence(
        &self,
        span: &str,
        spec: &TypeSpec,
        has_context: bool,
        skip_context_boost: bool,
        mut conf: f32,
    ) -> f32 {
        if has_context && !skip_context_boost {
            conf += 0.3;
        }
        // A passport in "NN NN NNNNNN" format (series as two pairs + 6-digit number)
        // right after a passport marker is a confident passport (0.9).
        if spec.id == "passport" && has_context && PASSPORT_PAIR_PAIR_RE.is_match(span) {
            conf = 0.9;
        }
        conf.min(1.0)
    }

    /// True if the span is a substring of any allow-listed substring.
    fn is_allow_listed(&self, span: &str, opts: &DetectOptions<'_>) -> bool {
        let span_lower = span.to_lowercase();
        opts.allow_substrings
            .iter()
            .any(|a| a.to_lowercase().contains(&span_lower))
    }

    /// FIO: 2-3 capitalized words / initials, at least one dictionary or suffix hit.
    fn detect_fio(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        let all_tokens = name_tokens(text);
        let tokens = self.fio_tokens(text, &all_tokens);
        let n = tokens.len();
        for i in 0..n {
            for len in 1..=3usize {
                if i + len > n {
                    break;
                }
                let window = &tokens[i..i + len];
                if let Some(entity) = self.fio_window_entity(text, opts, spec, window) {
                    candidates.push(entity);
                }
            }
        }
        // Latin patronymic patterns (e.g. "Ivanov Ivan Ivanovich"): three capitalized Latin
        // words where the third ends in a patronymic suffix. Detected without a PII marker.
        for re in self.registry.patterns(&spec.id) {
            for m in re.find_iter(text) {
                if let Some(entity) = self.fio_pattern_entity(text, opts, spec, m.start(), m.end()) {
                    candidates.push(entity);
                }
            }
        }
        candidates
    }

    /// Builds a FIO candidate from a Latin patronymic pattern match, or None when rejected.
    fn fio_pattern_entity(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        spec: &TypeSpec,
        start: usize,
        end: usize,
    ) -> Option<Entity> {
        let span = &text[start..end];
        // The pattern is case-insensitive; require capitalized words ("с заглавной").
        if !span
            .split_whitespace()
            .all(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
        {
            return None;
        }
        if self.is_allow_listed(span, opts) {
            return None;
        }
        let conf = 0.7f32;
        if !passes_threshold(conf, opts) {
            return None;
        }
        Some(Entity { type_id: spec.id.clone(), start, end, confidence: conf })
    }

    /// Filters name tokens that may belong to a FIO span (drops marker and city tokens).
    fn fio_tokens(&self, text: &str, all_tokens: &[NameToken]) -> Vec<NameToken> {
        all_tokens
            .iter()
            .enumerate()
            .filter(|(i, t)| {
                // A context marker word (e.g. "Клиент", "Поэт") never belongs to a FIO span.
                if self.is_marker_word(&t.lower) {
                    return false;
                }
                if !self.is_city(&t.lower) {
                    return true;
                }
                // A city token is kept when followed by initials (a FIO pattern,
                // e.g. "г. Пушкин И. С."), or when it is not preceded by a city marker
                // (e.g. "Александр Сергеевич Пушкин" — "Пушкин" is a surname here).
                let followed_by_initial = all_tokens.get(i + 1).map(|n| n.is_initial).unwrap_or(false);
                if followed_by_initial {
                    return true;
                }
                !self.preceded_by_city_marker(text, t.start)
            })
            .map(|(_, t)| NameToken {
                start: t.start,
                end: t.end,
                lower: t.lower.clone(),
                capitalized: t.capitalized,
                is_initial: t.is_initial,
                is_latin: t.is_latin,
            })
            .collect()
    }

    /// Builds a FIO candidate for a token window, or None when the window is rejected.
    fn fio_window_entity(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        spec: &TypeSpec,
        window: &[NameToken],
    ) -> Option<Entity> {
        let (start, end, comps) = self.fio_window_valid(text, spec, window)?;
        let (has_pii, has_non_pii) = self.fio_context(text, spec, window, start, end);
        // Non-PII marker without PII marker suppresses the candidate.
        if has_non_pii && !has_pii {
            return None;
        }
        // A name in guillemets after a brand marker (e.g. "Магазин «Мария Ра»") is a
        // brand name, not a FIO.
        if in_guillemets(text, start, end) && self.has_brand_marker_before(text, start) {
            return None;
        }
        // A single-word FIO that is a public person's surname, near a birth marker,
        // is a biographical reference (e.g. "Пушкин родился 6 июня 1799"), not a client.
        if comps == 1
            && self.allowlist.is_public_surname(&window[0].lower)
            && self.has_birth_marker(text, start, end)
        {
            return None;
        }
        let conf = self.fio_confidence(text, opts, window, has_pii, has_non_pii);
        if !passes_threshold(conf, opts) {
            return None;
        }
        Some(Entity { type_id: spec.id.clone(), start, end, confidence: conf })
    }

    /// Structural checks for a FIO window. Returns (start, end, component_count) or None.
    fn fio_window_valid(
        &self,
        text: &str,
        spec: &TypeSpec,
        window: &[NameToken],
    ) -> Option<(usize, usize, usize)> {
        // All tokens must be capitalized words or initials.
        if window.iter().any(|t| !t.capitalized) {
            return None;
        }
        // Consecutive tokens must be adjacent (only spaces / periods between).
        if window.windows(2).any(|w| !tokens_adjacent(text, &w[0], &w[1])) {
            return None;
        }
        // Skip tokens that are part of an address (after street markers).
        if window.iter().any(|t| self.preceded_by_street_marker(text, t.start)) {
            return None;
        }
        // A word after a military/academic rank (e.g. "Маршала Жукова, д. 15") is a
        // street name, not a FIO.
        if is_rank_word(&window[0].lower) {
            return None;
        }
        let (qualifies, comps) = self.fio_qualifies(window);
        if !qualifies {
            return None;
        }
        // Single word requires PII context.
        if comps == 1 && !self.has_pii_context(text, window[0].start, window[0].end, spec) {
            return None;
        }
        // A Latin name (e.g. "Theodore Weaver") requires PII context: Latin without a
        // PII marker is not a FIO (e.g. "Yves talks", "CREATE TABLE IF", "Russian State
        // University").
        if window.iter().all(|t| t.is_latin)
            && !self.has_pii_context(text, window[0].start, window[0].end, spec)
        {
            return None;
        }
        // First word of sentence, single candidate, not in any dict -> skip.
        if comps == 1 && is_sentence_start(text, window[0].start) && !self.in_any_name_dict(&window[0].lower) {
            return None;
        }
        let start = window[0].start;
        let end = window[window.len() - 1].end;
        Some((start, end, comps))
    }

    /// PII / non-PII context flags for a FIO window.
    fn fio_context(
        &self,
        text: &str,
        spec: &TypeSpec,
        window: &[NameToken],
        start: usize,
        end: usize,
    ) -> (bool, bool) {
        let has_pii = self.has_pii_context(text, start, end, spec);
        let mut has_non_pii = self.has_non_pii_context(text, start, end, spec);
        // A leading word that is itself a non-PII marker (e.g. "Поэт Александр Пушкин")
        // counts as non-PII context even though it is inside the span.
        if !has_non_pii {
            let non_pii = self.effective_non_pii_markers(spec);
            if non_pii.iter().any(|m| m == &window[0].lower) {
                has_non_pii = true;
            }
        }
        (has_pii, has_non_pii)
    }

    /// Computes the confidence for a validated FIO window.
    fn fio_confidence(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        window: &[NameToken],
        has_pii: bool,
        has_non_pii: bool,
    ) -> f32 {
        let comps = window.len();
        let start = window[0].start;
        let end = window[window.len() - 1].end;
        let mut conf = self.fio_base_confidence(window, comps);
        conf = self.fio_marker_adjustment(conf, opts, has_pii, has_non_pii);
        // A span whose words are a subset of a public person's name is a negative signal.
        let span_words = normalize_name_words(&text[start..end]);
        if self.allowlist.matches_person_subset(&span_words) {
            conf -= 0.3;
        }
        conf.clamp(0.0, 1.0)
    }

    /// Base confidence from the FIO shape (component count, initials, Latin).
    fn fio_base_confidence(&self, window: &[NameToken], comps: usize) -> f32 {
        let mut conf: f32 = match comps {
            3 => 0.6,
            _ => 0.5,
        };
        // Two words, one a first name and one a surname in oblique case (e.g. "Ивану
        // Петрову") are a confident FIO.
        if comps == 2 {
            let any_first_case = window.iter().any(|t| self.first_name_in_any_case(&t.lower));
            let any_surname_case = window.iter().any(|t| self.surname_in_any_case(&t.lower));
            if any_first_case && any_surname_case {
                conf = 0.7;
            }
        }
        // Surname + initials (e.g. "Лукин П. П.", "П.П. Лукин") is a confident FIO.
        let has_initial = window.iter().any(|t| t.is_initial);
        let has_surname = window
            .iter()
            .any(|t| self.in_any_name_dict(&t.lower) || self.is_surname_suffix(&t.lower));
        if has_initial && has_surname {
            conf = 0.8;
        }
        // A Latin name near a PII marker (e.g. "клиент Theodore Weaver") is a confident FIO.
        if comps == 2 && window.iter().all(|t| t.is_latin) {
            conf = 0.7;
        }
        conf
    }

    /// Applies the PII / non-PII marker conflict adjustment per the trap policy.
    fn fio_marker_adjustment(
        &self,
        mut conf: f32,
        opts: &DetectOptions<'_>,
        has_pii: bool,
        has_non_pii: bool,
    ) -> f32 {
        if has_pii && has_non_pii {
            match opts.trap_policy {
                TrapPolicy::PreferMask => conf += 0.3,
                TrapPolicy::PreferSkip => conf -= 0.3,
            }
        } else if has_pii {
            conf += 0.3;
        } else if has_non_pii {
            conf -= 0.3;
        }
        conf
    }

    /// Returns (qualifies_as_fio, component_count).
    fn fio_qualifies(&self, window: &[NameToken]) -> (bool, usize) {
        let comps = window.len();
        let any_dict = window.iter().any(|t| self.in_any_name_dict(&t.lower));
        let any_patronymic = window.iter().any(|t| self.is_patronymic(&t.lower));
        let any_surname_suffix = window.iter().any(|t| self.is_surname_suffix(&t.lower));
        let any_first_name = window.iter().any(|t| self.dicts.contains("first_names", &t.lower));
        let any_initial = window.iter().any(|t| t.is_initial);
        if any_dict || any_patronymic {
            return (true, comps);
        }
        if any_surname_suffix && (any_first_name || any_initial) {
            return (true, comps);
        }
        // A single word with a surname suffix (e.g. "Морозов", "Ефимов") qualifies as a FIO
        // when it carries PII context (handled by the caller: single words require a marker).
        if comps == 1 && any_surname_suffix {
            return (true, comps);
        }
        // Two adjacent capitalized words, one a first name and one a surname in any case
        // (oblique forms like "Ивану Петрову") qualify as a FIO.
        if comps == 2 {
            let any_first_case = window.iter().any(|t| self.first_name_in_any_case(&t.lower));
            let any_surname_case = window.iter().any(|t| self.surname_in_any_case(&t.lower));
            if any_first_case && any_surname_case {
                return (true, comps);
            }
        }
        // Two adjacent Latin capitalized words (e.g. "Theodore Weaver") qualify as a FIO
        // when near a PII marker (handled by the caller).
        if comps == 2 && window.iter().all(|t| t.is_latin) {
            return (true, comps);
        }
        // 3 capitalized words with no dictionary hit: only with PII context (handled by caller).
        if comps == 3 && !any_initial {
            // A mixed-script phrase (both Cyrillic and Latin words, e.g. "Сервис Online
            // Banking") is a brand/service name, not a FIO.
            let has_cyr = window.iter().any(|t| !t.is_latin);
            let has_lat = window.iter().any(|t| t.is_latin);
            if has_cyr && has_lat {
                return (false, comps);
            }
            return (true, comps);
        }
        (false, comps)
    }

    fn is_city(&self, lower: &str) -> bool {
        self.dicts.contains("cities", lower)
    }

    fn in_any_name_dict(&self, lower: &str) -> bool {
        self.dicts.contains("surnames", lower)
            || self.dicts.contains("first_names", lower)
            || self.dicts.contains("patronymics", lower)
    }

    /// True if the word is a first name in any grammatical case (nominative or oblique).
    fn first_name_in_any_case(&self, lower: &str) -> bool {
        if self.dicts.contains("first_names", lower) {
            return true;
        }
        let spec = self.registry.get("fio");
        let endings = spec.map(|s| s.first_name_case_endings.as_slice()).unwrap_or(&[]);
        endings.iter().any(|e| {
            if let Some(stripped) = lower.strip_suffix(e.as_str()) {
                if !stripped.is_empty() && self.dicts.contains("first_names", stripped) {
                    return true;
                }
            }
            false
        })
    }

    /// True if the word is a surname in any grammatical case (nominative or oblique).
    fn surname_in_any_case(&self, lower: &str) -> bool {
        if self.dicts.contains("surnames", lower) {
            return true;
        }
        let spec = self.registry.get("fio");
        let endings = spec.map(|s| s.first_name_case_endings.as_slice()).unwrap_or(&[]);
        if self.surname_matches_any_suffix(lower, endings) {
            return true;
        }
        let suffixes = spec.map(|s| s.surname_case_suffixes.as_slice()).unwrap_or(&[]);
        self.surname_matches_any_suffix(lower, suffixes)
    }

    /// True if stripping any of the given suffixes from `lower` leaves a non-empty stem
    /// that is present in the surnames dictionary.
    fn surname_matches_any_suffix(&self, lower: &str, suffixes: &[String]) -> bool {
        suffixes.iter().any(|s| {
            if let Some(stripped) = lower.strip_suffix(s.as_str()) {
                if !stripped.is_empty() && self.dicts.contains("surnames", stripped) {
                    return true;
                }
            }
            false
        })
    }

    fn is_patronymic(&self, lower: &str) -> bool {
        let spec = self.registry.get("fio");
        let suffixes = spec.map(|s| s.patronymic_suffixes.as_slice()).unwrap_or(&[]);
        suffixes.iter().any(|s| lower.ends_with(s))
    }

    fn is_surname_suffix(&self, lower: &str) -> bool {
        let spec = self.registry.get("fio");
        let suffixes = spec.map(|s| s.surname_suffixes.as_slice()).unwrap_or(&[]);
        suffixes.iter().any(|s| lower.ends_with(s))
    }

    fn has_pii_context(&self, text: &str, start: usize, end: usize, spec: &TypeSpec) -> bool {
        let markers = self.effective_pii_markers(spec);
        if markers.is_empty() {
            return false;
        }
        has_context_word_around(text, start, end, spec.context_window, &markers)
    }

    fn has_non_pii_context(&self, text: &str, start: usize, end: usize, spec: &TypeSpec) -> bool {
        let markers = self.effective_non_pii_markers(spec);
        if markers.is_empty() {
            return false;
        }
        has_context_word_around_wb(text, start, end, spec.context_window, &markers)
    }

    /// True if a global non-pii marker (юридический адрес, пункт выдачи, отделение,
    /// офис, банк...) appears within a window around the span.
    fn has_global_non_pii_near(&self, text: &str, start: usize, end: usize) -> bool {
        let markers = &self.registry.context().non_pii_markers;
        if markers.is_empty() {
            return false;
        }
        has_context_word_around(text, start, end, 60, markers)
    }

    /// Effective PII markers for a type: per-type `pii_markers`, else per-type `pii_context`,
    /// else the global `context.pii_markers`.
    fn effective_pii_markers(&self, spec: &TypeSpec) -> Vec<String> {
        if !spec.pii_markers.is_empty() {
            spec.pii_markers.clone()
        } else if !spec.pii_context.is_empty() {
            spec.pii_context.clone()
        } else {
            self.registry.context().pii_markers.clone()
        }
    }

    /// Effective non-PII markers for a type: per-type `non_pii_markers` (or `non_pii_context`)
/// combined with the global `context.non_pii_markers`. A type with its own `non_pii_markers`
    /// overrides the global list (like `effective_pii_markers`).
    fn effective_non_pii_markers(&self, spec: &TypeSpec) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if !spec.non_pii_markers.is_empty() {
            out.extend(spec.non_pii_markers.iter().cloned());
            return out;
        }
        if !spec.non_pii_context.is_empty() {
            out.extend(spec.non_pii_context.iter().cloned());
        }
        for m in &self.registry.context().non_pii_markers {
            if !out.contains(m) {
                out.push(m.clone());
            }
        }
        out
    }

    /// Strict cvv/pin marker check: the marker must be to the LEFT of the value, within 12
    /// chars, with only spaces, ':', '-', '=', or the word "код" between them. This rejects
    /// values like "001" in "CVV находится на обороте карты (заметка № 001/cvv)" while
    /// keeping glued forms like "CVV317".
    ///
    /// For CVV the check is relaxed to catch conversational speech ("нужен cvc, вот 123",
    /// "код на обороте карты 123"): the marker may be up to 30 chars to the left with at
    /// most 3 words and no other number in between, in the same sentence. A value right
    /// after "№", "номер", "заметка", "шаг", "ошибка", "код ошибки" or "версия" is never
    /// a CVV.
    fn has_cvv_pin_marker(&self, text: &str, start: usize, spec: &TypeSpec) -> bool {
        let markers = &spec.context_words;
        let window = context_window_before(text, start, 60);
        let window_start = start - window.len();
        let lower = window.to_lowercase();
        for m in markers {
            if let Some(pos) = lower.rfind(m) {
                let marker_end = window_start + pos + m.len();
                let between = &text[marker_end..start];
                if self.marker_between_ok(between, spec) {
                    return true;
                }
            }
        }
        false
    }

    /// True when the text between a marker and the value satisfies the pin/cvv rule.
    fn marker_between_ok(&self, between: &str, spec: &TypeSpec) -> bool {
        if spec.id == "cvv" {
            return self.cvv_marker_ok(between);
        }
        between.chars().count() <= 12 && is_pin_separator(between.trim())
    }

    /// True when the text between a CVV marker and the value satisfies the conversational
    /// rule: within 30 chars, at most 3 words, no other number, no sentence boundary, and
    /// the value is not immediately preceded by a non-CVV label word.
    fn cvv_marker_ok(&self, between: &str) -> bool {
        if between.chars().count() > 30 {
            return false;
        }
        // Same sentence: a sentence-ending punctuation or a newline ends the clause.
        if between.contains('.') || between.contains('!') || between.contains('?') || between.contains('\n') {
            return false;
        }
        // No other number between the marker and the value.
        if between.chars().any(|c| c.is_ascii_digit()) {
            return false;
        }
        // At most 3 words between the marker and the value.
        if between.split_whitespace().count() > 3 {
            return false;
        }
        // The value must not be immediately preceded by a non-CVV label word.
        let trimmed = between.trim_end();
        const NON_CVV_LABELS: [&str; 7] = ["№", "номер", "заметка", "шаг", "ошибка", "код ошибки", "версия"];
        !NON_CVV_LABELS.iter().any(|l| trimmed.ends_with(l))
    }

    /// True if `spec`'s marker is the effective context for a value at `start`, using the
    /// nearest-left-marker rule: a marker counts only when it is the nearest field label
    /// (word followed by ':') or the nearest marker of any marker type to the left.
    fn has_nearest_marker(&self, text: &str, start: usize, spec: &TypeSpec) -> bool {
        let markers = &spec.context_words;
        if markers.is_empty() {
            return false;
        }
        let field_end = self.nearest_field_label_end(text, start);
        let marker = self.nearest_marker_type(text, start);
        match (field_end, marker) {
            (Some(fe), Some((ty, me, word))) => {
                if fe > me {
                    self.field_label_matches(text, fe, spec)
                } else {
                    self.marker_type_matches(text, start, &ty, &word, spec)
                }
            }
            (Some(fe), None) => self.field_label_matches(text, fe, spec),
            (None, Some((ty, _, word))) => self.marker_type_matches(text, start, &ty, &word, spec),
            (None, None) => false,
        }
    }

    /// True if the nearest marker type `ty` (matched word `word`) makes the value belong to
    /// `spec`. A passport series label ("серия") is ambiguous: the nearest document-type
    /// marker (паспорт vs права/водительское/удостоверение) decides passport vs driver license.
    fn marker_type_matches(&self, text: &str, start: usize, ty: &str, word: &str, spec: &TypeSpec) -> bool {
        if is_series_label(word) {
            let is_dl = self.nearest_document_type(text, start) == Some(true);
            return if spec.id == "driver_license" { is_dl } else { !is_dl };
        }
        ty == spec.id
    }

    /// True if the phrase before a field label's colon (since the last sentence boundary)
    /// contains any of the given markers. A passport series label ("серия") is ambiguous and
    /// decided by the nearest document-type marker.
    fn field_label_matches(&self, text: &str, colon_end: usize, spec: &TypeSpec) -> bool {
        let window = context_window_before(text, colon_end, 200);
        let window_start = colon_end - window.len();
        let boundary = window
            .rfind(['.', ';', '\n', '!', '?'])
            .map(|i| window_start + i + 1)
            .unwrap_or(window_start);
        let phrase = &text[boundary..colon_end];
        let lower = phrase.to_lowercase();
        if is_series_label_phrase(&lower) {
            let is_dl = self.nearest_document_type(text, colon_end) == Some(true);
            return if spec.id == "driver_license" { is_dl } else { !is_dl };
        }
        spec.context_words.iter().any(|m| lower.contains(m))
    }

    /// Nearest document-type marker to the left of `start`: Some(true) if a driver license
    /// marker (права, водительское, удостоверение, ву) is closer than a passport marker
    /// (паспорт, паспортные), Some(false) if a passport marker is closer, None if neither.
    /// Series labels ("серия") are not document-type markers.
    fn nearest_document_type(&self, text: &str, start: usize) -> Option<bool> {
        let prefix = context_window_before(text, start, 200);
        let lower = prefix.to_lowercase();
        let mut best_dl: Option<usize> = None;
        let mut best_pp: Option<usize> = None;
        for m in DRIVER_LICENSE_DOC_MARKERS {
            if let Some(pos) = lower.rfind(m) {
                let end = pos + m.len();
                best_dl = Some(best_dl.map_or(end, |b| b.max(end)));
            }
        }
        for m in PASSPORT_DOC_MARKERS {
            if let Some(pos) = lower.rfind(m) {
                let end = pos + m.len();
                best_pp = Some(best_pp.map_or(end, |b| b.max(end)));
            }
        }
        match (best_dl, best_pp) {
            (Some(d), Some(p)) => Some(d > p),
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (None, None) => None,
        }
    }

    /// Returns the type id, end offset and matched word of the nearest marker-type context word
    /// to the left of `start` (within a bounded window), if any.
    fn nearest_marker_type(&self, text: &str, start: usize) -> Option<(String, usize, String)> {
        let re = self.marker_re.as_ref()?;
        let prefix = context_window_before(text, start, 200);
        let window_start = start - prefix.len();
        let mut best: Option<(String, usize, String)> = None;
        for m in re.find_iter(prefix) {
            let word = prefix[m.start()..m.end()].to_lowercase();
            if let Some(ty) = self.marker_type_of.get(&word) {
                if is_standalone_word(prefix, m.start(), m.end()) {
                    best = Some((ty.clone(), window_start + m.end(), word));
                }
            }
        }
        best
    }

    /// Returns the end offset of the nearest field label (word followed by ':') to the left
    /// of `start` (within a bounded window), if any.
    fn nearest_field_label_end(&self, text: &str, start: usize) -> Option<usize> {
        let prefix = context_window_before(text, start, 200);
        let window_start = start - prefix.len();
        FIELD_LABEL_RE.find_iter(prefix).map(|m| window_start + m.end()).max()
    }

    /// Nearest address marker to the left of `start`: Some(true) if pii, Some(false) if
    /// non-pii, None if no marker. The nearest marker decides the address type.
    fn nearest_address_marker(&self, text: &str, start: usize, spec: &TypeSpec) -> Option<bool> {
        let pii = self.effective_pii_markers(spec);
        let non_pii = self.effective_non_pii_markers(spec);
        let window = context_window_before(text, start, 200);
        let window_start = start - window.len();
        let lower = window.to_lowercase();
        let mut best_pii: Option<usize> = None;
        let mut best_non_pii: Option<usize> = None;
        for m in &pii {
            if let Some(pos) = lower.rfind(m) {
                let end = window_start + pos + m.len();
                best_pii = Some(best_pii.map_or(end, |b| b.max(end)));
            }
        }
        for m in &non_pii {
            if let Some(pos) = lower.rfind(m) {
                let end = window_start + pos + m.len();
                best_non_pii = Some(best_non_pii.map_or(end, |b| b.max(end)));
            }
        }
        match (best_pii, best_non_pii) {
            (Some(p), Some(n)) => Some(p > n),
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (None, None) => None,
        }
    }

    /// Dates: only with a marker within the window before; future dates rejected; old dates penalized.
    fn detect_date(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let patterns = self.registry.patterns(&spec.id);
        let mut candidates = Vec::new();
        for re in patterns {
            for m in re.find_iter(text) {
                if let Some(e) = self.date_candidate(text, opts, spec, m.start(), m.end()) {
                    candidates.push(e);
                }
            }
        }
        candidates
    }

    /// Builds a date entity for a single regex match, or None when the span is rejected.
    fn date_candidate(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        spec: &TypeSpec,
        m_start: usize,
        m_end: usize,
    ) -> Option<Entity> {
        let (start, end) = self.date_span(text, m_start, m_end, spec)?;
        let span = &text[start..end];
        // Marker must be within the window before the date or within 20 chars after it
        // (e.g. "10.02.1982 года рождения", "06.06.1988 г.р.").
        let before = context_window_before(text, start, spec.context_window).to_lowercase();
        let after = context_window_after(text, end, 20).to_lowercase();
        let has_marker = spec.context_words.iter().any(|w| before.contains(w) || after.contains(w));
        if !has_marker {
            return None;
        }
        if date_in_future(span) {
            return None;
        }
        let mut conf = 0.6f32;
        if age_exceeds(span, self.historical_date_years) {
            conf -= 0.3;
        }
        if !passes_threshold(conf, opts) {
            return None;
        }
        Some(Entity { type_id: spec.id.clone(), start, end, confidence: conf })
    }

    /// Extends a date span with a trailing suffix (e.g. " г.", " года"). Returns None when the
    /// span (extended or not) is not a valid date.
    fn date_span(&self, text: &str, start: usize, m_end: usize, spec: &TypeSpec) -> Option<(usize, usize)> {
        let mut end = m_end;
        // Extend the span to include a trailing suffix (e.g. " г.", " года") right after the year.
        let after = &text[end..];
        for suffix in &spec.date_suffixes {
            if let Some(rest) = after.strip_prefix(suffix.as_str()) {
                if rest.chars().next().map(|c| !c.is_alphabetic()).unwrap_or(true) {
                    end += suffix.len();
                    break;
                }
            }
        }
        let span = &text[start..end];
        if !validators::date(span) {
            // The suffix extension may have produced an invalid date (e.g. "10.02.1982 года").
            // Fall back to the unextended span when it is a valid date.
            let unextended = &text[start..m_end];
            if validators::date(unextended) {
                end = m_end;
            } else {
                return None;
            }
        }
        Some((start, end))
    }

    /// Birth place: text after a marker up to end of sentence / comma / period.
    fn detect_birth_place(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        let lower = text.to_lowercase();
        for marker in &spec.context_words {
            let mut search_from = 0;
            while let Some(pos) = lower[search_from..].find(marker) {
                let marker_end = search_from + pos + marker.len();
                if let Some((start, end)) = extract_place_after(text, marker_end, &self.registry.context().abbreviation_words) {
                    let span = &text[start..end];
                    // Only accept a place that looks like a toponym (city marker or city name),
                    // or when the marker itself strongly implies a place follows.
                    let strong_marker = spec.strong_markers.iter().any(|m| m == marker);
                    if !strong_marker && !self.looks_like_place(span) {
                        search_from = marker_end;
                        continue;
                    }
                    let conf = 0.7f32;
                    if passes_threshold(conf, opts) {
                        candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
                    }
                }
                search_from = marker_end;
            }
        }
        candidates
    }

    /// True if a span looks like a place (city marker, city name, or region marker).
    fn looks_like_place(&self, span: &str) -> bool {
        // A valid date is not a place (e.g. "05 мая 1985 г.").
        if validators::date(span) {
            return false;
        }
        let markers = &self.registry.context().place_markers;
        if markers.iter().any(|m| span.contains(m.as_str())) {
            return true;
        }
        cyrillic_words(span).iter().any(|(_, _, lower, _)| self.is_city(lower))
    }

    /// Citizenship: a country word after a marker.
    fn detect_citizenship(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        let lower = text.to_lowercase();
        for marker in &spec.context_words {
            let mut search_from = 0;
            while let Some(pos) = lower[search_from..].find(marker) {
                let marker_end = search_from + pos + marker.len();
                if let Some((start, end)) = find_country_after(text, marker_end, &self.dicts, &self.registry.context().country_suffixes) {
                    let conf = 0.7f32;
                    if conf >= opts.min_confidence {
                        candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
                    }
                }
                search_from = marker_end;
            }
        }
        candidates
    }

    /// Passport issuer: text after a marker up to a date / subdivision code / period.
    /// Markers: "выдан", "выдано", "кем выдан", "орган выдачи" (optionally "кем выдан (N):").
    /// The phrase must start with an issuer prefix from the registry.
    fn detect_passport_issuer(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        let prefixes = &self.registry.context().issuer_prefixes;
        for m in ISSUER_MARKER_RE.find_iter(text) {
            let marker_end = m.end();
            let abbrev = &self.registry.context().abbreviation_words;
            if let Some((start, end)) = extract_issuer_after(text, marker_end, prefixes, abbrev) {
                let conf = 0.7f32;
                if conf >= opts.min_confidence {
                    candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
                }
            }
        }
        candidates
    }

    /// Street + house number without "д." (e.g. "ул. Гагарина 28", "пр. Победы 45 кв 89",
    /// "проспекте Сахарова 22"). A street marker plus a name (1-3 words, may start with a
    /// digit) and a house number is a confident address (0.8) on its own. A preceding city
    /// is included in the span. Also detects "city, capitalized word, number" (e.g.
    /// "Хабаровск, Маршала Жукова, 188") at 0.7.
    ///
    /// The street marker may be abbreviated ("ул.", "пр.") or a full word in any case
    /// ("улице", "проспекте").
    fn detect_street_address(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        for m in STREET_ADDR_RE.find_iter(text) {
            let start = m.start();
            let end = m.end();
            // A non-pii marker (отделение, офис, банк...) suppresses the address.
            if self.has_non_pii_context(text, start, end, spec) {
                continue;
            }
            let mut conf = 0.8f32;
            // Include a preceding city ("г. Москва, " or "Москва, ") in the span.
            let (span_start, span_end) = self.extend_with_city(text, start, end);
            // An organization near the address is a negative signal.
            let non_pii = self.effective_non_pii_markers(spec);
            if self.allowlist.org_near(text, span_start, span_end, 60, &non_pii) {
                conf -= 0.3;
            }
            conf = conf.clamp(0.0, 1.0);
            if passes_threshold(conf, opts) {
                candidates.push(Entity { type_id: spec.id.clone(), start: span_start, end: span_end, confidence: conf });
            }
        }
        // "city, capitalized word, number" (e.g. "Хабаровск, Маршала Жукова, 188").
        candidates.extend(self.detect_city_word_number(text, opts, spec));
        candidates
    }

    /// Extends a street-address span to include a preceding city ("г. Москва, " or
    /// "Москва, "). Returns the widened span.
    fn extend_with_city(&self, text: &str, start: usize, end: usize) -> (usize, usize) {
        let window = context_window_before(text, start, 60);
        let window_start = start - window.len();
        let trimmed = window.trim_end();
        // "г. Москва, " — city marker + city name + comma.
        if let Some(pos) = trimmed.rfind("г.") {
            let after = &trimmed[pos + "г.".len()..];
            let after = after.trim_start();
            if let Some(comma) = after.find(',') {
                let city = &after[..comma].trim();
                if self.looks_like_city_name(city) {
                    return (window_start + pos, end);
                }
            }
        }
        // "Москва, " — bare city name + comma. The city is the word before the comma.
        if let Some(comma) = trimmed.rfind(',') {
            let before = &trimmed[..comma];
            let before = before.trim_end();
            let city_start = before
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_whitespace())
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(0);
            let city = &before[city_start..];
            if self.looks_like_city_name(city) {
                return (window_start + city_start, end);
            }
        }
        (start, end)
    }

    /// True if a span is a city name (from the dictionary) or a city marker + name.
    fn looks_like_city_name(&self, span: &str) -> bool {
        let lower = span.to_lowercase();
        if self.dicts.contains("cities", &lower) {
            return true;
        }
        // "г. Москва" style: strip a leading "г." / "город".
        let stripped = lower
            .strip_prefix("г.")
            .or_else(|| lower.strip_prefix("город"))
            .map(|s| s.trim())
            .unwrap_or(&lower);
        self.dicts.contains("cities", stripped)
    }

    /// "city, capitalized word(s), number" (e.g. "Хабаровск, Маршала Жукова, 188",
    /// "Вольск, Рокоссовского, 131") -> address 0.7.
    fn detect_city_word_number(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        for (start, end, lower, is_cap) in cyrillic_words(text) {
            if !is_cap || !self.dicts.contains("cities", &lower) {
                continue;
            }
            if let Some((span_start, span_end)) = self.city_word_number_span(text, start, end) {
                // A non-pii marker (юридический адрес, пункт выдачи, отделение, офис, банк...)
                // suppresses the address.
                if self.has_global_non_pii_near(text, span_start, span_end) {
                    continue;
                }
                if passes_threshold(0.7, opts) {
                    candidates.push(Entity { type_id: spec.id.clone(), start: span_start, end: span_end, confidence: 0.7 });
                }
            }
        }
        candidates
    }

    /// Extracts the "city, street name, number" span after a city word. Returns None when the
    /// structure does not match.
    fn city_word_number_span(&self, text: &str, start: usize, end: usize) -> Option<(usize, usize)> {
        // After the city: ", capitalized word(s), number".
        let after = &text[end..];
        let after = after.trim_start();
        let after = after.strip_prefix(',').map(|s| s.trim_start()).unwrap_or(after);
        let words = cyrillic_words(after);
        if words.is_empty() {
            return None;
        }
        // Take 1-2 capitalized words as the street name.
        let (_, we, wlower, wcap) = &words[0];
        if !*wcap {
            return None;
        }
        // A street name that is a context word of another PII type (e.g. "Паспорт 4509")
        // is not a street.
        if self.non_address_context_words.contains(wlower) {
            return None;
        }
        let mut street_end = *we;
        if let Some((_, we2, _, wcap2)) = words.get(1) {
            if *wcap2 {
                street_end = *we2;
            }
        }
        // Convert the street-name end to an absolute byte offset in `text`. `after` is a
        // sub-slice of `text` (after trimming and comma stripping), so its absolute
        // offset is `after.as_ptr() - text.as_ptr()`.
        let street_end_abs = (after.as_ptr() as usize - text.as_ptr() as usize) + street_end;
        // After the street name: a comma and a number.
        let between = &text[street_end_abs..];
        let between = between.trim_start();
        let between = between.strip_prefix(',').map(|s| s.trim_start()).unwrap_or(between);
        let num = HOUSE_NUMBER_RE.find(between)?;
        if num.start() != 0 {
            return None;
        }
        let num_end = num.end();
        // The number must be followed by a boundary (space, period, end).
        let after_num = &between[num_end..];
        if !after_num.is_empty()
            && !after_num.starts_with(char::is_whitespace)
            && !after_num.starts_with('.')
        {
            return None;
        }
        // Compute the absolute byte offset of the number's end. `between` is a sub-slice of
        // `text` (after trimming and comma stripping), so its absolute offset is
        // `between.as_ptr() - text.as_ptr()`.
        let span_end = (between.as_ptr() as usize - text.as_ptr() as usize) + num_end;
        Some((start, span_end))
    }

    /// Address: group of 2+ consecutive components (index, city, street, house, apartment, region).
    fn detect_address(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = self.detect_street_address(text, opts, spec);
        let comps = self.find_address_components(text);
        if comps.is_empty() {
            return candidates;
        }
        let mut i = 0;
        while i < comps.len() {
            let mut j = i + 1;
            while j < comps.len() && self.components_adjacent(text, comps[j - 1].1, comps[j].0) {
                j += 1;
            }
            let group = &comps[i..j];
            if group.len() >= 2 {
                if let Some(e) = self.address_group_candidate(text, opts, spec, group) {
                    candidates.push(e);
                }
            }
            i = j;
        }
        candidates
    }

    /// Builds an address entity for a group of adjacent components, or None when rejected.
    fn address_group_candidate(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        spec: &TypeSpec,
        group: &[(usize, usize)],
    ) -> Option<Entity> {
        let start = group[0].0;
        let end = group[group.len() - 1].1;
        // A span that starts with a document marker (e.g. "Накладная 9876 543210") is a
        // document number, not an address. Only the start counts: "ул. Заказная, д. 5"
        // is an address even though it contains the word "заказ".
        if self.has_document_marker_at_start(text, start) {
            return None;
        }
        // A full address by structure (city + street + house, or street + house +
        // apartment) is confident on its own (0.7) without a marker. Only a non-pii
        // marker (отделение, офис...) lowers it.
        let is_full = self.is_full_address(text, group);
        let mut conf: f32 = if is_full { 0.7 } else { 0.5 };
        // The nearest marker to the left decides whether this is a personal address
        // (pii marker) or an organization address (non-pii marker). No marker -> the
        // address keeps its structural confidence (full 0.7, other 0.5).
        match self.nearest_address_marker(text, start, spec) {
            Some(true) => conf += 0.3,
            Some(false) => conf -= if is_full { 0.5 } else { 0.3 },
            None => {}
        }
        // An organization near the address is a negative signal.
        let non_pii = self.effective_non_pii_markers(spec);
        if self.allowlist.org_near(text, start, end, 60, &non_pii) {
            conf -= 0.3;
        }
        conf = conf.clamp(0.0, 1.0);
        if !passes_threshold(conf, opts) {
            return None;
        }
        Some(Entity { type_id: spec.id.clone(), start, end, confidence: conf })
    }

    /// True if an address group is a full address by structure: city + street + house, or
    /// street + house + apartment.
    fn is_full_address(&self, text: &str, group: &[(usize, usize)]) -> bool {
        let kinds: Vec<AddrKind> = group
            .iter()
            .map(|&(s, e)| self.classify_address_component(text, s, e))
            .collect();
        let has_city = kinds.contains(&AddrKind::City);
        let has_street = kinds.contains(&AddrKind::Street);
        let has_house = kinds.contains(&AddrKind::House);
        let has_apartment = kinds.contains(&AddrKind::Apartment);
        (has_city && has_street && has_house) || (has_street && has_house && has_apartment)
    }

    /// Classifies a single address component span by its leading marker / shape.
    fn classify_address_component(&self, text: &str, start: usize, end: usize) -> AddrKind {
        let span = &text[start..end];
        let lower = span.to_lowercase();
        let ctx = self.registry.context();
        if lower.starts_with("г.") || lower.starts_with("город") {
            return AddrKind::City;
        }
        if lower.starts_with("кв.") || lower.starts_with("квартира")
            || lower.starts_with("оф.") || lower.starts_with("пом.")
        {
            return AddrKind::Apartment;
        }
        if lower.starts_with("д.") || lower.starts_with("дом")
            || lower.starts_with("к.") || lower.starts_with("корп.") || lower.starts_with("стр.")
        {
            return AddrKind::House;
        }
        if starts_with_street_marker(&lower, &ctx.street_markers)
            || ctx.street_markers.iter().any(|m| lower.ends_with(m.as_str()))
        {
            return AddrKind::Street;
        }
        if lower.starts_with("обл.") || lower.starts_with("область")
            || lower.starts_with("край") || lower.starts_with("респ.")
        {
            return AddrKind::Region;
        }
        if span.chars().all(|c| c.is_ascii_digit()) && span.chars().count() == 6 {
            return AddrKind::Index;
        }
        if self.dicts.contains("cities", &lower) {
            return AddrKind::City;
        }
        if span.chars().all(|c| c.is_ascii_digit()) {
            return AddrKind::House;
        }
        AddrKind::Other
    }

    fn find_address_components(&self, text: &str) -> Vec<(usize, usize)> {
        let mut comps: Vec<(usize, usize)> = Vec::new();
        for re in ADDRESS_COMPONENT_RES.iter() {
            for m in re.find_iter(text) {
                comps.push((m.start(), m.end()));
            }
        }
        // "word number" components (e.g. "Тверская 15"). A street only when the leading word
        // is not a context word of another PII type (rule 1) and not a sentence-start word
        // without a preceding city or street marker in the same group (rule 2).
        let word_number = self.word_number_components(text);
        comps.extend(word_number.iter().copied());
        // Bare city names from the dictionary.
        for (start, end, lower, is_cap) in cyrillic_words(text) {
            if is_cap && self.dicts.contains("cities", &lower) {
                comps.push((start, end));
            }
        }
        // Hyphenated city names (e.g. "Санкт-Петербург", "Ростов-на-Дону").
        for m in HYPHENATED_WORD_RE.find_iter(text) {
            let span = &text[m.start()..m.end()];
            if self.dicts.contains("cities", &span.to_lowercase()) {
                comps.push((m.start(), m.end()));
            }
        }
        // Bare numbers are house components only when they follow a street component.
        comps.sort_by_key(|c| c.0);
        for m in BARE_NUMBER_RE.find_iter(text) {
            if self.number_follows_street(text, m.start(), &comps) {
                comps.push((m.start(), m.end()));
            }
        }
        comps.sort_by_key(|c| c.0);
        // Rule 2: drop a sentence-start "word number" component whose group has no city or
        // street marker before it.
        let rejected: Vec<(usize, usize)> = word_number
            .iter()
            .copied()
            .filter(|&(s, _)| self.sentence_start_word_number_rejected(text, s, &comps))
            .collect();
        comps.retain(|c| !rejected.contains(c));
        dedup_components(comps)
    }

    /// "word number" components (e.g. "Тверская 15") whose leading word is not a context word
    /// of another PII type (rule 1).
    fn word_number_components(&self, text: &str) -> Vec<(usize, usize)> {
        let mut out: Vec<(usize, usize)> = Vec::new();
        for m in WORD_NUMBER_RE.find_iter(text) {
            let span = &text[m.start()..m.end()];
            let word_len = span.find(char::is_whitespace).unwrap_or(span.len());
            let word = &span[..word_len];
            if self.non_address_context_words.contains(&word.to_lowercase()) {
                continue;
            }
            out.push((m.start(), m.end()));
        }
        out
    }

    /// True if a "word number" component at `start` is a sentence-start word with no city or
    /// street marker before it in the same group (so it is not a street).
    fn sentence_start_word_number_rejected(
        &self,
        text: &str,
        start: usize,
        comps: &[(usize, usize)],
    ) -> bool {
        if !is_sentence_start(text, start) {
            return false;
        }
        let mut cur_start = start;
        loop {
            let prev = comps
                .iter()
                .filter(|c| c.1 <= cur_start)
                .max_by_key(|c| c.1);
            let prev = match prev {
                Some(p) => *p,
                None => return true,
            };
            if !self.components_adjacent(text, prev.1, cur_start) {
                return true;
            }
            match self.classify_address_component(text, prev.0, prev.1) {
                AddrKind::City | AddrKind::Street => return false,
                _ => {}
            }
            cur_start = prev.0;
        }
    }

    /// True if a bare number at `start` is preceded by a street component.
    fn number_follows_street(&self, text: &str, start: usize, comps: &[(usize, usize)]) -> bool {
        // The immediately preceding component must be a street (starts with a street marker).
        let mut prev: Option<(usize, usize)> = None;
        for c in comps {
            if c.1 <= start {
                prev = Some(*c);
            } else {
                break;
            }
        }
        let prev = match prev {
            Some(p) => p,
            None => return false,
        };
        let between = &text[prev.1..start];
        if !between.trim().is_empty() && between.trim() != "," {
            return false;
        }
        let prev_span = &text[prev.0..prev.1];
        let prev_lower = prev_span.to_lowercase();
        // A street component may carry the marker at the start ("ул. Ленина") or at the
        // end ("Невский пр-т").
        starts_with_street_marker(&prev_lower, &self.registry.context().street_markers)
            || self
                .registry
                .context()
                .street_markers
                .iter()
                .any(|m| prev_lower.ends_with(m.as_str()))
    }

    /// Card holder: 2-3 capitalized or all-caps words (Cyrillic or Latin) right after a
    /// card-holder marker ("держатель", "cardholder", "владелец карты", "имя на карте"),
    /// or after a card number. The marker may be followed by an optional ':' or '—'.
    fn detect_card_holder(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        self.card_holder_from_markers(text, opts, spec, &mut candidates);
        self.card_holder_from_card_number(text, opts, spec, &mut candidates);
        candidates
    }

    /// Marker-anchored card holders: a name right after a card-holder marker.
    fn card_holder_from_markers(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        spec: &TypeSpec,
        candidates: &mut Vec<Entity>,
    ) {
        let lower = text.to_lowercase();
        for marker in &spec.context_words {
            let mut search_from = 0;
            while let Some(pos) = lower[search_from..].find(marker) {
                let marker_end = search_from + pos + marker.len();
                if let Some((start, end)) = extract_card_holder_after(text, marker_end) {
                    // A card holder name is embossed in all caps (e.g. "IVAN PETROV") or is a
                    // Cyrillic name (e.g. "Наталья Чернецкий"). A Latin title-case name after
                    // "держатель" (e.g. "Theodore Weaver") is a generic FIO, not a card holder.
                    if is_card_holder_name(&text[start..end]) {
                        push_card_holder(candidates, spec, start, end, opts);
                    }
                }
                search_from = marker_end;
            }
        }
    }

    /// Card-number fallback: a name right after a card number.
    fn card_holder_from_card_number(
        &self,
        text: &str,
        opts: &DetectOptions<'_>,
        spec: &TypeSpec,
        candidates: &mut Vec<Entity>,
    ) {
        for m in CARD_HOLDER_NAME_RE.find_iter(text) {
            let start = m.start();
            let end = m.end();
            if self.card_number_before_within(text, start, 60) && is_card_holder_name(&text[start..end]) {
                push_card_holder(candidates, spec, start, end, opts);
            }
        }
    }

    fn card_number_before_within(&self, text: &str, start: usize, window: usize) -> bool {
        let patterns = self.registry.patterns("card_number");
        let before = context_window_before(text, start, window);
        patterns.iter().any(|re| re.is_match(before))
    }

    /// True if a card-holder marker ("держатель", "cardholder", "владелец карты",
    /// "имя на карте") is near the span. Such a name is a card holder, not a generic FIO.
    fn has_card_holder_marker(&self, text: &str, start: usize, end: usize) -> bool {
        let markers = self
            .registry
            .get("card_holder")
            .map(|s| s.context_words.clone())
            .unwrap_or_default();
        has_context_word_around(text, start, end, 40, &markers)
    }

    /// True if a card marker ("карта", "card", "номер карты", "№ карты") is near the span.
    /// A marker negated by "не является" (e.g. "не является картой") is not a card marker.
    fn has_card_marker(&self, text: &str, start: usize, end: usize) -> bool {
        let markers = &self.registry.context().card_markers;
        let before = context_window_before(text, start, 40).to_lowercase();
        let after = context_window_after(text, end, 40).to_lowercase();
        markers.iter().any(|m| {
            marker_present_not_negated(&before, m) || marker_present_not_negated(&after, m)
        })
    }

    /// True if a birth marker ("родился", "родилась", "дата рождения", "д.р", "г.р") is near.
    fn has_birth_marker(&self, text: &str, start: usize, end: usize) -> bool {
        let markers = &self.registry.context().birth_markers;
        let before = context_window_before(text, start, 40).to_lowercase();
        let after = context_window_after(text, end, 40).to_lowercase();
        markers.iter().any(|m| before.contains(m.as_str()) || after.contains(m.as_str()))
    }

    /// True if a document marker (накладная, партия, счёт-фактура, артикул, инвентарный
    /// номер, тикет, заказ) appears as a standalone word within a window before `start`.
    /// A number right after such a marker is a document number, not a passport.
    fn has_document_marker_before(&self, text: &str, start: usize) -> bool {
        let before = context_window_before(text, start, 60).to_lowercase();
        DOCUMENT_MARKERS.iter().any(|m| contains_word_boundary(&before, m))
    }

    /// True if the span starting at `start` begins with a document marker (накладная,
    /// партия, счёт-фактура, артикул, инвентарный номер, тикет, заказ). A span that
    /// starts with such a marker is a document number, not an address.
    fn has_document_marker_at_start(&self, text: &str, start: usize) -> bool {
        let lower = context_window_after(text, start, 40).to_lowercase();
        DOCUMENT_MARKERS.iter().any(|m| {
            if let Some(rest) = lower.strip_prefix(m) {
                rest.chars().next().map(|c| !c.is_alphanumeric()).unwrap_or(true)
            } else {
                false
            }
        })
    }

    /// True if a brand marker (магазин, компания, ООО, кафе, сеть, поезд, бренд) appears
    /// as a standalone word within a window before `start`.
    fn has_brand_marker_before(&self, text: &str, start: usize) -> bool {
        let before = context_window_before(text, start, 40).to_lowercase();
        BRAND_MARKERS.iter().any(|m| contains_word_boundary(&before, m))
    }

    /// True if a service marker (горячая линия, служба поддержки, колл-центр) appears as a
    /// standalone word within a window around the span.
    fn has_service_marker_near(&self, text: &str, start: usize, end: usize) -> bool {
        let before = context_window_before(text, start, 40).to_lowercase();
        let after = context_window_after(text, end, 40).to_lowercase();
        SERVICE_MARKERS
            .iter()
            .any(|m| contains_word_boundary(&before, m) || contains_word_boundary(&after, m))
    }

    /// True if a strong PII marker (client, passport, phone, etc.) is near the span. Birth
    /// markers ("родился") are excluded: they also appear in biographical references.
    fn strong_pii_marker(&self, text: &str, start: usize, end: usize) -> bool {
        let ctx = self.registry.context();
        let before = context_window_before(text, start, 60).to_lowercase();
        let after = context_window_after(text, end, 60).to_lowercase();
        ctx.pii_markers.iter().any(|m| {
            if matches!(m.as_str(), "родился" | "родилась") {
                return false;
            }
            before.contains(m.as_str()) || after.contains(m.as_str())
        })
    }

    /// True if a strong biographical marker (поэт, писатель, композитор, "в биографии",
    /// памятник, музей, император) appears within a few words directly before `start`.
    fn strong_biography_marker_before(&self, text: &str, start: usize) -> bool {
        const MARKERS: &[&str] = &[
            "поэт",
            "писатель",
            "композитор",
            "биографи",
            "памятник",
            "музей",
            "император",
        ];
        let window = context_window_before(text, start, 100);
        let trimmed = window.trim_end();
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        let tail: Vec<&str> = words.iter().rev().take(4).rev().copied().collect();
        let tail_lower = tail.join(" ").to_lowercase();
        MARKERS.iter().any(|m| tail_lower.contains(m))
    }

    /// True if the word is a context marker of any type (pii, non-pii, or a type's
    /// context_words). Marker words never belong to a FIO span.
    fn is_marker_word(&self, lower: &str) -> bool {
        let ctx = self.registry.context();
        if ctx.pii_markers.iter().any(|m| m == lower) {
            return true;
        }
        if ctx.non_pii_markers.iter().any(|m| m == lower) {
            return true;
        }
        self.registry.types().iter().any(|s| {
            s.context_words.iter().any(|w| w == lower)
                || s.pii_context.iter().any(|w| w == lower)
                || s.non_pii_context.iter().any(|w| w == lower)
                || s.pii_markers.iter().any(|w| w == lower)
                || s.non_pii_markers.iter().any(|w| w == lower)
        })
    }

    /// True if the token at `start` is preceded by a street marker ("ул.", "улица").
    fn preceded_by_street_marker(&self, text: &str, start: usize) -> bool {
        let prefix = &text[..start];
        let trimmed = prefix.trim_end();
        if trimmed.is_empty() {
            return false;
        }
        let last_word_start = trimmed
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        let last_word = &trimmed[last_word_start..];
        let last_word = last_word.trim_end_matches('.');
        let markers = &self.registry.context().street_markers;
        markers.iter().any(|m| last_word.to_lowercase() == *m)
    }

    /// True if the token at `start` is preceded by a city marker ("г.", "город").
    fn preceded_by_city_marker(&self, text: &str, start: usize) -> bool {
        let prefix = &text[..start];
        let trimmed = prefix.trim_end();
        if trimmed.is_empty() {
            return false;
        }
        let last_word_start = trimmed
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        let last_word = &trimmed[last_word_start..];
        let last_word = last_word.trim_end_matches('.');
        let markers = &self.registry.context().city_markers;
        markers.iter().any(|m| last_word.to_lowercase() == *m)
    }

    /// True if two address components are separated only by separators (comma, space, "г." etc.).
    fn components_adjacent(&self, text: &str, prev_end: usize, next_start: usize) -> bool {
        if prev_end > next_start {
            return false;
        }
        let between = &text[prev_end..next_start];
        let between = between.trim();
        if between.is_empty() {
            return true;
        }
        let seps = &self.registry.context().address_separators;
        seps.iter().any(|s| between == s.as_str())
    }
}

/// A capitalized word (Cyrillic or Latin) or an initial (single uppercase letter, optional period).
struct NameToken {
    start: usize,
    end: usize,
    lower: String,
    capitalized: bool,
    is_initial: bool,
    is_latin: bool,
}

/// True if the word is a military/academic rank in genitive case (e.g. "маршала", "генерала").
fn is_rank_word(lower: &str) -> bool {
    matches!(
        lower,
        "маршала" | "генерала" | "адмирала" | "академика"
    )
}

/// Document-type markers that disambiguate a passport series label ("серия") between a
/// passport and a driver license. Series labels themselves are not document-type markers.
const PASSPORT_DOC_MARKERS: &[&str] = &[
    "паспорт", "паспорта", "паспорте", "паспорту", "паспортом", "паспортные",
];
const DRIVER_LICENSE_DOC_MARKERS: &[&str] = &[
    "права", "прав", "водительское", "водительского", "водительские", "водительских",
    "удостоверение", "удостоверения", "удостоверению", "удостоверением", "ву", "в/у",
];

/// Document/order markers: a numeric sequence right after one of these is a document
/// number, not a passport or an address.
const DOCUMENT_MARKERS: &[&str] = &[
    "накладная", "партия", "счёт-фактура", "артикул", "инвентарный номер", "тикет", "заказ",
];

/// Brand markers: a name in guillemets right after one of these is a brand name, not a FIO.
const BRAND_MARKERS: &[&str] = &[
    "магазин", "компания", "ооо", "кафе", "сеть", "поезд", "бренд",
];

/// Service markers: a toll-free 8-800 number near one of these is a service line, not a
/// personal phone.
const SERVICE_MARKERS: &[&str] = &["горячая линия", "служба поддержки", "колл-центр"];

/// True if the word is a passport series label ("серия" in any case).
fn is_series_label(word: &str) -> bool {
    matches!(word, "серия" | "серии" | "серию" | "серий")
}

/// True if a phrase (lowercased) contains a passport series label as a standalone word.
fn is_series_label_phrase(lower: &str) -> bool {
    ["серия", "серии", "серию", "серий"]
        .iter()
        .any(|w| contains_word_boundary(lower, w))
}

/// Short street-marker abbreviations that are ambiguous prefixes of common words
/// (e.g. "пр" matches "Права", "Приморский"; "ул" matches "Ульяновск"). Such a marker
/// counts as a street only when followed by '.' or '-' (e.g. "ул.", "пр-т"), not when it
/// is a bare prefix of a longer word.
fn is_short_street_abbrev(marker: &str) -> bool {
    matches!(marker, "ул" | "пр" | "пер" | "наб" | "ш" | "пл")
}

/// True if `lower` starts with a street marker. Abbreviated markers (ул, пр, пер, наб,
/// ш, пл) must be followed by '.' or '-' to avoid matching words like "Права" (пр) or
/// "Ульяновск" (ул). Full words (улица, проспект, ...) and complete forms ("пр-т",
/// "б-р") match as-is.
fn starts_with_street_marker(lower: &str, markers: &[String]) -> bool {
    markers.iter().any(|m| {
        if !lower.starts_with(m.as_str()) {
            return false;
        }
        if is_short_street_abbrev(m) {
            let rest = &lower[m.len()..];
            rest.starts_with('.') || rest.starts_with('-')
        } else {
            true
        }
    })
}

/// Drops components fully contained in a previous one (keeps the longer).
fn dedup_components(comps: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut deduped: Vec<(usize, usize)> = Vec::with_capacity(comps.len());
    for c in comps {
        if let Some(last) = deduped.last_mut() {
            if c.0 < last.1 {
                if c.1 > last.1 {
                    last.1 = c.1;
                }
                continue;
            }
        }
        deduped.push(c);
    }
    deduped
}

fn name_tokens(text: &str) -> Vec<NameToken> {
    let mut out = Vec::new();
    for m in NAME_TOKEN_RE.find_iter(text) {
        let w = &text[m.start()..m.end()];
        let letters: String = w.chars().filter(|c| c.is_alphabetic()).collect();
        let is_initial = letters.chars().count() == 1;
        let capitalized = w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
        let is_latin = letters.chars().all(|c| c.is_ascii_alphabetic());
        out.push(NameToken {
            start: m.start(),
            end: m.end(),
            lower: letters.to_lowercase(),
            capitalized,
            is_initial,
            is_latin,
        });
    }
    out
}

/// True if two name tokens are separated only by spaces, or by a period that follows a
/// single-letter initial (e.g. "И. И. Иванов"). A period after a full word is a sentence
/// boundary and breaks the span.
fn tokens_adjacent(text: &str, a: &NameToken, b: &NameToken) -> bool {
    let between = &text[a.end..b.start];
    if between.chars().all(|c| c.is_whitespace()) {
        return true;
    }
    // A period is allowed only when the preceding token is a single-letter initial.
    if a.is_initial {
        let trimmed = between.trim_start_matches(|c: char| c.is_whitespace());
        if let Some(rest) = trimmed.strip_prefix('.') {
            if rest.chars().all(|c| c.is_whitespace()) {
                return true;
            }
        }
    }
    false
}

fn is_sentence_start(text: &str, start: usize) -> bool {
    let prefix = &text[..start];
    let trimmed = prefix.trim_end();
    if trimmed.is_empty() {
        return true;
    }
    trimmed.ends_with(['.', '!', '?', ';', '\n'])
}

fn has_context_word_around(text: &str, start: usize, end: usize, window: usize, words: &[String]) -> bool {
    let before = context_window_before(text, start, window).to_lowercase();
    let after = context_window_after(text, end, window).to_lowercase();
    words.iter().any(|w| before.contains(w) || after.contains(w))
}

/// Like `has_context_word_around` but a single-word marker must appear as a standalone word
/// (word boundaries), so "например" does not match the marker "пример". Multi-word markers
/// (containing a space) still match as substrings.
fn has_context_word_around_wb(text: &str, start: usize, end: usize, window: usize, words: &[String]) -> bool {
    let before = context_window_before(text, start, window).to_lowercase();
    let after = context_window_after(text, end, window).to_lowercase();
    words.iter().any(|w| contains_word_boundary(&before, w) || contains_word_boundary(&after, w))
}

/// True if `needle` appears in `haystack` as a standalone word (not inside a longer word).
/// Multi-word needles (containing a space) match as plain substrings.
fn contains_word_boundary(haystack: &str, needle: &str) -> bool {
    if needle.contains(' ') {
        return haystack.contains(needle);
    }
    let mut search_from = 0;
    while let Some(pos) = haystack[search_from..].find(needle) {
        let abs = search_from + pos;
        let before_ok = abs == 0
            || !haystack[..abs]
                .chars()
                .next_back()
                .map(|c| c.is_alphanumeric())
                .unwrap_or(false);
        let after = abs + needle.len();
        let after_ok = after >= haystack.len()
            || !haystack[after..]
                .chars()
                .next()
                .map(|c| c.is_alphanumeric())
                .unwrap_or(false);
        if before_ok && after_ok {
            return true;
        }
        search_from = abs + needle.len();
    }
    false
}

/// True if the slice `haystack[start..end]` is a standalone word (not adjacent to an
/// alphanumeric character on either side). Multi-word markers (containing a space) are
/// checked at their outer boundaries.
fn is_standalone_word(haystack: &str, start: usize, end: usize) -> bool {
    let before_ok = start == 0
        || !haystack[..start]
            .chars()
            .next_back()
            .map(|c| c.is_alphanumeric())
            .unwrap_or(false);
    let after_ok = end >= haystack.len()
        || !haystack[end..]
            .chars()
            .next()
            .map(|c| c.is_alphanumeric())
            .unwrap_or(false);
    before_ok && after_ok
}

/// True if the byte range [start, end) lies inside guillemets «...» (an opening « before
/// start with no closing » between it and start, and a closing » after end with no opening
/// « between end and it).
fn in_guillemets(text: &str, start: usize, end: usize) -> bool {
    let before = context_window_before(text, start, 80);
    let after = context_window_after(text, end, 80);
    let open = before.rfind('«');
    let close = after.find('»');
    match (open, close) {
        (Some(o), Some(c)) => {
            let last_close = before.rfind('»');
            let next_open = after.find('«');
            (last_close.is_none_or(|lc| lc < o)) && (next_open.is_none_or(|no| no > c))
        }
        _ => false,
    }
}

/// Threshold check honoring the trap policy: prefer_mask uses >=, prefer_skip uses >.
/// A small epsilon absorbs f32 rounding so that 0.6 - 0.3 == 0.3 compares as exactly 0.3.
fn passes_threshold(conf: f32, opts: &DetectOptions<'_>) -> bool {
    const EPS: f32 = 1e-6;
    match opts.trap_policy {
        TrapPolicy::PreferMask => conf + EPS >= opts.min_confidence,
        TrapPolicy::PreferSkip => conf > opts.min_confidence + EPS,
    }
}

/// True if two byte offsets are in the same sentence (no '.' or newline between them).
fn same_sentence(text: &str, a: usize, b: usize) -> bool {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    !text[lo..hi].contains(['.', '\n'])
}

/// Returns the slice of up to `window` chars immediately before byte offset `start`.
fn context_window_before(text: &str, start: usize, window: usize) -> &str {
    let prefix = &text[..start];
    let mut count = 0usize;
    let mut idx = 0usize;
    for (i, _) in prefix.char_indices().rev() {
        count += 1;
        if count >= window {
            idx = i;
            break;
        }
    }
    if count < window {
        prefix
    } else {
        &text[idx..start]
    }
}

/// Returns the slice of up to `window` chars immediately after byte offset `end`.
fn context_window_after(text: &str, end: usize, window: usize) -> &str {
    let rest = &text[end..];
    let mut count = 0usize;
    let mut idx = rest.len();
    for (i, _) in rest.char_indices() {
        count += 1;
        if count >= window {
            idx = i;
            break;
        }
    }
    if count < window {
        rest
    } else {
        &rest[..idx]
    }
}

/// True if `marker` appears in `window` and is not negated by a preceding
/// "не является" (e.g. "не является картой" is not a card marker).
fn marker_present_not_negated(window: &str, marker: &str) -> bool {
    let mut search_from = 0usize;
    while let Some(rel) = window[search_from..].find(marker) {
        let abs = search_from + rel;
        let before = &window[..abs];
        if !before.ends_with("не является ") {
            return true;
        }
        search_from = abs + marker.len();
    }
    false
}

/// True when the trimmed text between a pin/cvv marker and the value is a valid
/// separator: empty, ":", "-", "=", the word "код", or the glued form "-код" / "-код:"
/// (e.g. "CVV-код 317", "CVC-код: 123").
fn is_pin_separator(trimmed: &str) -> bool {
    trimmed.is_empty()
        || trimmed == ":"
        || trimmed == "-"
        || trimmed == "="
        || trimmed == "код"
        || trimmed == "-код"
        || trimmed == "-код:"
        || trimmed == "код:"
}

/// Sorts by start; on overlap keeps the longer span, ties broken by higher confidence.
fn resolve_overlaps(mut candidates: Vec<Entity>) -> Vec<Entity> {
    candidates.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
    });
    let mut result: Vec<Entity> = Vec::with_capacity(candidates.len());
    for c in candidates {
        if let Some(last) = result.last_mut() {
            if c.start < last.end {
                if should_replace_overlap(last, &c) {
                    *last = c;
                }
                continue;
            }
        }
        result.push(c);
    }
    result
}

/// True when the incoming candidate should replace the current last span on overlap.
fn should_replace_overlap(last: &Entity, c: &Entity) -> bool {
    let c_len = c.end - c.start;
    let l_len = last.end - last.start;
    if c_len > l_len {
        return true;
    }
    if c_len < l_len {
        return false;
    }
    // A card holder beats a generic FIO on the same span: the name is anchored
    // to a card-holder marker or a card number, so it is a card holder, not a FIO.
    if (c.type_id == "card_holder" && last.type_id == "fio")
        || (last.type_id == "card_holder" && c.type_id == "fio")
    {
        return c.type_id == "card_holder";
    }
    c.confidence > last.confidence
}

/// Extracts the place after a birth marker, up to end of sentence / comma / period.
fn extract_place_after(text: &str, from: usize, abbrev: &[String]) -> Option<(usize, usize)> {
    let rest = &text[from..];
    // Skip leading whitespace, colons and commas.
    let lead = rest
        .find(|c: char| !c.is_whitespace() && c != ':' && c != ',')
        .unwrap_or(rest.len());
    let rest = &rest[lead..];
    let end_rel = place_end(rest, abbrev);
    let sentence = &rest[..end_rel];
    // Find a standalone "в" and take the text after it.
    let after_v = if let Some(m) = WORD_V_RE.find(sentence) {
        m.end()
    } else {
        0
    };
    let place = &sentence[after_v..];
    let trimmed_start = place
        .find(|c: char| !c.is_whitespace() && c != ':' && c != ',')
        .unwrap_or(place.len());
    let place = &place[trimmed_start..];
    let trimmed_end = place.trim_end().len();
    let place = &place[..trimmed_end];
    if place.is_empty() {
        return None;
    }
    let start = from + lead + after_v + trimmed_start;
    let end = start + place.len();
    Some((start, end))
}

/// End offset of a place phrase: stops at comma, semicolon, newline, colon, or a
/// sentence-ending period. A period that terminates an abbreviation ("г.", "с.", "п.",
/// "пос.", "обл.") is not a delimiter.
fn place_end(rest: &str, abbrev: &[String]) -> usize {
    let mut i = 0;
    while i < rest.len() {
        let c = rest[i..].chars().next().unwrap();
        match c {
            ',' | ';' | '\n' | ':' => return i,
            '.' => {
                if is_abbreviation_period(rest, i, abbrev) {
                    i += c.len_utf8();
                } else {
                    // Sentence-ending period: delimiter if followed by space + uppercase
                    // or by the end of the text.
                    let after = rest[i + c.len_utf8()..].trim_start();
                    if after.is_empty() {
                        return i;
                    }
                    if after.chars().next().map(|ch| ch.is_uppercase()).unwrap_or(false) {
                        return i;
                    }
                    i += c.len_utf8();
                }
            }
            _ => i += c.len_utf8(),
        }
    }
    rest.len()
}

/// True if the period at `period_idx` terminates an abbreviation like "г.", "с.", "п.".
fn is_abbreviation_period(rest: &str, period_idx: usize, abbrev: &[String]) -> bool {
    let before = &rest[..period_idx];
    let word_start = before
        .char_indices()
        .rev()
        .find(|(_, c)| !c.is_alphabetic())
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    let word = &before[word_start..];
    abbrev.iter().any(|a| word == a.as_str())
}

/// Finds a country word or multi-word country phrase after a marker (longest match wins).
fn find_country_after(text: &str, from: usize, dicts: &Dictionaries, suffixes: &[String]) -> Option<(usize, usize)> {
    let rest = &text[from..];
    let end_rel = rest.find([',', '.', ';', '\n']).unwrap_or(rest.len());
    let sentence = &rest[..end_rel];
    let words = cyrillic_words(sentence);
    let mut best: Option<(usize, usize, usize)> = None;
    for i in 0..words.len() {
        let mut phrase = String::new();
        for j in i..(i + 4).min(words.len()) {
            if j > i {
                phrase.push(' ');
            }
            phrase.push_str(&words[j].2);
            if is_country(&phrase, dicts, suffixes) {
                let start = words[i].0;
                let end = words[j].1;
                let len = end - start;
                if best.is_none_or(|(_, _, bl)| len > bl) {
                    best = Some((start, end, len));
                }
            }
        }
    }
    best.map(|(s, e, _)| (from + s, from + e))
}

fn is_country(lower: &str, dicts: &Dictionaries, suffixes: &[String]) -> bool {
    if dicts.contains("countries", lower) {
        return true;
    }
    // Multi-word phrases are stored verbatim; no suffix stripping for them.
    if lower.contains(' ') {
        return false;
    }
    // Handle common genitive forms by stripping a trailing suffix.
    for suffix in suffixes {
        if let Some(stripped) = lower.strip_suffix(suffix.as_str()) {
            if dicts.contains("countries", stripped) {
                return true;
            }
        }
    }
    false
}

/// Extracts the passport issuer phrase after a marker.
fn extract_issuer_after(text: &str, from: usize, prefixes: &[String], abbrev: &[String]) -> Option<(usize, usize)> {
    let rest = &text[from..];
    let stop = issuer_phrase_end(rest, abbrev);
    let phrase = &rest[..stop];
    // Skip leading whitespace, colons, commas, dashes and a parenthesized number
    // (e.g. "кем выдан (12): ОВД ...").
    let trimmed_start = phrase
        .find(|c: char| !c.is_whitespace() && !matches!(c, ':' | ',' | '—' | '-'))
        .unwrap_or(phrase.len());
    let phrase = &phrase[trimmed_start..];
    let trimmed_end = phrase
        .trim_end_matches(|c: char| c.is_whitespace() || c == ',' || c == '.')
        .len();
    let phrase = &phrase[..trimmed_end];
    if phrase.is_empty() {
        return None;
    }
    let lower = phrase.to_lowercase();
    if !prefixes.iter().any(|p| lower.starts_with(p.as_str())) {
        return None;
    }
    let start = from + trimmed_start;
    let end = start + phrase.len();
    Some((start, end))
}

/// Extracts a card holder name (2-3 capitalized or all-caps words, Cyrillic or Latin) right
/// after a card-holder marker, skipping an optional ':' or '—'. Returns None when no such
/// name follows.
fn extract_card_holder_after(text: &str, from: usize) -> Option<(usize, usize)> {
    let rest = &text[from..];
    // Skip leading whitespace, colons, commas and dashes.
    let lead = rest
        .find(|c: char| !c.is_whitespace() && !matches!(c, ':' | ',' | '—' | '-'))
        .unwrap_or(rest.len());
    let rest = &rest[lead..];
    let m = CARD_HOLDER_NAME_RE.find(rest)?;
    let start = from + lead + m.start();
    let end = from + lead + m.end();
    Some((start, end))
}

/// True if a name is a card holder name: all-caps (card-embossed, e.g. "IVAN PETROV") or
/// Cyrillic (e.g. "Наталья Чернецкий"). A Latin title-case name (e.g. "Theodore Weaver") is
/// a generic FIO, not a card holder.
fn is_card_holder_name(s: &str) -> bool {
    let mut has_alpha = false;
    let mut has_cyrillic = false;
    let mut has_latin_lower = false;
    for c in s.chars() {
if c.is_alphabetic() {
                has_alpha = true;
                if ('\u{0400}'..='\u{04FF}').contains(&c) {
                    has_cyrillic = true;
                }
            if c.is_ascii_alphabetic() && c.is_lowercase() {
                has_latin_lower = true;
            }
        }
    }
    has_alpha && (has_cyrillic || !has_latin_lower)
}

/// Pushes a card-holder entity when the fixed confidence passes the threshold.
fn push_card_holder(candidates: &mut Vec<Entity>, spec: &TypeSpec, start: usize, end: usize, opts: &DetectOptions<'_>) {
    let conf = 0.8f32;
    if conf >= opts.min_confidence {
        candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
    }
}

/// End offset of an issuer phrase: stops at a comma, semicolon, newline, a sentence-ending
/// period (not an abbreviation period like "г."), a date (numeric or textual), or the
/// "код подразделения" / "к/п" labels.
fn issuer_phrase_end(rest: &str, abbrev: &[String]) -> usize {
    let mut i = 0;
    while i < rest.len() {
        let c = rest[i..].chars().next().unwrap();
        match c {
            ',' | ';' | '\n' => return i,
            '.' => {
                if is_abbreviation_period(rest, i, abbrev) {
                    i += c.len_utf8();
                } else {
                    return i;
                }
            }
            _ => {
                let tail = &rest[i..];
                if ISSUER_DATE_START_RE.is_match(tail)
                    || tail.starts_with("код подразделения")
                    || tail.starts_with("к/п")
                {
                    return i;
                }
                i += c.len_utf8();
            }
        }
    }
    rest.len()
}

fn cyrillic_words(text: &str) -> Vec<(usize, usize, String, bool)> {
    let mut out = Vec::new();
    for m in CYRILLIC_WORD_RE.find_iter(text) {
        let w = &text[m.start()..m.end()];
        let lower = w.to_lowercase();
        let is_cap = w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
        out.push((m.start(), m.end(), lower, is_cap));
    }
    out
}

/// Counts ASCII digits in a span.
fn digit_count(span: &str) -> usize {
    span.chars().filter(|c| c.is_ascii_digit()).count()
}

/// True if a phone span is a toll-free 8-800 / +7 800 number (the 3-digit code right after
/// the leading 7/8 is 800).
fn phone_code_is_800(span: &str) -> bool {
    let digits: Vec<char> = span.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.len() >= 4 && digits[1..4] == ['8', '0', '0']
}

fn validator_passes(v: Validator, span: &str) -> bool {
    match v {
        Validator::None => true,
        Validator::Luhn => validators::luhn(span),
        Validator::Inn => validators::inn(span),
        Validator::Snils => validators::snils(span),
        Validator::Date => validators::date(span),
        Validator::Phone => validators::phone(span),
        Validator::Email => validators::email(span),
    }
}

/// Validators are a fixed set selected by name from the registry.
pub mod validators {
    /// Standard Luhn check. Operates on digits only; non-digits are ignored.
    pub fn luhn(s: &str) -> bool {
        let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
        if digits.len() < 2 {
            return false;
        }
        let mut sum = 0u32;
        let mut double = false;
        for &d in digits.iter().rev() {
            let mut v = d;
            if double {
                v *= 2;
                if v > 9 {
                    v -= 9;
                }
            }
            sum += v;
            double = !double;
        }
        sum.is_multiple_of(10)
    }

    /// Russian INN: 10 or 12 digits with FNS control digits.
    pub fn inn(s: &str) -> bool {
        let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
        match digits.len() {
            10 => {
                let coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8];
                let sum: u32 = coeffs.iter().zip(&digits).map(|(&c, &d)| c * d).sum();
                let control = (sum % 11) % 10;
                control == digits[9]
            }
            12 => {
                let c1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
                let c2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
                let s1: u32 = c1.iter().zip(&digits).map(|(&c, &d)| c * d).sum();
                let s2: u32 = c2.iter().zip(&digits).map(|(&c, &d)| c * d).sum();
                let control1 = (s1 % 11) % 10;
                let control2 = (s2 % 11) % 10;
                control1 == digits[10] && control2 == digits[11]
            }
            _ => false,
        }
    }

    /// Russian SNILS: 11 digits, control sum of first 9 with weights 9..1.
    pub fn snils(s: &str) -> bool {
        let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
        if digits.len() != 11 {
            return false;
        }
        let sum: u32 = digits[..9].iter().zip((1..=9).rev()).map(|(&d, w)| d * w).sum();
        let control = if sum < 100 {
            sum
        } else if sum == 100 || sum == 101 {
            0
        } else {
            let m = sum % 101;
            if m == 100 { 0 } else { m }
        };
        let actual = digits[9] * 10 + digits[10];
        control == actual
    }

    /// Accepts dd.mm.yyyy, dd/mm/yyyy, dd-mm-yyyy, yyyy-mm-dd, mm.dd.yyyy (ambiguous both ways),
    /// and textual Russian dates ("5 мая 1985", "пятого мая 1985").
    pub fn date(s: &str) -> bool {
        let s = s.trim();
        if let Some((d, m, y)) = parse_textual_date(s) {
            return is_valid_calendar(d, m, y);
        }
        if let Some((d, m, y)) = parse_numeric_date(s) {
            return is_valid_calendar(d, m, y);
        }
        false
    }

    /// Extracts the year from a supported date format.
    pub fn extract_year(s: &str) -> Option<i32> {
        if let Some((_, _, y)) = parse_textual_date(s) {
            return Some(y);
        }
        if let Some((_, _, y)) = parse_numeric_date(s) {
            return Some(y);
        }
        None
    }

    fn parse_numeric_date(s: &str) -> Option<(u32, u32, i32)> {
        let sep = if s.contains('.') {
            '.'
        } else if s.contains('/') {
            '/'
        } else if s.contains('-') {
            '-'
        } else {
            return None;
        };
        let parts: Vec<&str> = s.split(sep).collect();
        if parts.len() != 3 {
            return None;
        }
        let a: i32 = parts[0].trim().parse().ok()?;
        let b: i32 = parts[1].trim().parse().ok()?;
        let c: i32 = parts[2].trim().parse().ok()?;
        if a >= 1000 {
            // yyyy-mm-dd
            return Some((c as u32, b as u32, a));
        }
        let year = if c < 100 {
            if c < 70 { 2000 + c } else { 1900 + c }
        } else {
            c
        };
        if a > 12 {
            return Some((a as u32, b as u32, year));
        }
        if b > 12 {
            return Some((b as u32, a as u32, year));
        }
        resolve_ambiguous_date(a, b, year)
    }

    /// Resolves a date where both day and month are <= 12 by trying both orders.
    fn resolve_ambiguous_date(a: i32, b: i32, year: i32) -> Option<(u32, u32, i32)> {
        if is_valid_calendar(a as u32, b as u32, year) {
            Some((a as u32, b as u32, year))
        } else if is_valid_calendar(b as u32, a as u32, year) {
            Some((b as u32, a as u32, year))
        } else {
            None
        }
    }

    fn parse_textual_date(s: &str) -> Option<(u32, u32, i32)> {
        let mut parts: Vec<&str> = s.split_whitespace().collect();
        if let Some(last) = parts.last() {
            if *last == "г." || *last == "года" || *last == "год" {
                parts.pop();
            }
        }
        if parts.len() < 3 {
            return None;
        }
        let day = parse_day(parts[0])?;
        let month = month_number(parts[1])?;
        let year = parse_year(parts[2])?;
        Some((day, month, year))
    }

    fn parse_day(s: &str) -> Option<u32> {
        if let Ok(n) = s.parse::<u32>() {
            return Some(n);
        }
        let s = s.to_lowercase();
        let ordinals: &[(&str, u32)] = &[
            ("первого", 1), ("второго", 2), ("третьего", 3), ("четвертого", 4), ("четвёртого", 4),
            ("пятого", 5), ("шестого", 6), ("седьмого", 7), ("восьмого", 8), ("девятого", 9),
            ("десятого", 10), ("одиннадцатого", 11), ("двенадцатого", 12), ("тринадцатого", 13),
            ("четырнадцатого", 14), ("пятнадцатого", 15), ("шестнадцатого", 16), ("семнадцатого", 17),
            ("восемнадцатого", 18), ("девятнадцатого", 19), ("двадцатого", 20), ("тридцатого", 30),
        ];
        ordinals.iter().find(|(w, _)| *w == s).map(|(_, n)| *n)
    }

    fn month_number(s: &str) -> Option<u32> {
        let s = s.to_lowercase();
        let months: &[(&str, u32)] = &[
            ("январь", 1), ("января", 1), ("февраль", 2), ("февраля", 2), ("март", 3), ("марта", 3),
            ("апрель", 4), ("апреля", 4), ("май", 5), ("мая", 5), ("июнь", 6), ("июня", 6),
            ("июль", 7), ("июля", 7), ("август", 8), ("августа", 8), ("сентябрь", 9), ("сентября", 9),
            ("октябрь", 10), ("октября", 10), ("ноябрь", 11), ("ноября", 11), ("декабрь", 12), ("декабря", 12),
        ];
        months.iter().find(|(w, _)| *w == s).map(|(_, n)| *n)
    }

    fn parse_year(s: &str) -> Option<i32> {
        let n: i32 = s.parse().ok()?;
        if n < 100 {
            Some(if n < 70 { 2000 + n } else { 1900 + n })
        } else {
            Some(n)
        }
    }

    fn is_valid_calendar(day: u32, month: u32, year: i32) -> bool {
        if !(1..=12).contains(&month) || !(1..=9999).contains(&year) {
            return false;
        }
        let days = days_in_month(month, year);
        (1..=days).contains(&day)
    }

    fn days_in_month(month: u32, year: i32) -> u32 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                    29
                } else {
                    28
                }
            }
            _ => 0,
        }
    }

    /// Phone: after removing non-digits, 11 digits starting with 7/8, or 10 digits starting with 9/4/8.
    pub fn phone(s: &str) -> bool {
        let digits: Vec<char> = s.chars().filter(|c| c.is_ascii_digit()).collect();
        match digits.len() {
            11 => matches!(digits[0], '7' | '8'),
            10 => matches!(digits[0], '9' | '4' | '8'),
            _ => false,
        }
    }

    /// Email: local part, '@', domain with at least one dot. Whitespace around '@' and dots
    /// (tokenized emails like "ugray@gmail . com") is ignored.
    pub fn email(s: &str) -> bool {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let s = s.trim();
        if s.is_empty() {
            return false;
        }
        let at = match s.rfind('@') {
            Some(i) => i,
            None => return false,
        };
        let local = &s[..at];
        let domain = &s[at + 1..];
        if local.is_empty() || domain.is_empty() {
            return false;
        }
        if !domain.contains('.') {
            return false;
        }
        if domain.starts_with('.') || domain.ends_with('.') {
            return false;
        }
        true
    }
}

fn extract_year(s: &str) -> Option<i32> {
    validators::extract_year(s)
}

fn current_year() -> i32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (1970 + secs / (365 * 24 * 3600)) as i32
}

fn date_in_future(s: &str) -> bool {
    match extract_year(s) {
        Some(y) => y > current_year(),
        None => false,
    }
}

fn age_exceeds(s: &str, years: u32) -> bool {
    match extract_year(s) {
        Some(y) => (current_year() - y) as u32 > years,
        None => false,
    }
}

/// Latin letters that look like Cyrillic ones, mapped to their Cyrillic equivalents.
/// Used to normalize mixed-script words (e.g. "Иванoв" -> "Иванов").
fn latin_to_cyrillic(c: char) -> Option<char> {
    match c {
        'a' => Some('а'),
        'e' => Some('е'),
        'o' => Some('о'),
        'p' => Some('р'),
        'c' => Some('с'),
        'x' => Some('х'),
        'y' => Some('у'),
        'k' => Some('к'),
        'm' => Some('м'),
        't' => Some('т'),
        'h' => Some('н'),
        'b' => Some('в'),
        'A' => Some('А'),
        'B' => Some('В'),
        'E' => Some('Е'),
        'K' => Some('К'),
        'M' => Some('М'),
        'H' => Some('Н'),
        'O' => Some('О'),
        'P' => Some('Р'),
        'C' => Some('С'),
        'T' => Some('Т'),
        'X' => Some('Х'),
        'Y' => Some('У'),
        _ => None,
    }
}

/// True if the character is Cyrillic.
fn is_cyrillic(c: char) -> bool {
    ('\u{0400}'..='\u{04FF}').contains(&c)
}

/// Normalizes Latin lookalike letters inside words that contain at least one Cyrillic letter.
/// Returns `(normalized_text, offset_map)` where `offset_map[i]` is the original byte offset
/// of the character at normalized byte offset `i` (one entry per char boundary plus the end).
/// Returns `None` when no replacement was made (the common case), so the caller can work on
/// the original text without building an offset table.
fn normalize_mixed(text: &str) -> Option<(String, Vec<usize>)> {
    // Fast pre-pass without allocations: if no word contains both a Cyrillic letter and a
    // Latin lookalike, there is nothing to normalize and the caller works on the original
    // text (the common case must not become slower).
    if !has_mixed_word(text) {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut orig: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let ch = text[i..].chars().next().unwrap();
        if ch.is_alphabetic() {
            let word_end = word_end(text, i);
            let word = &text[i..word_end];
            if word_has_cyrillic(word) {
                push_normalized_word(&mut out, &mut orig, i, word);
            } else {
                push_word(&mut out, &mut orig, i, word);
            }
            i = word_end;
        } else {
            orig.push(i);
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    let map = build_offset_map(&out, &orig, text.len());
    Some((out, map))
}

/// True if any word contains both a Cyrillic letter and a Latin lookalike from
/// `latin_to_cyrillic`. Scans without allocating.
fn has_mixed_word(text: &str) -> bool {
    let mut i = 0;
    while i < text.len() {
        let ch = text[i..].chars().next().unwrap();
        if ch.is_alphabetic() {
            let word_end = word_end(text, i);
            let word = &text[i..word_end];
            if word_has_cyrillic(word) && word.chars().any(|c| latin_to_cyrillic(c).is_some()) {
                return true;
            }
            i = word_end;
        } else {
            i += ch.len_utf8();
        }
    }
    false
}

/// End byte offset of the maximal run of alphabetic chars starting at `start`.
fn word_end(text: &str, start: usize) -> usize {
    let mut j = start;
    while j < text.len() {
        let c = text[j..].chars().next().unwrap();
        if !c.is_alphabetic() {
            break;
        }
        j += c.len_utf8();
    }
    j
}

/// True if the word contains at least one Cyrillic letter.
fn word_has_cyrillic(word: &str) -> bool {
    word.chars().any(is_cyrillic)
}

/// Appends a word to `out`, replacing Latin lookalikes with Cyrillic. Returns true when at
/// least one replacement was made.
fn push_normalized_word(out: &mut String, orig: &mut Vec<usize>, base: usize, word: &str) -> bool {
    let mut changed = false;
    for (rel, c) in word.char_indices() {
        orig.push(base + rel);
        match latin_to_cyrillic(c) {
            Some(r) => {
                out.push(r);
                changed = true;
            }
            None => out.push(c),
        }
    }
    changed
}

/// Appends a word to `out` unchanged, recording the original offsets.
fn push_word(out: &mut String, orig: &mut Vec<usize>, base: usize, word: &str) {
    for (rel, c) in word.char_indices() {
        orig.push(base + rel);
        out.push(c);
    }
}

/// Builds the byte-offset map: `map[byte_offset]` = original byte offset at each char
/// boundary of the normalized text. Non-boundary bytes (inside a multi-byte char) are filled
/// with the current char's original offset; they are never accessed because entity offsets
/// are always on char boundaries.
fn build_offset_map(out: &str, orig: &[usize], orig_len: usize) -> Vec<usize> {
    let mut map: Vec<usize> = Vec::with_capacity(out.len() + 1);
    for (k, (byte_off, _)) in out.char_indices().enumerate() {
        while map.len() < byte_off {
            map.push(orig[k]);
        }
        map.push(orig[k]);
    }
    // Fill any remaining bytes up to out.len() (inside the last multi-byte char) with the
    // last char's original offset.
    let last_orig = orig[orig.len() - 1];
    while map.len() < out.len() {
        map.push(last_orig);
    }
    map.push(orig_len);
    map
}

static NAME_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b[А-ЯЁ][а-яё]+\b|\b[А-ЯЁ]{2,}\b|\b[А-ЯЁ]\.|\b[A-Z][a-z]+\b|\b[A-Z]{2,}\b|\b[A-Z][A-Za-z]+\b|\b[A-Z]\.",
    )
    .unwrap()
});
static CYRILLIC_WORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[А-ЯЁа-яё]+").unwrap());
static WORD_V_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bв\b").unwrap());
/// Matches an issuer marker ("выдан", "выдано", "кем выдан", "орган выдачи") followed by an
/// optional parenthesized number and an optional separator (":", "—", "-").
static ISSUER_MARKER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?iu)\b(?:кем выдан|орган выдачи|выдан|выдано)\b\s*(?:\(\d+\))?\s*[:—\-]?\s*").unwrap()
});
/// Matches the start of a date (numeric or textual) at the current position.
static ISSUER_DATE_START_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b|^\d{1,2}\s+[а-яё]+\s+\d{2,4}\b").unwrap()
});
/// 2-3 capitalized or all-caps words (Cyrillic or Latin), e.g. "Иванов Петров",
/// "ИВАНОВ ПЕТРОВ", "IVAN PETROV".
static CARD_HOLDER_NAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:[А-ЯЁ][а-яё]+|[А-ЯЁ]{2,}|[A-Z][a-z]+|[A-Z]{2,})(?:\s+(?:[А-ЯЁ][а-яё]+|[А-ЯЁ]{2,}|[A-Z][a-z]+|[A-Z]{2,})){1,2}\b",
    )
    .unwrap()
});
static ADDRESS_COMPONENT_RES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\b[1-6]\d{5}\b").unwrap(),
        Regex::new(r"(?:г\.|город)\s+[А-ЯЁ][а-яё]+").unwrap(),
        Regex::new(r"(?:ул\.|улица|пр-т|проспект|пер\.|переулок|наб\.|ш\.|шоссе|б-р|бульвар)\s+[А-ЯЁ][а-яё]+").unwrap(),
        Regex::new(r"[А-ЯЁ][а-яё]+\s+(?:пр-т|проспект|ул\.|улица|пер\.|переулок|наб\.|ш\.|шоссе|б-р|бульвар)").unwrap(),
        Regex::new(r"(?:д\.|дом|к\.|корп\.|стр\.)\s+\d+").unwrap(),
        Regex::new(r"(?:кв\.|квартира|оф\.|пом\.)\s+\d+").unwrap(),
        Regex::new(r"(?:обл\.|область|край|респ\.)\s+[А-ЯЁ][а-яё]+").unwrap(),
    ]
});
/// A bare "capitalized word + number" (e.g. "Тверская 15"). A street only when the word is
/// not a context word of another PII type and not a sentence-start word without a preceding
/// city or street marker in the same group.
static WORD_NUMBER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[А-ЯЁ][а-яё]+\s+\d+").unwrap());
static BARE_NUMBER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d+(?:[А-ЯЁа-яё]|/\d+)?(?:\s*к\.?\s*\d+)?\b").unwrap()
});
static HYPHENATED_WORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[А-ЯЁ][а-яё]+-[А-ЯЁ][а-яё]+").unwrap());

/// Street marker + street name (1-3 words, may start with a digit) + house number
/// (`\d+[а-я]?(/\d+)?`) + optional корпус/к./стр./кв./квартира/подъезд + number.
/// Street markers match in any grammatical case (e.g. "улице", "проспекте").
static STREET_ADDR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?iu)\b(?:ул\.|улиц[а-яё]*|пр\.|пр-т|проспект[а-яё]*|пер\.|переул[а-яё]*|ш\.|шоссе|б-р|бульвар[а-яё]*|наб\.|набережн[а-яё]*|пл\.|площад[а-яё]*|мкр\.|микрорайон[а-яё]*)\s+",
        r"(?:[А-ЯЁа-яё]+|\d+[а-яё-]*[А-ЯЁа-яё]*)",
        r"(?:\s+(?:[А-ЯЁа-яё]+|\d+[а-яё-]*[А-ЯЁа-яё]*)){0,2}?",
        r"\s+\d+[а-яА-ЯёЁ]?(?:/\d+)?",
        r"(?:\s+(?:корпус|корп\.|к\.|стр\.|кв\.|квартира|подъезд)\s*\d+)?",
    ))
    .unwrap()
});

/// A house number with an optional letter or fraction (e.g. "17к3", "28/4").
static HOUSE_NUMBER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d+[а-яА-ЯёЁ]?(?:/\d+)?").unwrap());

/// Passport series as two pairs + 6-digit number (e.g. "48 90 234004").
static PASSPORT_PAIR_PAIR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{2} \d{2} \d{6}$").unwrap());

/// Matches a field label: a word followed by a colon (e.g. "Код заявки:").
static FIELD_LABEL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?iu)\b[а-яёa-z0-9\-]+\s*:").unwrap()
});