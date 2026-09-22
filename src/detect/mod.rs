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
                    words.insert(line.to_lowercase());
                }
                lists.insert(name, words);
            }
        }
        Ok(Self { lists })
    }

    pub fn contains(&self, list: &str, word_lower: &str) -> bool {
        self.lists.get(list).map(|s| s.contains(word_lower)).unwrap_or(false)
    }
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
}

/// Marker types that use the nearest-left-marker rule to resolve context.
fn is_marker_type(id: &str) -> bool {
    matches!(id, "cvv" | "card_pin" | "passport" | "inn" | "subdivision_code" | "driver_license")
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
    let re = RegexBuilder::new(&format!(r"\b(?:{})\b", alt))
        .case_insensitive(true)
        .unicode(true)
        .build()
        .expect("valid marker regex");
    (Some(re), marker_type_of)
}

impl Detector {
    pub fn new(registry: std::sync::Arc<Registry>, dicts: std::sync::Arc<Dictionaries>) -> Self {
        let (marker_re, marker_type_of) = build_marker_map(&registry);
        Self {
            registry,
            dicts,
            historical_date_years: 120,
            allowlist: std::sync::Arc::new(Allowlist::empty()),
            marker_re,
            marker_type_of,
        }
    }

    /// Like `new` but with an allow-list of public persons and organizations.
    pub fn with_allowlist(
        registry: std::sync::Arc<Registry>,
        dicts: std::sync::Arc<Dictionaries>,
        allowlist: Allowlist,
    ) -> Self {
        let (marker_re, marker_type_of) = build_marker_map(&registry);
        Self {
            registry,
            dicts,
            historical_date_years: 120,
            allowlist: std::sync::Arc::new(allowlist),
            marker_re,
            marker_type_of,
        }
    }

    /// Sets the historical-date threshold (years). Defaults to 120.
    pub fn with_historical_date_years(mut self, years: u32) -> Self {
        self.historical_date_years = years;
        self
    }

    /// Runs all enabled types, validates, scores, drops allow-listed and overlapping spans
    /// (longer / more confident wins). Result sorted by start. Case-insensitive.
    pub fn detect(&self, text: &str, opts: &DetectOptions<'_>) -> Vec<Entity> {
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
        resolve_overlaps(candidates)
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
                let start = m.start();
                let end = m.end();
                let span = &text[start..end];

                let mut conf = 0.4f32;
                let mut skip_context_boost = false;

                let has_context = if is_marker_type(&spec.id) {
                    self.has_nearest_marker(text, start, spec)
                } else if spec.context_words.is_empty() {
                    false
                } else {
                    let window = context_window_before(text, start, spec.context_window);
                    let window_lower = window.to_lowercase();
                    spec.context_words.iter().any(|w| window_lower.contains(w))
                };

                if spec.validator != Validator::None {
                    if validator_passes(spec.validator, span) {
                        conf += 0.4;
                    } else if spec.id == "card_number" && self.has_card_marker(text, start, end) {
                        // A 16-digit card in 4x4 format after a card marker is masked even
                        // when Luhn fails (synthetic jury numbers), at confidence 0.6.
                        conf = 0.6;
                        skip_context_boost = true;
                    } else {
                        continue;
                    }
                }

                if has_context && !skip_context_boost {
                    conf += 0.3;
                }
                if spec.context_required && !has_context {
                    continue;
                }
                // A non-PII marker (e.g. "пример", "тест") suppresses the candidate outright, since it
                // marks the value as not real data.
                let has_non_pii = self.has_non_pii_context(text, start, end, spec);
                if has_non_pii {
                    continue;
                }
                conf = conf.min(1.0);

                if !passes_threshold(conf, opts) {
                    continue;
                }

                let span_lower = span.to_lowercase();
                let allow_listed = opts
                    .allow_substrings
                    .iter()
                    .any(|a| a.to_lowercase().contains(&span_lower));
                if allow_listed {
                    continue;
                }

                candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
            }
        }
    }

    /// FIO: 2-3 capitalized words / initials, at least one dictionary or suffix hit.
    fn detect_fio(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        let all_tokens = name_tokens(text);
        let tokens: Vec<NameToken> = all_tokens
            .iter()
            .enumerate()
            .filter(|(i, t)| {
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
            })
            .collect();
        let n = tokens.len();
        for i in 0..n {
            for len in 1..=3usize {
                if i + len > n {
                    break;
                }
                let window = &tokens[i..i + len];
                // All tokens must be capitalized words or initials.
                if window.iter().any(|t| !t.capitalized) {
                    continue;
                }
                // Consecutive tokens must be adjacent (only spaces / periods between).
                if window.windows(2).any(|w| !tokens_adjacent(text, &w[0], &w[1])) {
                    continue;
                }
                // Skip tokens that are part of an address (after street markers).
                if window.iter().any(|t| self.preceded_by_street_marker(text, t.start)) {
                    continue;
                }
                let (qualifies, comps) = self.fio_qualifies(window);
                if !qualifies {
                    continue;
                }
                // Single word requires PII context.
                if comps == 1 && !self.has_pii_context(text, window[0].start, window[0].end, spec) {
                    continue;
                }
                // First word of sentence, single candidate, not in any dict -> skip.
                if comps == 1 && is_sentence_start(text, window[0].start) && !self.in_any_name_dict(&window[0].lower) {
                    continue;
                }
                let start = window[0].start;
                let end = window[window.len() - 1].end;
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
                // Non-PII marker without PII marker suppresses the candidate.
                if has_non_pii && !has_pii {
                    continue;
                }
                // A single-word FIO that is a public person's surname, near a birth marker,
                // is a biographical reference (e.g. "Пушкин родился 6 июня 1799"), not a client.
                if comps == 1
                    && self.allowlist.is_public_surname(&window[0].lower)
                    && self.has_birth_marker(text, start, end)
                {
                    continue;
                }
                let mut conf: f32 = match comps {
                    3 => 0.6,
                    2 => 0.5,
                    _ => 0.5,
                };
                // Marker conflict is resolved by the trap policy.
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
                // A span whose words are a subset of a public person's name is a negative signal.
                let span_words = normalize_name_words(&text[start..end]);
                if self.allowlist.matches_person_subset(&span_words) {
                    conf -= 0.3;
                }
                conf = conf.clamp(0.0, 1.0);
                if !passes_threshold(conf, opts) {
                    continue;
                }
                candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
            }
        }
        candidates
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
        // 3 capitalized words with no dictionary hit: only with PII context (handled by caller).
        if comps == 3 && !any_initial {
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
        has_context_word_around(text, start, end, spec.context_window, &markers)
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
/// combined with the global `context.non_pii_markers`.
    fn effective_non_pii_markers(&self, spec: &TypeSpec) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if !spec.non_pii_markers.is_empty() {
            out.extend(spec.non_pii_markers.iter().cloned());
        } else if !spec.non_pii_context.is_empty() {
            out.extend(spec.non_pii_context.iter().cloned());
        }
        for m in &self.registry.context().non_pii_markers {
            if !out.contains(m) {
                out.push(m.clone());
            }
        }
        out
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
            (Some(fe), Some((ty, me))) => {
                if fe > me {
                    self.field_label_has_marker(text, fe, markers)
                } else {
                    ty == spec.id
                }
            }
            (Some(fe), None) => self.field_label_has_marker(text, fe, markers),
            (None, Some((ty, _))) => ty == spec.id,
            (None, None) => false,
        }
    }

    /// Returns the type id and end offset of the nearest marker-type context word to the left
    /// of `start` (within a bounded window), if any.
    fn nearest_marker_type(&self, text: &str, start: usize) -> Option<(String, usize)> {
        let re = self.marker_re.as_ref()?;
        let prefix = context_window_before(text, start, 200);
        let window_start = start - prefix.len();
        let mut best: Option<(String, usize)> = None;
        for m in re.find_iter(prefix) {
            let word = prefix[m.start()..m.end()].to_lowercase();
            if let Some(ty) = self.marker_type_of.get(&word) {
                best = Some((ty.clone(), window_start + m.end()));
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

    /// True if the phrase before a field label's colon (since the last sentence boundary)
    /// contains any of the given markers.
    fn field_label_has_marker(&self, text: &str, colon_end: usize, markers: &[String]) -> bool {
        let prefix = &text[..colon_end];
        let boundary = prefix
            .rfind(['.', ';', '\n', '!', '?'])
            .map(|i| i + 1)
            .unwrap_or(0);
        let phrase = &text[boundary..colon_end];
        let lower = phrase.to_lowercase();
        markers.iter().any(|m| lower.contains(m))
    }

    /// Nearest address marker to the left of `start`: Some(true) if pii, Some(false) if
    /// non-pii, None if no marker. The nearest marker decides the address type.
    fn nearest_address_marker(&self, text: &str, start: usize, spec: &TypeSpec) -> Option<bool> {
        let pii = self.effective_pii_markers(spec);
        let non_pii = self.effective_non_pii_markers(spec);
        let prefix = &text[..start];
        let lower = prefix.to_lowercase();
        let mut best_pii: Option<usize> = None;
        let mut best_non_pii: Option<usize> = None;
        for m in &pii {
            if let Some(pos) = lower.rfind(m) {
                let end = pos + m.len();
                best_pii = Some(best_pii.map_or(end, |b| b.max(end)));
            }
        }
        for m in &non_pii {
            if let Some(pos) = lower.rfind(m) {
                let end = pos + m.len();
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
                let start = m.start();
                let mut end = m.end();
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
                    let unextended = &text[start..m.end()];
                    if validators::date(unextended) {
                        end = m.end();
                    } else {
                        continue;
                    }
                }
                // Marker must be within the window before the date or within 20 chars after it
                // (e.g. "10.02.1982 года рождения", "06.06.1988 г.р.").
                let before = context_window_before(text, start, spec.context_window).to_lowercase();
                let after = context_window_after(text, end, 20).to_lowercase();
                let has_marker = spec.context_words.iter().any(|w| before.contains(w) || after.contains(w));
                if !has_marker {
                    continue;
                }
                if date_in_future(span) {
                    continue;
                }
                let mut conf = 0.6f32;
                if age_exceeds(span, self.historical_date_years) {
                    conf -= 0.3;
                }
                if !passes_threshold(conf, opts) {
                    continue;
                }
                candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
            }
        }
        candidates
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
    fn detect_passport_issuer(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        let lower = text.to_lowercase();
        for marker in &spec.context_words {
            let mut search_from = 0;
            while let Some(pos) = lower[search_from..].find(marker) {
                let marker_end = search_from + pos + marker.len();
                if let Some((start, end)) = extract_issuer_after(text, marker_end, &self.registry.context().issuer_prefixes) {
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

    /// Address: group of 2+ consecutive components (index, city, street, house, apartment, region).
    fn detect_address(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let comps = self.find_address_components(text);
        if comps.is_empty() {
            return Vec::new();
        }
        let mut candidates = Vec::new();
        let mut i = 0;
        while i < comps.len() {
            let mut j = i + 1;
            while j < comps.len() && self.components_adjacent(text, comps[j - 1].1, comps[j].0) {
                j += 1;
            }
            let group = &comps[i..j];
            let count = group.len();
            if count >= 2 {
                let start = group[0].0;
                let end = group[group.len() - 1].1;
                let mut conf: f32 = 0.5;
                // The nearest marker to the left decides whether this is a personal address
                // (pii marker) or an organization address (non-pii marker). No marker -> skip.
                match self.nearest_address_marker(text, start, spec) {
                    Some(true) => conf += 0.3,
                    Some(false) => conf -= 0.3,
                    None => conf -= 0.3,
                }
                // An organization near the address is a negative signal.
                let non_pii = self.effective_non_pii_markers(spec);
                if self.allowlist.org_near(text, start, end, 60, &non_pii) {
                    conf -= 0.3;
                }
                conf = conf.clamp(0.0, 1.0);
                if passes_threshold(conf, opts) {
                    candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
                }
            }
            i = j;
        }
        candidates
    }

    fn find_address_components(&self, text: &str) -> Vec<(usize, usize)> {
        let mut comps: Vec<(usize, usize)> = Vec::new();
        for re in ADDRESS_COMPONENT_RES.iter() {
            for m in re.find_iter(text) {
                comps.push((m.start(), m.end()));
            }
        }
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
        // Drop components fully contained in a previous one (keep the longer).
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
        self.registry
            .context()
            .street_markers
            .iter()
            .any(|m| prev_lower.starts_with(m.as_str()) || prev_lower.ends_with(m.as_str()))
    }

    /// Card holder: Latin all-caps words with a marker or near a card number.
    fn detect_card_holder(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let mut candidates = Vec::new();
        for m in CARD_HOLDER_RE.find_iter(text) {
            let start = m.start();
            let end = m.end();
            let window = context_window_before(text, start, spec.context_window);
            let window_lower = window.to_lowercase();
            let has_marker = spec.context_words.iter().any(|w| window_lower.contains(w));
            let after_card = self.card_number_before_within(text, start, 60);
            if !has_marker && !after_card {
                continue;
            }
            let conf = 0.8f32;
            if conf >= opts.min_confidence {
                candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
            }
        }
        candidates
    }

    fn card_number_before_within(&self, text: &str, start: usize, window: usize) -> bool {
        let patterns = self.registry.patterns("card_number");
        for re in patterns {
            for m in re.find_iter(text) {
                if m.end() <= start && start - m.end() <= window {
                    return true;
                }
            }
        }
        false
    }

    /// True if a card marker ("карта", "card", "номер карты", "№ карты") is near the span.
    fn has_card_marker(&self, text: &str, start: usize, end: usize) -> bool {
        let markers = &self.registry.context().card_markers;
        let before = context_window_before(text, start, 40).to_lowercase();
        let after = context_window_after(text, end, 40).to_lowercase();
        markers.iter().any(|m| before.contains(m.as_str()) || after.contains(m.as_str()))
    }

    /// True if a birth marker ("родился", "родилась", "дата рождения", "д.р", "г.р") is near.
    fn has_birth_marker(&self, text: &str, start: usize, end: usize) -> bool {
        let markers = &self.registry.context().birth_markers;
        let before = context_window_before(text, start, 40).to_lowercase();
        let after = context_window_after(text, end, 40).to_lowercase();
        markers.iter().any(|m| before.contains(m.as_str()) || after.contains(m.as_str()))
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
            .map(|(i, _)| i + 1)
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
            .map(|(i, _)| i + 1)
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

/// A capitalized Cyrillic word or an initial (single uppercase letter, optional period).
struct NameToken {
    start: usize,
    end: usize,
    lower: String,
    capitalized: bool,
    is_initial: bool,
}

fn name_tokens(text: &str) -> Vec<NameToken> {
    let mut out = Vec::new();
    for m in NAME_TOKEN_RE.find_iter(text) {
        let w = &text[m.start()..m.end()];
        let letters: String = w.chars().filter(|c| c.is_alphabetic()).collect();
        let is_initial = letters.chars().count() == 1;
        let capitalized = w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
        out.push(NameToken {
            start: m.start(),
            end: m.end(),
            lower: letters.to_lowercase(),
            capitalized,
            is_initial,
        });
    }
    out
}

/// True if two name tokens are separated only by spaces or periods (initials).
fn tokens_adjacent(text: &str, a: &NameToken, b: &NameToken) -> bool {
    let between = &text[a.end..b.start];
    between.chars().all(|c| c.is_whitespace() || c == '.')
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
                let c_len = c.end - c.start;
                let l_len = last.end - last.start;
                let replace = if c_len > l_len {
                    true
                } else if c_len == l_len {
                    c.confidence > last.confidence
                } else {
                    false
                };
                if replace {
                    *last = c;
                }
                continue;
            }
        }
        result.push(c);
    }
    result
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
        .map(|(i, _)| i + 1)
        .unwrap_or(0);
    let word = &before[word_start..];
    abbrev.iter().any(|a| word == a.as_str())
}

/// Finds a country word after a marker.
fn find_country_after(text: &str, from: usize, dicts: &Dictionaries, suffixes: &[String]) -> Option<(usize, usize)> {
    let rest = &text[from..];
    let end_rel = rest.find([',', '.', ';', '\n']).unwrap_or(rest.len());
    let sentence = &rest[..end_rel];
    for (start, end, lower, _) in cyrillic_words(sentence) {
        if is_country(&lower, dicts, suffixes) {
            return Some((from + start, from + end));
        }
    }
    None
}

fn is_country(lower: &str, dicts: &Dictionaries, suffixes: &[String]) -> bool {
    if dicts.contains("countries", lower) {
        return true;
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
fn extract_issuer_after(text: &str, from: usize, prefixes: &[String]) -> Option<(usize, usize)> {
    let rest = &text[from..];
    let stop = ISSUER_STOP_RE.find(rest).map(|m| m.start()).unwrap_or(rest.len());
    let phrase = &rest[..stop];
    let trimmed_start = phrase
        .find(|c: char| !c.is_whitespace() && c != ':' && c != ',')
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

    /// Email: local part, '@', domain with at least one dot.
    pub fn email(s: &str) -> bool {
        let s = s.trim();
        if s.is_empty() || s.contains(char::is_whitespace) {
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

static NAME_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[А-ЯЁ][а-яё]+\b|\b[А-ЯЁ]{2,}\b|\b[А-ЯЁ]\.").unwrap()
});
static CYRILLIC_WORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[А-ЯЁа-яё]+").unwrap());
static WORD_V_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bв\b").unwrap());
static ISSUER_STOP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b|код подразделения|к/п|[,;]").unwrap()
});
static CARD_HOLDER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Z]{2,}(?:[ ]+[A-Z]{2,}){1,2}\b").unwrap());
static ADDRESS_COMPONENT_RES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\b[1-6]\d{5}\b").unwrap(),
        Regex::new(r"(?:г\.|город)\s+[А-ЯЁ][а-яё]+").unwrap(),
        Regex::new(r"(?:ул\.|улица|пр-т|проспект|пер\.|переулок|наб\.|ш\.|шоссе|б-р|бульвар)\s+[А-ЯЁ][а-яё]+").unwrap(),
        Regex::new(r"[А-ЯЁ][а-яё]+\s+(?:пр-т|проспект|ул\.|улица|пер\.|переулок|наб\.|ш\.|шоссе|б-р|бульвар)").unwrap(),
        Regex::new(r"(?:д\.|дом|к\.|корп\.|стр\.)\s+\d+").unwrap(),
        Regex::new(r"(?:кв\.|квартира|оф\.|пом\.)\s+\d+").unwrap(),
        Regex::new(r"(?:обл\.|область|край|респ\.)\s+[А-ЯЁ][а-яё]+").unwrap(),
        Regex::new(r"[А-ЯЁ][а-яё]+\s+\d+").unwrap(),
    ]
});
static BARE_NUMBER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d+(?:[А-ЯЁа-яё]|/\d+)?(?:\s*к\.?\s*\d+)?\b").unwrap()
});
static HYPHENATED_WORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[А-ЯЁ][а-яё]+-[А-ЯЁ][а-яё]+").unwrap());

/// Matches a field label: a word followed by a colon (e.g. "Код заявки:").
static FIELD_LABEL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?iu)\b[а-яёa-z0-9\-]+\s*:").unwrap()
});