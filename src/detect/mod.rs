use crate::registry::{Registry, TypeSpec, Validator};
use crate::types::Entity;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

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
}

pub struct Detector {
    registry: std::sync::Arc<Registry>,
    dicts: std::sync::Arc<Dictionaries>,
    /// Birth dates older than this many years get a confidence penalty.
    historical_date_years: u32,
}

impl Detector {
    pub fn new(registry: std::sync::Arc<Registry>, dicts: std::sync::Arc<Dictionaries>) -> Self {
        Self { registry, dicts, historical_date_years: 120 }
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

        resolve_overlaps(candidates)
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

                let mut conf = 0.6f32;

                let has_context = if spec.context_words.is_empty() {
                    false
                } else {
                    let window = context_window_before(text, start, spec.context_window);
                    let window_lower = window.to_lowercase();
                    spec.context_words.iter().any(|w| window_lower.contains(w))
                };

                if spec.validator != Validator::None {
                    if validator_passes(spec.validator, span) {
                        conf += 0.3;
                    } else {
                        continue;
                    }
                }

                if has_context {
                    conf += 0.1;
                }
                if spec.context_required && !has_context {
                    continue;
                }
                conf = conf.min(1.0);

                if conf < opts.min_confidence {
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
                // A city token is kept when followed by initials (a FIO pattern),
                // e.g. "г. Пушкин И. С.".
                all_tokens.get(i + 1).map(|n| n.is_initial).unwrap_or(false)
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
                if window.iter().any(|t| preceded_by_street_marker(text, t.start)) {
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
                let has_non_pii = self.has_non_pii_context(text, start, end, spec);
                // Non-PII marker without PII marker suppresses the candidate.
                if has_non_pii && !has_pii {
                    continue;
                }
                let mut conf: f32 = match comps {
                    3 => 0.9,
                    2 => 0.7,
                    _ => 0.5,
                };
                if has_pii {
                    conf += 0.3;
                }
                if has_non_pii {
                    conf -= 0.3;
                }
                conf = conf.clamp(0.0, 1.0);
                if conf < opts.min_confidence {
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
        if spec.pii_context.is_empty() {
            return false;
        }
        has_context_word_around(text, start, end, spec.context_window, &spec.pii_context)
    }

    fn has_non_pii_context(&self, text: &str, start: usize, end: usize, spec: &TypeSpec) -> bool {
        if spec.non_pii_context.is_empty() {
            return false;
        }
        has_context_word_around(text, start, end, spec.context_window, &spec.non_pii_context)
    }

    /// Dates: only with a marker within the window before; future dates rejected; old dates penalized.
    fn detect_date(&self, text: &str, opts: &DetectOptions<'_>, spec: &TypeSpec) -> Vec<Entity> {
        let patterns = self.registry.patterns(&spec.id);
        let mut candidates = Vec::new();
        for re in patterns {
            for m in re.find_iter(text) {
                let start = m.start();
                let mut end = m.end();
                // Extend the span to include a trailing " г." or " года" right after the year.
                let after = &text[end..];
                if let Some(rest) = after.strip_prefix(" г.") {
                    if rest.chars().next().map(|c| !c.is_alphabetic()).unwrap_or(true) {
                        end += " г.".len();
                    }
                } else if let Some(rest) = after.strip_prefix(" года") {
                    if rest.chars().next().map(|c| !c.is_alphabetic()).unwrap_or(true) {
                        end += " года".len();
                    }
                }
                let span = &text[start..end];
                if !validators::date(span) {
                    continue;
                }
                // Marker must be within the window before the date.
                let window = context_window_before(text, start, spec.context_window);
                let window_lower = window.to_lowercase();
                let has_marker = spec.context_words.iter().any(|w| window_lower.contains(w));
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
                if conf < opts.min_confidence {
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
                if let Some((start, end)) = extract_place_after(text, marker_end) {
                    let span = &text[start..end];
                    // Only accept a place that looks like a toponym (city marker or city name),
                    // or when the marker itself strongly implies a place follows.
                    let strong_marker = matches!(marker.as_str(), "место рождения" | "уроженец" | "уроженка");
                    if !strong_marker && !self.looks_like_place(span) {
                        search_from = marker_end;
                        continue;
                    }
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

    /// True if a span looks like a place (city marker, city name, or region marker).
    fn looks_like_place(&self, span: &str) -> bool {
        // A valid date is not a place (e.g. "05 мая 1985 г.").
        if validators::date(span) {
            return false;
        }
        if span.contains("г.") || span.contains("город") || span.contains("с.") || span.contains("пос.")
            || span.contains("обл.") || span.contains("область") || span.contains("край")
            || span.contains("респ.") || span.contains("деревня")
        {
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
                if let Some((start, end)) = find_country_after(text, marker_end, &self.dicts) {
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
                if let Some((start, end)) = extract_issuer_after(text, marker_end) {
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
            while j < comps.len() && components_adjacent(text, comps[j - 1].1, comps[j].0) {
                j += 1;
            }
            let group = &comps[i..j];
            let count = group.len();
            if count >= 2 {
                let start = group[0].0;
                let end = group[group.len() - 1].1;
                let mut conf: f32 = if count >= 3 { 0.9 } else { 0.7 };
                let window = context_window_before(text, start, spec.context_window);
                let window_lower = window.to_lowercase();
                if spec.context_words.iter().any(|w| window_lower.contains(w)) {
                    conf += 0.1;
                }
                conf = conf.min(1.0);
                if conf >= opts.min_confidence {
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
        STREET_MARKERS
            .iter()
            .any(|m| prev_lower.starts_with(m) || prev_lower.ends_with(m))
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

fn preceded_by_street_marker(text: &str, start: usize) -> bool {
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
    STREET_MARKERS.contains(&last_word.to_lowercase().as_str())
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
fn extract_place_after(text: &str, from: usize) -> Option<(usize, usize)> {
    let rest = &text[from..];
    // Skip leading whitespace, colons and commas.
    let lead = rest
        .find(|c: char| !c.is_whitespace() && c != ':' && c != ',')
        .unwrap_or(rest.len());
    let rest = &rest[lead..];
    let end_rel = place_end(rest);
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
fn place_end(rest: &str) -> usize {
    let mut i = 0;
    while i < rest.len() {
        let c = rest[i..].chars().next().unwrap();
        match c {
            ',' | ';' | '\n' | ':' => return i,
            '.' => {
                if is_abbreviation_period(rest, i) {
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
fn is_abbreviation_period(rest: &str, period_idx: usize) -> bool {
    let before = &rest[..period_idx];
    let word_start = before
        .char_indices()
        .rev()
        .find(|(_, c)| !c.is_alphabetic())
        .map(|(i, _)| i + 1)
        .unwrap_or(0);
    let word = &before[word_start..];
    matches!(
        word,
        "г" | "с" | "п" | "пос" | "обл" | "ул" | "пер" | "наб" | "ш" | "б-р" | "пл"
            | "пр" | "д" | "к" | "стр" | "кв" | "оф" | "пом" | "корп" | "респ" | "край"
    )
}

/// Finds a country word after a marker.
fn find_country_after(text: &str, from: usize, dicts: &Dictionaries) -> Option<(usize, usize)> {
    let rest = &text[from..];
    let end_rel = rest.find([',', '.', ';', '\n']).unwrap_or(rest.len());
    let sentence = &rest[..end_rel];
    for (start, end, lower, _) in cyrillic_words(sentence) {
        if is_country(&lower, dicts) {
            return Some((from + start, from + end));
        }
    }
    None
}

fn is_country(lower: &str, dicts: &Dictionaries) -> bool {
    if dicts.contains("countries", lower) {
        return true;
    }
    // Handle common genitive forms by stripping a trailing vowel.
    for suffix in ["ии", "а", "и", "ы", "я", "ов", "ев"] {
        if let Some(stripped) = lower.strip_suffix(suffix) {
            if dicts.contains("countries", stripped) {
                return true;
            }
        }
    }
    false
}

/// Extracts the passport issuer phrase after a marker.
fn extract_issuer_after(text: &str, from: usize) -> Option<(usize, usize)> {
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
    if !ISSUER_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return None;
    }
    let start = from + trimmed_start;
    let end = start + phrase.len();
    Some((start, end))
}

/// True if two address components are separated only by separators (comma, space, "г." etc.).
fn components_adjacent(text: &str, prev_end: usize, next_start: usize) -> bool {
    if prev_end > next_start {
        return false;
    }
    let between = &text[prev_end..next_start];
    let between = between.trim();
    between.is_empty() || between == "," || between == "г." || between == "г"
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

static STREET_MARKERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["ул", "улица", "пл", "площадь", "пр", "пр-т", "проспект", "пер", "переулок", "наб", "набережная", "ш", "шоссе", "б-р", "бульвар"]
        .iter()
        .copied()
        .collect()
});

static ISSUER_PREFIXES: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec!["оуфмс", "уфмс", "овд", "гу мвд", "мвд", "тп", "овм", "отделом", "отделением", "управлением"]
});