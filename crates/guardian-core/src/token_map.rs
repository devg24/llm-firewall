use std::collections::HashMap;

use crate::redact::PiiType;

/// Per-request reverse lookup map: token string → (original secret, PiiType).
///
/// Shared via `Arc<std::sync::Mutex<TokenMap>>` between the outbound redactor
/// and the inbound SSE stream mutator. NEVER stored in `AppState`; always
/// instantiated per HTTP request and dropped when the request cycle completes.
pub struct TokenMap {
    inner: HashMap<String, (String, PiiType)>,
}

impl TokenMap {
    /// Create an empty `TokenMap`.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Insert a mapping from a replacement token to its original secret value and PII type.
    pub fn insert(&mut self, token: String, secret: String, pii_type: PiiType) {
        self.inner.insert(token, (secret, pii_type));
    }

    /// Look up the original secret and type by its replacement token.
    pub fn get(&self, token: &str) -> Option<&(String, PiiType)> {
        self.inner.get(token)
    }

    /// Returns `true` if the map contains no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of entries in the map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns an iterator over all keys (tokens) in the map.
    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, String, (String, PiiType)> {
        self.inner.keys()
    }

    /// Returns a list of all detected secret PII types recorded in this map.
    pub fn secret_types(&self) -> Vec<PiiType> {
        self.inner.values().map(|(_, pii_type)| *pii_type).collect()
    }
}

impl Default for TokenMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let map = TokenMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn default_is_empty() {
        let map = TokenMap::default();
        assert!(map.is_empty());
    }

    #[test]
    fn insert_and_get() {
        let mut map = TokenMap::new();
        map.insert(
            "[REDACTED_EMAIL_1]".to_string(),
            "alice@example.com".to_string(),
            PiiType::Email,
        );

        assert!(!map.is_empty());
        assert_eq!(map.len(), 1);

        let result = map.get("[REDACTED_EMAIL_1]");
        assert!(result.is_some());
        let (secret, pii_type) = result.unwrap();
        assert_eq!(secret, "alice@example.com");
        assert_eq!(*pii_type, PiiType::Email);
    }

    #[test]
    fn get_missing_returns_none() {
        let map = TokenMap::new();
        assert!(map.get("[REDACTED_EMAIL_1]").is_none());
    }

    #[test]
    fn multiple_inserts() {
        let mut map = TokenMap::new();
        map.insert(
            "[REDACTED_EMAIL_1]".to_string(),
            "alice@example.com".to_string(),
            PiiType::Email,
        );
        map.insert(
            "[REDACTED_SSN_1]".to_string(),
            "123-45-6789".to_string(),
            PiiType::Ssn,
        );
        map.insert(
            "[REDACTED_IP_1]".to_string(),
            "192.168.1.1".to_string(),
            PiiType::Ip,
        );

        assert_eq!(map.len(), 3);

        let (s, t) = map.get("[REDACTED_SSN_1]").unwrap();
        assert_eq!(s, "123-45-6789");
        assert_eq!(*t, PiiType::Ssn);
    }

    #[test]
    fn insert_overwrites_existing_token() {
        let mut map = TokenMap::new();
        map.insert(
            "[REDACTED_EMAIL_1]".to_string(),
            "first@example.com".to_string(),
            PiiType::Email,
        );
        map.insert(
            "[REDACTED_EMAIL_1]".to_string(),
            "second@example.com".to_string(),
            PiiType::Email,
        );

        assert_eq!(map.len(), 1);
        let (secret, _) = map.get("[REDACTED_EMAIL_1]").unwrap();
        assert_eq!(secret, "second@example.com");
    }
}
