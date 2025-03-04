/// A very quick implementation of a dual map, which is a map that can be indexed by either key or value.
/// simply by maintaining two maps, one for each direction. This is not a very efficient implementation in terms
/// of memory usage, doubling the memory usage of the map.
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DualMap<K, V> {
    key_to_value: HashMap<K, V>,
    value_to_key: HashMap<V, K>,
}

impl<K: std::hash::Hash + Eq + Clone, V: std::hash::Hash + Eq + Clone> Default for DualMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: std::hash::Hash + Eq + Clone, V: std::hash::Hash + Eq + Clone> DualMap<K, V> {
    pub fn new() -> DualMap<K, V> {
        DualMap {
            key_to_value: HashMap::new(),
            value_to_key: HashMap::new(),
        }
    }

    pub fn into_hashmap(self) -> HashMap<K, V> {
        self.key_to_value
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.key_to_value.contains_key(key)
    }

    pub fn contains_value(&self, value: &V) -> bool {
        self.value_to_key.contains_key(value)
    }

    pub fn insert(&mut self, key: K, value: V) {
        self.key_to_value.insert(key.clone(), value.clone());
        self.value_to_key.insert(value, key);
    }

    pub fn get_by_key(&self, key: &K) -> Option<&V> {
        self.key_to_value.get(key)
    }

    pub fn get_by_value(&self, value: &V) -> Option<&K> {
        self.value_to_key.get(value)
    }

    pub fn remove_by_key(&mut self, key: &K) -> Option<V> {
        if let Some(value) = self.key_to_value.remove(key) {
            self.value_to_key.remove(&value);
            Some(value)
        } else {
            None
        }
    }

    pub fn remove_by_value(&mut self, value: &V) -> Option<K> {
        if let Some(key) = self.value_to_key.remove(value) {
            self.key_to_value.remove(&key);
            Some(key)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.key_to_value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.key_to_value.is_empty()
    }

    pub fn clear(&mut self) {
        self.key_to_value.clear();
        self.value_to_key.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_key() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        assert!(map.contains_key(&1));
        assert!(!map.contains_key(&2));
    }

    #[test]
    fn test_contains_value() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        assert!(map.contains_value(&"a"));
        assert!(!map.contains_value(&"b"));
    }

    #[test]
    fn test_into_hashmap() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        map.insert(2, "b");
        let hashmap = map.into_hashmap();
        assert_eq!(hashmap.get(&1), Some(&"a"));
        assert_eq!(hashmap.get(&2), Some(&"b"));
    }

    #[test]
    fn test_insert_and_get() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        assert_eq!(map.get_by_key(&1), Some(&"a"));
        assert_eq!(map.get_by_value(&"a"), Some(&1));
    }

    #[test]
    fn test_remove_by_key() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        assert_eq!(map.remove_by_key(&1), Some("a"));
        assert_eq!(map.get_by_key(&1), None);
        assert_eq!(map.get_by_value(&"a"), None);
    }

    #[test]
    fn test_remove_by_value() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        assert_eq!(map.remove_by_value(&"a"), Some(1));
        assert_eq!(map.get_by_key(&1), None);
        assert_eq!(map.get_by_value(&"a"), None);
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut map = DualMap::new();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());

        map.insert(1, "a");
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());

        map.remove_by_key(&1);
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        map.insert(2, "b");
        map.clear();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert_eq!(map.get_by_key(&1), None);
        assert_eq!(map.get_by_key(&2), None);
        assert_eq!(map.get_by_value(&"a"), None);
        assert_eq!(map.get_by_value(&"b"), None);
    }

    #[test]
    fn test_get_by_key() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        map.insert(2, "b");
        assert_eq!(map.get_by_key(&1), Some(&"a"));
        assert_eq!(map.get_by_key(&2), Some(&"b"));
        assert_eq!(map.get_by_key(&3), None);
    }

    #[test]
    fn test_get_by_value() {
        let mut map = DualMap::new();
        map.insert(1, "a");
        map.insert(2, "b");
        assert_eq!(map.get_by_value(&"a"), Some(&1));
        assert_eq!(map.get_by_value(&"b"), Some(&2));
        assert_eq!(map.get_by_value(&"c"), None);
    }
}
