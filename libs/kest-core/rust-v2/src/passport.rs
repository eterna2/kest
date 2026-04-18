use super::cache::CacheBackend;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Passport {
    pub entries: Vec<String>,
}

impl Passport {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(&self.entries).unwrap_or_else(|_| "[]".to_string())
    }

    pub fn deserialize(data: &str) -> Self {
        if let Ok(entries) = serde_json::from_str(data) {
            Self { entries }
        } else {
            Self::new()
        }
    }

    pub fn get_parent_scores_and_taints(&self) -> (Vec<i32>, std::collections::HashSet<String>) {
        let mut scores = Vec::new();
        let mut taints = std::collections::HashSet::new();

        for entry in &self.entries {
            let parts: Vec<&str> = entry.split('.').collect();
            if parts.len() < 2 {
                continue;
            }
            
            let payload_b64 = parts[1];
            let mut padding = String::new();
            if payload_b64.len() % 4 != 0 {
                padding = str::repeat("=", 4 - (payload_b64.len() % 4));
            }
            let to_decode = format!("{}{}", payload_b64, padding);
            
            if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE.decode(&to_decode) {
                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                    if let Some(score) = parsed.get("trust_score").and_then(|v| v.as_i64()) {
                        scores.push(score as i32);
                    }
                    if let Some(t_array) = parsed.get("taints").and_then(|v| v.as_array()) {
                        for t in t_array {
                            if let Some(t_str) = t.as_str() {
                                taints.insert(t_str.to_string());
                            }
                        }
                    }
                }
            }
        }
        (scores, taints)
    }
}

pub const MAX_BAGGAGE_SIZE: usize = 4096;
pub const COMPRESS_KEY: &str = "kest.passport_z";

pub struct BaggageManager;

impl BaggageManager {
    fn compress(data: &str) -> String {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(1));
        let _ = encoder.write_all(data.as_bytes());
        let compressed = encoder.finish().unwrap_or_default();
        URL_SAFE_NO_PAD.encode(compressed)
    }

    fn decompress(encoded: &str) -> String {
        if let Ok(compressed) = URL_SAFE_NO_PAD.decode(encoded) {
            let mut decoder = ZlibDecoder::new(&compressed[..]);
            let mut s = String::new();
            if decoder.read_to_string(&mut s).is_ok() {
                return s;
            }
        }
        "".to_string()
    }

    pub fn pack(passport: &Passport, cache: Option<&dyn CacheBackend>) -> HashMap<String, String> {
        let mut result = HashMap::new();
        let serialized = passport.serialize();
        
        let root_hash = if let Some(last) = passport.entries.last() {
            let mut hasher = Sha256::new();
            hasher.update(last.as_bytes());
            hex::encode(hasher.finalize())
        } else {
            "0".to_string()
        };

        if serialized.len() <= MAX_BAGGAGE_SIZE {
            result.insert("kest.passport".to_string(), serialized);
            result.insert("kest.chain_tip".to_string(), root_hash);
            return result;
        }

        let compressed_encoded = Self::compress(&serialized);
        if compressed_encoded.len() <= MAX_BAGGAGE_SIZE {
            result.insert(COMPRESS_KEY.to_string(), compressed_encoded);
            result.insert("kest.chain_tip".to_string(), root_hash);
            return result;
        }

        if let Some(cache_backend) = cache {
            let claim_id = Uuid::now_v7().to_string();
            cache_backend.set(&format!("kest.claim.{}", claim_id), &serialized);
            result.insert("kest.claim_check".to_string(), claim_id);
            result.insert("kest.chain_tip".to_string(), root_hash);
            return result;
        }

        // Best effort
        result.insert(COMPRESS_KEY.to_string(), compressed_encoded);
        result.insert("kest.chain_tip".to_string(), root_hash);
        result
    }

    pub fn unpack<F>(baggage_func: F, cache: Option<&dyn CacheBackend>) -> Result<Passport, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(claim_id) = baggage_func("kest.claim_check") {
            if let Some(cache_backend) = cache {
                if let Some(cached) = cache_backend.get(&format!("kest.claim.{}", claim_id)) {
                    return Ok(Passport::deserialize(&cached));
                }
                return Err(format!("Claim check record {} not found in cache", claim_id));
            }
            return Err("Claim check found but no cache configured".to_string());
        }

        if let Some(compressed_val) = baggage_func(COMPRESS_KEY) {
            let decompressed = Self::decompress(&compressed_val);
            if !decompressed.is_empty() {
                return Ok(Passport::deserialize(&decompressed));
            }
        }

        if let Some(raw) = baggage_func("kest.passport") {
            return Ok(Passport::deserialize(&raw));
        }

        Ok(Passport::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::InMemoryCache;

    #[test]
    fn test_pack_unpack_inline() {
        let mut p = Passport::new();
        p.entries.push("entry1".to_string());
        p.entries.push("entry2".to_string());

        let bag = BaggageManager::pack(&p, None);
        assert!(bag.contains_key("kest.passport"));
        assert!(bag.contains_key("kest.chain_tip"));

        let unpacked = BaggageManager::unpack(|k| bag.get(k).cloned(), None).unwrap();
        assert_eq!(unpacked.entries.len(), 2);
        assert_eq!(unpacked.entries[0], "entry1");
    }

    #[test]
    fn test_pack_unpack_compressed() {
        let mut p = Passport::new();
        let large_entry = "x".repeat(5000); // Exceeds 4096
        p.entries.push(large_entry);

        let bag = BaggageManager::pack(&p, None);
        assert!(bag.contains_key(COMPRESS_KEY));
        assert!(bag.contains_key("kest.chain_tip"));

        let unpacked = BaggageManager::unpack(|k| bag.get(k).cloned(), None).unwrap();
        assert_eq!(unpacked.entries.len(), 1);
        assert_eq!(unpacked.entries[0].len(), 5000);
    }

    #[test]
    fn test_pack_unpack_claim_check() {
        let mut p = Passport::new();
        // create a large enough entry that is difficult to compress well
        let entries: Vec<String> = (0..5000).map(|i| format!("entry_id_{}", i)).collect();
        p.entries = entries;

        let cache = InMemoryCache::new();
        let cache_trait: &dyn CacheBackend = &cache;

        let bag = BaggageManager::pack(&p, Some(cache_trait));
        assert!(bag.contains_key("kest.claim_check"));
        
        let unpacked = BaggageManager::unpack(|k| bag.get(k).cloned(), Some(cache_trait)).unwrap();
        assert_eq!(unpacked.entries.len(), 5000);
    }

    #[test]
    fn test_missing_cache_for_claim_check() {
        let mut p = Passport::new();
        let entries: Vec<String> = (0..5000).map(|i| format!("entry_id_{}", i)).collect();
        p.entries = entries;

        let cache = InMemoryCache::new();
        let cache_trait: &dyn CacheBackend = &cache;
        let bag = BaggageManager::pack(&p, Some(cache_trait));

        let unpacked = BaggageManager::unpack(|k| bag.get(k).cloned(), None);
        assert!(unpacked.is_err());
    }
}
