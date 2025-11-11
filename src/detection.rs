use std::collections::HashSet;

lazy_static::lazy_static! {
    pub static ref SAFE_STRING_CACHE: moka::sync::Cache<String, ()> = {
        let capacity = crate::config::SYSTEM_CONFIG.safe_string_cache_capacity as u64;
        moka::sync::Cache::builder().max_capacity(capacity).build()
    };

    pub static ref SAFE_STRING_BLOOM: std::sync::Mutex<bloomfilter::Bloom<String>> = {
        std::sync::Mutex::new(bloomfilter::Bloom::new_for_fp_rate(100000, 0.01).unwrap())
    };

    pub static ref SUSSY_DOMAINS: HashSet<String> = {
        [
            "discord.com",
            "discordapp.com",
            "pastebin.com",
            "bit.ly",
            "tinyurl.com",
        ]
        .iter()
        .map(|&s| s.to_lowercase())
        .collect()
    };
}

pub fn is_cached_safe_string(s: &str) -> bool {
    if let Ok(bloom) = SAFE_STRING_BLOOM.lock() {
        if !bloom.check(&s.to_string()) {
            return false;
        }
    }

    SAFE_STRING_CACHE.get(s).is_some()
}

pub fn cache_safe_string(s: &str) -> bool {
    let string_owned = s.to_string();

    if let Ok(mut bloom) = SAFE_STRING_BLOOM.lock() {
        bloom.set(&string_owned);
    }

    SAFE_STRING_CACHE.insert(string_owned, ());
    true
}

pub fn calculate_detection_hash(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    if data.len() > 1024 {
        let start = &data[..512];
        let middle = &data[data.len() / 2 - 256..data.len() / 2 + 256];
        let end = &data[data.len() - 512..];

        start.hash(&mut hasher);
        middle.hash(&mut hasher);
        end.hash(&mut hasher);
        (data.len() as u64).hash(&mut hasher);
    } else {
        data.hash(&mut hasher);
    }

    hasher.finish()
}
