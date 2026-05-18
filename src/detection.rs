use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

lazy_static::lazy_static! {
    pub static ref SAFE_STRING_CACHE: moka::sync::Cache<String, ()> = {
        let capacity = crate::config::SYSTEM_CONFIG.safe_string_cache_capacity as u64;
        moka::sync::Cache::builder()
            .max_capacity(capacity)
            .build()
    };

    pub static ref SAFE_STRING_BLOOM: std::sync::RwLock<bloomfilter::Bloom<u64>> = {
        let capacity = crate::config::SYSTEM_CONFIG.safe_string_cache_capacity;
        std::sync::RwLock::new(
            bloomfilter::Bloom::new_for_fp_rate(capacity, 0.01).unwrap()
        )
    };

    pub static ref SUSSY_DOMAINS: HashSet<String> = [
        "discord.com",
        "discordapp.com",
        "discord.gg",
        "cdn.discordapp.com",
        "pastebin.com",
        "hastebin.com",
        "ghostbin.co",
        "gofile.io",
        "transfer.sh",
        "webhook.site",
        "requestbin.net",
        "ngrok.io",
        "ngrok-free.app",
        "localtunnel.me",
        "serveo.net",
        "grabify.link",
        "iplogger.org",
        "ipify.org",
        "ifconfig.me",
        "bit.ly",
        "tinyurl.com",
    ]
    .iter()
    .map(|&s| s.to_lowercase())
    .collect();
}

fn get_bloom_hash(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

pub fn is_cached_safe_string(s: &str) -> bool {
    if SAFE_STRING_CACHE.get(s).is_some() {
        return true;
    }

    let h = get_bloom_hash(s);
    match SAFE_STRING_BLOOM.try_read() {
        Ok(guard) if !guard.check(&h) => return false,
        _ => {}
    }

    SAFE_STRING_CACHE.get(s).is_some()
}

pub fn cache_safe_string(s: &str) {
    let h = get_bloom_hash(s);

    if let Ok(mut guard) = SAFE_STRING_BLOOM.try_write() {
        guard.set(&h);
    } else if let Ok(mut guard) = SAFE_STRING_BLOOM.write() {
        guard.set(&h);
    }

    SAFE_STRING_CACHE.insert(s.to_string(), ());
}

pub fn calculate_detection_hash(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();

    if data.len() > 1024 {
        data[..512].hash(&mut hasher);
        let mid = data.len() / 2;
        data[mid - 256..mid + 256].hash(&mut hasher);
        data[data.len() - 512..].hash(&mut hasher);
        (data.len() as u64).hash(&mut hasher);
    } else {
        data.hash(&mut hasher);
    }

    hasher.finish()
}
