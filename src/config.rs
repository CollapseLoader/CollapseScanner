use lazy_static::lazy_static;
use std::env;
use sysinfo::System;

const DEFAULT_RESULT_CACHE_SIZE: usize = 4096;
const DEFAULT_BUFFER_SIZE: usize = 512 * 1024;
const DEFAULT_SAFE_STRING_CACHE_CAPACITY: usize = 4000;

const LOW_MEMORY_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024;
const MEDIUM_MEMORY_THRESHOLD: u64 = 8 * 1024 * 1024 * 1024;
const HIGH_MEMORY_THRESHOLD: u64 = 16 * 1024 * 1024 * 1024;

lazy_static! {
    pub static ref SYSTEM_CONFIG: SystemConfig = SystemConfig::new();
}

pub struct SystemConfig {
    pub result_cache_size: usize,
    pub buffer_size: usize,
    pub safe_string_cache_capacity: usize,
    pub parallel_scanning: bool,
    pub available_memory: u64,
    pub max_file_size: usize,
}

fn parse_env_usize(key: &str) -> Option<usize> {
    env::var(key).ok()?.parse::<usize>().ok()
}

impl SystemConfig {
    fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let total_memory = sys.total_memory() * 1024;
        let available_memory = env::var("COLLAPSE_AVAILABLE_MEMORY_OVERRIDE_MB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|mb| mb * 1024 * 1024)
            .unwrap_or(total_memory);

        let result_cache_size =
            parse_env_usize("COLLAPSE_RESULT_CACHE_SIZE").unwrap_or(match available_memory {
                m if m < LOW_MEMORY_THRESHOLD => DEFAULT_RESULT_CACHE_SIZE,
                m if m < MEDIUM_MEMORY_THRESHOLD => 16_384,
                m if m < HIGH_MEMORY_THRESHOLD => 65_536,
                _ => 131_072,
            });

        let buffer_size = parse_env_usize("COLLAPSE_BUFFER_SIZE_MB")
            .map(|mb| mb * 1024 * 1024)
            .unwrap_or_else(|| match available_memory {
                m if m < LOW_MEMORY_THRESHOLD => DEFAULT_BUFFER_SIZE,
                m if m < MEDIUM_MEMORY_THRESHOLD => 2 * 1024 * 1024,
                m if m < HIGH_MEMORY_THRESHOLD => 8 * 1024 * 1024,
                _ => 16 * 1024 * 1024,
            });

        let safe_string_cache_capacity = parse_env_usize("COLLAPSE_STRING_CACHE_CAPACITY")
            .unwrap_or(match available_memory {
                m if m < LOW_MEMORY_THRESHOLD => DEFAULT_SAFE_STRING_CACHE_CAPACITY,
                m if m < MEDIUM_MEMORY_THRESHOLD => 20_000,
                m if m < HIGH_MEMORY_THRESHOLD => 80_000,
                _ => 2_000_000,
            });

        let parallel_scanning = match env::var("COLLAPSE_PARALLEL_SCANNING") {
            Ok(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"),
            Err(_) => available_memory >= LOW_MEMORY_THRESHOLD,
        };

        let max_file_size = match available_memory {
            m if m < LOW_MEMORY_THRESHOLD => 100,
            m if m < MEDIUM_MEMORY_THRESHOLD => 250,
            m if m < HIGH_MEMORY_THRESHOLD => 500,
            _ => 1000,
        };

        SystemConfig {
            result_cache_size,
            buffer_size,
            safe_string_cache_capacity,
            parallel_scanning,
            available_memory,
            max_file_size,
        }
    }

    pub fn log_config(&self) {
        println!("[*] System Configuration:");
        println!(
            "   [m] Available Memory: {:.2} GB",
            self.available_memory as f64 / (1024.0 * 1024.0 * 1024.0)
        );
        println!(
            "   [c] Result Cache Size: {} entries",
            self.result_cache_size
        );
        println!(
            "   [b] Buffer Size: {} MB",
            self.buffer_size / (1024 * 1024)
        );
        println!(
            "   [s] String Cache Capacity: {} entries",
            self.safe_string_cache_capacity
        );
        println!("   [f] Max File Size: {} MB", self.max_file_size);
        println!(
            "   [p] Parallel Scanning: {}",
            if self.parallel_scanning {
                "Enabled"
            } else {
                "Disabled"
            }
        );
    }
}
