use lazy_static::lazy_static;
use std::env;
use sysinfo::System;

const DEFAULT_RESULT_CACHE_SIZE: usize = 4096;
const DEFAULT_BUFFER_SIZE: usize = 512 * 1024; // 512 KB
const DEFAULT_SAFE_STRING_CACHE_CAPACITY: usize = 4000;

const LOW_MEMORY_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024; // 4 GB
const MEDIUM_MEMORY_THRESHOLD: u64 = 8 * 1024 * 1024 * 1024; // 8 GB
const HIGH_MEMORY_THRESHOLD: u64 = 16 * 1024 * 1024 * 1024; // 16 GB

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

impl SystemConfig {
    fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let total_memory = sys.total_memory() * 1024;
        let available_memory = if let Ok(val) = env::var("COLLAPSE_AVAILABLE_MEMORY_OVERRIDE_MB") {
            if let Ok(mb) = val.parse::<u64>() {
                mb * 1024 * 1024
            } else {
                total_memory
            }
        } else {
            total_memory
        };

        let buffer_size_mb_override = env::var("COLLAPSE_BUFFER_SIZE_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok());
        let result_cache_size_override = env::var("COLLAPSE_RESULT_CACHE_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok());
        let safe_string_cache_capacity_override = env::var("COLLAPSE_STRING_CACHE_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok());

        let result_cache_size = if let Some(override_val) = result_cache_size_override {
            override_val
        } else {
            match available_memory {
                mem if mem < LOW_MEMORY_THRESHOLD => DEFAULT_RESULT_CACHE_SIZE,
                mem if mem < MEDIUM_MEMORY_THRESHOLD => 16384,
                mem if mem < HIGH_MEMORY_THRESHOLD => 65536,
                _ => 131072,
            }
        };

        let buffer_size = if let Some(mb) = buffer_size_mb_override {
            mb * 1024 * 1024
        } else {
            match available_memory {
                mem if mem < LOW_MEMORY_THRESHOLD => DEFAULT_BUFFER_SIZE,
                mem if mem < MEDIUM_MEMORY_THRESHOLD => 2 * 1024 * 1024, // 2 MB
                mem if mem < HIGH_MEMORY_THRESHOLD => 8 * 1024 * 1024,   // 8 MB
                _ => 16 * 1024 * 1024,                                   // 16 MB
            }
        };

        let safe_string_cache_capacity =
            if let Some(override_val) = safe_string_cache_capacity_override {
                override_val
            } else {
                match available_memory {
                    mem if mem < LOW_MEMORY_THRESHOLD => DEFAULT_SAFE_STRING_CACHE_CAPACITY,
                    mem if mem < MEDIUM_MEMORY_THRESHOLD => 20_000,
                    mem if mem < HIGH_MEMORY_THRESHOLD => 80_000,
                    _ => 2_000_000,
                }
            };

        let parallel_scanning = match env::var("COLLAPSE_PARALLEL_SCANNING") {
            Ok(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"),
            Err(_) => available_memory >= LOW_MEMORY_THRESHOLD,
        };

        let max_file_size = match available_memory {
            mem if mem < LOW_MEMORY_THRESHOLD => 100,
            mem if mem < MEDIUM_MEMORY_THRESHOLD => 250,
            mem if mem < HIGH_MEMORY_THRESHOLD => 500,
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
