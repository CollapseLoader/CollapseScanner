use lazy_static::lazy_static;
use sysinfo::System;

const DEFAULT_RESULT_CACHE_SIZE: usize = 4096;
const DEFAULT_BUFFER_SIZE: usize = 512 * 1024;
const DEFAULT_SAFE_STRING_CACHE_CAPACITY: usize = 1000;

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
}

impl SystemConfig {
    fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let available_memory = sys.total_memory() * 1024;

        let result_cache_size = match available_memory {
            mem if mem < LOW_MEMORY_THRESHOLD => DEFAULT_RESULT_CACHE_SIZE,
            mem if mem < MEDIUM_MEMORY_THRESHOLD => 16384,
            mem if mem < HIGH_MEMORY_THRESHOLD => 65536,
            _ => 131072,
        };

        let buffer_size = match available_memory {
            mem if mem < LOW_MEMORY_THRESHOLD => DEFAULT_BUFFER_SIZE,
            mem if mem < MEDIUM_MEMORY_THRESHOLD => 2 * 1024 * 1024,
            mem if mem < HIGH_MEMORY_THRESHOLD => 8 * 1024 * 1024,
            _ => 16 * 1024 * 1024,
        };

        let safe_string_cache_capacity = match available_memory {
            mem if mem < LOW_MEMORY_THRESHOLD => DEFAULT_SAFE_STRING_CACHE_CAPACITY,
            mem if mem < MEDIUM_MEMORY_THRESHOLD => 5000,
            mem if mem < HIGH_MEMORY_THRESHOLD => 20000,
            _ => 50000,
        };

        let parallel_scanning = available_memory >= LOW_MEMORY_THRESHOLD;

        SystemConfig {
            result_cache_size,
            buffer_size,
            safe_string_cache_capacity,
            parallel_scanning,
            available_memory,
        }
    }

    pub fn log_config(&self) {
        println!("🔧 System Configuration:");
        println!(
            "   📊 Available Memory: {:.2} GB",
            self.available_memory as f64 / (1024.0 * 1024.0 * 1024.0)
        );
        println!(
            "   🧰 Result Cache Size: {} entries",
            self.result_cache_size
        );
        println!("   📦 Buffer Size: {} MB", self.buffer_size / (1024 * 1024));
        println!(
            "   💾 String Cache Capacity: {} entries",
            self.safe_string_cache_capacity
        );
        println!(
            "   🔍 Parallel Scanning: {}",
            if self.parallel_scanning {
                "Enabled"
            } else {
                "Disabled"
            }
        );
    }
}
