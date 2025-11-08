use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use wildmatch::WildMatch;

use crate::config::SYSTEM_CONFIG;
use crate::detection::SUSSY_DOMAINS;
use crate::errors::ScanError;
use crate::filters::GOOD_LINKS;
use crate::types::ScannerOptions;

type ResultCache = Arc<Mutex<LruCache<u64, Vec<(crate::types::FindingType, String)>>>>;

pub struct CollapseScanner {
    pub options: ScannerOptions,
    pub found_custom_jvm_indicator: Arc<Mutex<bool>>,
    pub good_links: HashSet<String>,
    pub suspicious_domains: HashSet<String>,
    pub ignored_suspicious_keywords: HashSet<String>,
    pub exclude_patterns: Vec<WildMatch>,
    pub find_patterns: Vec<WildMatch>,
    pub result_cache: ResultCache,
}

impl CollapseScanner {
    pub fn new(options: ScannerOptions) -> Result<Self, ScanError> {
        let good_links: HashSet<String> = GOOD_LINKS.iter().cloned().collect();

        if options.extract_resources || options.extract_strings || options.export_json {
            std::fs::create_dir_all(&options.output_dir)?;
        }

        let mut ignored_suspicious_keywords: HashSet<String> = HashSet::new();

        if let Some(ref path) = options.ignore_keywords_file {
            if options.verbose {
                println!(
                    "{} Loading keywords ignore list from: {}",
                    colored::Colorize::yellow("📄"),
                    path.display()
                );
            }
            match Self::load_ignore_list_from_file(path) {
                Ok(ignored) => {
                    ignored_suspicious_keywords.extend(ignored.clone());
                }
                Err(e) => {
                    eprintln!(
                        "{} Warning: Could not load keywords ignore list from {}: {}",
                        colored::Colorize::yellow("⚠️"),
                        path.display(),
                        e
                    );
                }
            }
        }

        let exclude_patterns = options
            .exclude_patterns
            .iter()
            .map(|p| WildMatch::new(p))
            .collect();
        let find_patterns = options
            .find_patterns
            .iter()
            .map(|p| WildMatch::new(p))
            .collect();

        let cache_size = NonZeroUsize::new(SYSTEM_CONFIG.result_cache_size)
            .unwrap_or_else(|| NonZeroUsize::new(1).unwrap());

        if options.verbose {
            SYSTEM_CONFIG.log_config();
        }

        Ok(CollapseScanner {
            good_links,
            suspicious_domains: SUSSY_DOMAINS.clone(),
            ignored_suspicious_keywords,
            options,
            found_custom_jvm_indicator: Arc::new(Mutex::new(false)),
            exclude_patterns,
            find_patterns,
            result_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
        })
    }
}
