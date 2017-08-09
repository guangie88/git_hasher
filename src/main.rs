extern crate crypto_hash;
#[macro_use] extern crate derive_new;
#[macro_use] extern crate error_chain;
extern crate file;
extern crate git2;
#[macro_use] extern crate log;
extern crate log4rs;
extern crate regex;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_yaml;
extern crate simple_logger;
extern crate structopt;
#[macro_use] extern crate structopt_derive;
extern crate strum;
#[macro_use] extern crate strum_macros;
extern crate toml;

use crypto_hash::Algorithm;
use git2::{Repository, StatusOptions};
use git2::build::CheckoutBuilder;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::process;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;
use std::string::ToString;
use std::sync::mpsc;
use structopt::StructOpt;

pub mod errors {
    error_chain! {
        errors {}
    }
}

use errors::ResultExt;

#[derive(StructOpt, Debug)]
#[structopt(name = "Git Hasher", about = "Performs hashing based on current local git repository")]
struct ArgConfig {
    #[structopt(short = "c", long = "config", help = "Config file path", default_value = "git_hasher_config.toml")]
    config_path: String,

    #[structopt(short = "l", long = "log", help = "Log config file path")]
    log_config_path: Option<String>,
}

#[derive(Deserialize)]
struct FileConfig {
    /// Path to generated hash file.
    hash_path: String,

    /// Must be MD5, SHA1, SHA256.
    hash_meth: String,

    /// Local git repository working directory path.
    git_path: String,

    /// Regex patterns to match after .gitignore filtering.
    regex_matches: Vec<String>,
}

#[derive(Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize, new)]
struct HashElement {
    /// Path of git working file (can be untracked).
    path: String,

    /// Hash value of binary content of file.
    hash: String,
}

impl<'a> From<&'a HashElement> for (&'a str, &'a str) {
    fn from(e: &'a HashElement) -> Self {
        (&e.path, &e.hash)
    }
}

#[derive(Deserialize, Serialize, new)]
struct HashCollection {
    /// Hash method name.
    meth: Algo,

    /// Collection of hash elements.
    elements: BTreeSet<HashElement>,
}

#[derive(EnumString, ToString, Deserialize, PartialEq, Eq, Serialize, Debug)]
enum Algo {
    MD5, SHA1, SHA256,
}

#[derive(ToString)]
enum NdType {
    New, Deleted,
}

fn init_logger(log_config_path: &Option<String>) -> errors::Result<()> {
    if let &Some(ref log_config_path) = log_config_path {
        log4rs::init_file(log_config_path, Default::default())
            .chain_err(|| format!("Unable to initialize log4rs logger with the given config file at '{}'", log_config_path))?;
    } else {
        simple_logger::init()
            .chain_err(|| "Unable to initialize default logger")?;
    }

    Ok(())
}

fn get_algo(hash_meth: &str) -> errors::Result<(Algo, Algorithm)> {
    let algo_enum = Algo::from_str(hash_meth)
        .chain_err(|| format!("Unknown hash method name '{}'", hash_meth))?;

    let algo = match algo_enum {
        Algo::MD5 => Algorithm::MD5,
        Algo::SHA1 => Algorithm::SHA1,
        Algo::SHA256 => Algorithm::SHA256,
    };

    Ok((algo_enum, algo))
}

fn read_string_from_file<P: AsRef<Path>>(path: P) -> errors::Result<String> {
    let path = path.as_ref();

    let mut config_file = File::open(path)
        .chain_err(|| format!("Unable to open config file path at {:?}", path))?;

    let mut s = String::new();

    config_file.read_to_string(&mut s)
        .map(|_| s)
        .chain_err(|| "Unable to read config file into string")
}

fn print_and_sum_modified<'a, I>(entries: I) -> u64
where I: Iterator<Item=(&'a str, &'a str, &'a str)> {
    info!("-- Modified Entries --");

    let count = entries.fold(0, |count, (path, prev_hash, curr_hash)| {
        info!("{}: {} -> {}", path, prev_hash, curr_hash);
        count + 1
    });

    if count == 0 { info!("NONE"); }
    count
}

fn print_and_sum_new_delete<'a, I>(entries: I, nd: NdType) -> u64
where I: Iterator<Item=(&'a str, &'a str)> {
    info!("-- {} Entries --", nd.to_string());

    let count = entries.fold(0, |count, (path, hash)| {
        info!("{}: {}", path, hash);
        count + 1
    });

    if count == 0 { info!("NONE"); }
    count
}

fn run() -> errors::Result<()> {
    // initialization
    let arg_config = ArgConfig::from_args();
    init_logger(&arg_config.log_config_path)?;

    let config_str = read_string_from_file(&arg_config.config_path)?;

    let config: FileConfig = toml::from_str(&config_str)
        .chain_err(|| format!("Unable to parse config as required toml format: {}", config_str))?;

    let (algo_enum, algo) = get_algo(&config.hash_meth)?;

    let regexes = config.regex_matches.iter()
        .map(|s| Regex::new(s).chain_err(|| format!("Unable to convert string: {} to regex pattern", s)))
        .collect::<Result<Vec<Regex>, errors::Error>>()?;

    // git section
    let repo = Repository::open(&config.git_path)
        .chain_err(|| format!("Unable to find local git working directory at '{}'", config.git_path))?;

    // attempt to parse the current commit (destructive) hash yaml first
    let prev_hash_collection = match repo.status_file(&Path::new(&config.hash_path)) {
        Ok(status) => {
            debug!("Hash path status: {:?}", status);

            // only checkout if the hash yaml file was modified
            // likely to be git2::STATUS_WT_MODIFIED) || status.contains(git2::STATUS_WT_DELETED)
            if status.contains(git2::STATUS_CURRENT) && !status.contains(git2::STATUS_WT_NEW) {
                let mut opts = CheckoutBuilder::new();
                let (tx, rx) = mpsc::channel();

                opts.force()
                    .path(&config.hash_path)
                    .update_index(false)
                    .progress(move |_: Option<&Path>, current_count: usize, total_count: usize| {
                        if current_count == total_count {
                            if let Err(e) = tx.send(Some(())) {
                                error!("Error sending Some value into git checkout channel: {}. Process will hang, press CTRL-C to terminate...", e);
                            }
                        }
                    });

                repo.checkout_index(None, Some(&mut opts))
                    .chain_err(|| format!("Unable to perform checkout on head for hash yaml at '{}'", config.hash_path))?;

                rx.recv().chain_err(|| "Unable to receive value from git checkout channel")?;

                let prev_content = match read_string_from_file(&config.hash_path) {
                    Ok(content) => Some(content),
                    Err(e) => {
                        error!("Assuming no previous hash, unable to read content from hash yaml file: {}", e);
                        None
                    },
                };

                let prev_hash_collection: Option<HashCollection> = prev_content.and_then(|prev_content| {
                    match serde_yaml::from_str(&prev_content) {
                        Ok(prev_hash_collection) => Some(prev_hash_collection),
                        Err(e) => {
                            error!("Assuming no previous hash, unable to parse previous hash yaml file: {}", e);
                            None
                        },
                    }
                });

                prev_hash_collection
            } else {
                // highly possibly the status is STATUS_WT_NEW
                // and assume that it is
                warn!("Found new hash yaml file in working tree at '{}', continuing as if the next created hash yaml file is NEW",
                    config.hash_path);

                None
            }
        },

        Err(e) => {
            warn!("{}. No previous hash yaml file found at '{}', continuing as if the next created hash yaml file is NEW",
                e, config.hash_path);

            None
        },
    };

    // allows untracked files to be shown
    let statuses = {
        let mut options = StatusOptions::new();

        options.include_untracked(true)
            .include_unmodified(true)
            .recurse_untracked_dirs(true);

        repo.statuses(Some(&mut options))
            .chain_err(|| format!("Unable to obtain statuses in the local git working directory at '{}'", config.git_path))?
    };

    let filtered_paths: Vec<String> = statuses.iter()
        .filter_map(|s| s.path().map(|p| p.to_owned()))
        .filter(|p| p != &config.hash_path && regexes.iter().any(|r| r.is_match(p)))
        .collect();
    
    let hash_elems: BTreeSet<HashElement> = filtered_paths.into_iter()
        .map(|p| {
            let buf = file::get(&p);
            let p_clone = p.clone();
            buf.map(|buf| HashElement::new(p, crypto_hash::hex_digest(algo.clone(), &buf))).map_err(|e| (e, p_clone))
        })
        .inspect(|res| {
            if let &Err((ref e, ref p)) = res {
                trace!("Assuming '{}' was deleted: {}", p, e);
            }
        })
        .filter_map(|res| res.ok())
        .collect();

    // serialize into file section
    let hash_collection = HashCollection::new(algo_enum, hash_elems);

    let mut hash_file = File::create(&config.hash_path)
        .chain_err(|| format!("Unable to create hash file at '{}'", config.hash_path))?;

    let hash_collection_str = serde_yaml::to_string(&hash_collection)
        .chain_err(|| "Unable to serialize hash collection into TOML")?;

    hash_file.write_all(hash_collection_str.as_bytes())
        .chain_err(|| format!("Unable to write into hash file at '{}'", config.hash_path))?;

    // compare both the hash collections
    let curr_elems = &hash_collection.elements;
    
    if let Some(prev_hash_collection) = prev_hash_collection {
        if &prev_hash_collection.meth == &hash_collection.meth {
            let prev_elems = &prev_hash_collection.elements;

            let possibly_new_entries: BTreeMap<&str, &str> = curr_elems.difference(prev_elems)
                .map(|hash_elem| hash_elem.into())
                .collect();

            let possibly_deleted_entries: BTreeMap<&str, &str> = prev_elems.difference(curr_elems)
                .map(|hash_elem| hash_elem.into())
                .collect();

            // key intersect with values diff => modified files
            let modified_entries = possibly_new_entries.iter()
                .filter_map(|(path, curr_hash)| {
                    possibly_deleted_entries
                        .get(path)
                        .map(|prev_hash| (*path, *prev_hash, *curr_hash))
                });

            // possibly new keys that do not appear in prev keys => new files
            let new_entries = possibly_new_entries.iter()
                .filter_map(|(path, curr_hash)| {
                    match possibly_deleted_entries.get(path) {
                        Some(_) => None,
                        None => Some((*path, *curr_hash)),
                    }
                });

            // possibly prev keys that do not appear in new keys => deleted files
            let deleted_entries = possibly_deleted_entries.iter()
                .filter_map(|(path, prev_hash)| {
                    match possibly_new_entries.get(path) {
                        Some(_) => None,
                        None => Some((*path, *prev_hash)),
                    }
                });

            
            let new_entries_count = print_and_sum_new_delete(new_entries, NdType::New);
            let deleted_entries_count = print_and_sum_new_delete(deleted_entries, NdType::Deleted);
            let modified_entries_count = print_and_sum_modified(modified_entries);

            info!("----- Summary -----");
            info!("     New count: {}", new_entries_count);
            info!(" Deleted count: {}", deleted_entries_count);
            info!("Modified count: {}", modified_entries_count);
            info!("   Total count: {}", curr_elems.len());
            
        } else {
            error!("Previous hash collection uses method: {}, while current hash collection uses method: {}, which is not comparable",
                prev_hash_collection.meth.to_string(), hash_collection.meth.to_string());
        }
    } else {
        info!("All files in current hash yaml file are NEW");
        info!("Total count: {}", curr_elems.len());
    }

    Ok(())
}

fn main() {
    match run() {
        Ok(_) => {
            info!("Program completed!");
            process::exit(0)
        },

        Err(ref e) => {
            error!("Error: {}", e);

            for e in e.iter().skip(1) {
                error!("> Caused by: {}", e);
            }

            process::exit(1);
        },
    }
}
