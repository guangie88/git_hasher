extern crate crypto_hash;
#[macro_use] extern crate derive_new;
extern crate docopt;
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
extern crate strum;
#[macro_use] extern crate strum_macros;
extern crate toml;

use crypto_hash::Algorithm;
use docopt::Docopt;
use git2::{IndexAddOption, ObjectType, Repository, ResetType, Signature, StatusOptions};
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

pub mod errors {
    error_chain! {
        errors {}
    }
}

use errors::ResultExt;

// parsing of arguments
const USAGE: &'static str = "
Git Hasher program to generate hash file within git working directory.

Usage:
    git_hasher [--conf=<conf>] [--log=<log>]
    git_hasher addcommit <commit-msg> [--conf=<conf>] [--log=<log>]
    git_hasher (-h | --help)

Options:
    -h --help       Show this help message.
    --conf=<conf>   Config file path [default: git_hasher_config.toml].
    --log=<log>     Log config file path.
";

#[derive(Debug, Deserialize)]
struct ArgConfig {
    flag_conf: String,
    flag_log: Option<String>,
    cmd_addcommit: bool,
    arg_commit_msg: Option<String>,
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

    /// Username to use for addcommit option.
    username: Option<String>,

    /// Email address to use for addcommit option.
    email: Option<String>,
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

fn init_logger(flag_log: &Option<String>) -> errors::Result<()> {
    if let &Some(ref flag_log) = flag_log {
        log4rs::init_file(flag_log, Default::default())
            .chain_err(|| format!("Unable to initialize log4rs logger with the given config file at '{}'", flag_log))?;
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
    let arg_config: ArgConfig = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // let arg_config = ArgConfig::from_args();
    init_logger(&arg_config.flag_log)?;

    let config_str = read_string_from_file(&arg_config.flag_conf)?;

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
    
    let has_changes = if let Some(prev_hash_collection) = prev_hash_collection {
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

            // indicate if the index is different from working tree
            new_entries_count > 0 || deleted_entries_count > 0 || modified_entries_count > 0
        } else {
            // not allowed to proceed
            bail!("Previous hash collection uses method: {}, while current hash collection uses method: {}, which is not comparable",
                prev_hash_collection.meth.to_string(), hash_collection.meth.to_string());
        }
    } else {
        info!("All files in current hash yaml file are NEW");
        info!("Total count: {}", curr_elems.len());

        // indicate if the index is different from working tree
        curr_elems.len() > 0
    };

    // performs possibly additional operations
    if let &Some(ref arg_commit_msg) = &arg_config.arg_commit_msg {
        if arg_commit_msg.is_empty() {
            bail!("Commit message cannot be empty for addcommit operation");
        }

        if !has_changes {
            bail!("No changes found in working tree for addcommit operation");
        }

        let username = config.username.as_ref()
            .ok_or_else(|| format!("No username in '{}' provided for addcommit option", arg_config.flag_conf))?;

        let email = config.email.as_ref()
            .ok_or_else(|| format!("No email address in '{}' provided for addcommit option", arg_config.flag_conf))?;

        let mut index = repo.index()
            .chain_err(|| "Unable to get index of git local repository")?;

        index.add_all(["."].iter(), IndexAddOption::empty(), None)
            .chain_err(|| "Unable to add all files into index for git local repository")?;

        let new_tree_oid = index.write_tree()
            .chain_err(|| "Unable to write tree using the updated index")?;

        let new_tree = repo.find_tree(new_tree_oid)
            .chain_err(|| "Unable to get tree from new OID")?;

        let head_commit = repo.head()
            .chain_err(|| "Unable to get the reference of HEAD")?
            .resolve()
            .chain_err(|| "Unable to resolve the reference of HEAD")?
            .peel(ObjectType::Commit)
            .chain_err(|| "Unable to peel after resolving reference of HEAD")?
            .into_commit()
            .map_err(|_| git2::Error::from_str("Cannot find commit"))
            .chain_err(|| "Unable to convert into commit after peeling")?;

        let author = Signature::now(username, email)
            .chain_err(|| "Unable to create signature")?;

        let committer = author.clone();
        
        let new_commit_oid = repo.commit(
            Some("HEAD"),
            &author,
            &committer,
            arg_commit_msg,
            &new_tree,
            &[&head_commit])
            .chain_err(|| "Unable to perform commit into local git repository")?;

        let new_commit = repo.find_commit(new_commit_oid)
            .chain_err(|| "Unable to find new commit from OID")?;

        repo.reset(new_commit.as_object(), ResetType::Hard, None)
            .chain_err(|| "Unable to reset HEAD to the new commit")?;

        info!("Successfully added and committed new changes!");
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
