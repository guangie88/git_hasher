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
use regex::Regex;
use std::process;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;
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

#[derive(Deserialize, Serialize, new)]
struct HashElement {
    /// Path of git working file (can be untracked).
    path: String,

    /// Hash value of binary content of file.
    hash: String,
}

#[derive(Deserialize, Serialize, new)]
struct HashCollection {
    /// Hash method name.
    meth: Algo,

    /// Collection of hash elements.
    elements: Vec<HashElement>,
}

#[derive(EnumString, Deserialize, Serialize, Debug)]
enum Algo {
    MD5, SHA1, SHA256,
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

    // allows untracked files to be shown
    let mut options = StatusOptions::new();
    options.include_untracked(true);
    options.recurse_untracked_dirs(true);

    let statuses = repo.statuses(Some(&mut options))
        .chain_err(|| format!("Unable to obtain statuses in the local git working directory at '{}'", config.git_path))?;

    let mut filtered_paths: Vec<String> = statuses.iter()
        .filter_map(|s| s.path().map(|p| p.to_owned()))
        .filter(|p| regexes.iter().any(|r| r.is_match(p)))
        .collect();

    filtered_paths.sort();
    let filtered_paths = filtered_paths;
    
    let hash_elems: Vec<HashElement> = filtered_paths.into_iter()
        .map(|p| {
            let buf = file::get(&p);
            buf.map(|buf| HashElement::new(p, crypto_hash::hex_digest(algo.clone(), &buf)))
        })
        .inspect(|res| {
            if let &Err(ref e) = res {
                error!("Unable to read file in git working directory: {}", e);
            }
        })
        .filter_map(|res| res.ok())
        .collect();

    info!("# of matching file(s): {}", hash_elems.len());

    // serialize into file section
    let hash_collection = HashCollection::new(algo_enum, hash_elems);

    let mut hash_file = File::create(&config.hash_path)
        .chain_err(|| format!("Unable to create hash file at '{}'", config.hash_path))?;

    let hash_collection_str = serde_yaml::to_string(&hash_collection)
        .chain_err(|| "Unable to serialize hash collection into TOML")?;

    hash_file.write_all(hash_collection_str.as_bytes())
        .chain_err(|| format!("Unable to write into hash file at '{}'", config.hash_path))?;

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
