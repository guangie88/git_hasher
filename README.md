# git_hasher

## Overview
Hashing program that works in a git working directory to generate MD5, SHA1 or SHA256 hashes for all files in the working directory based on `.gitignore`. Also contains very basic git operations like `init` and `addcommit`. Works on Linux and Windows and for testing purposes only.

[![Build Status](https://travis-ci.org/guangie88/git_hasher.svg?branch=master)](https://travis-ci.org/guangie88/git_hasher)
[![Build status](https://ci.appveyor.com/api/projects/status/ww8imshqnohgah9m?svg=true)](https://ci.appveyor.com/project/guangie88/git-hasher)

## Run Examples
All the commands below are run in Linux bash, and assumes that the executable `git_hasher` and its configuration file `git_hasher_config.toml` are placed in the same directory.

### Working directory initialization
```rust
./git_hasher init
```
Equivalent to `git init`.

### Hash and create file
```rust
./git_hasher hash
```
Generates the hash file `hash.yaml` which contains all the hashes. The hashing is applied to all files after filtering by `.gitignore`, and additional whitelist regular expression filter(s) based on field `regex_matches` found in `git_hasher_config.toml`. Additionally, the name of the generated hash file can be changed in the `git_hasher_config.toml`, and the type of hashing method (i.e. MD5, SHA1 or SHA256) can also be changed.

### Add all files and commit
```rust
./git_hasher addcommit "Commit message"
```
Equivalent to `git add . && git commit -m "Commit message"`. It is noteworthy that if `git_hasher` is part of the `git` index to be committed, the `git` reset to checkout all the files after the new commit will fail because `git_hasher` would be in use. However, the commit should be successful and it should be okay to just run `git reset --hard` to retry getting back all the files after the new commit.

## Notes
Technically, only `./git_hasher hash` is the useful command, since the other commands can be done via basic `git` commands. The other commands are there to close the loop of being able to initialize, create and commit into the local git repository, in the event that that `git` program is not present especially in Windows environment.