//! # lorri
//! lorri is a wrapper over Nix to abstract project-specific build
//! configuration and patterns in to a declarative configuration.

#![warn(missing_docs)]
// We usually want to use matches for clarity
#![allow(clippy::match_bool)]
#![allow(clippy::single_match)]
// I don’t think return, .into() is clearer than ?, sorry
#![allow(clippy::try_err)]
// triggered by select (TODO: fixed in crossbeam_channel 0.5)
#![allow(dropping_copy_types, clippy::zero_ptr)]

#[macro_use]
extern crate structopt;
#[macro_use]
extern crate serde_derive;

pub mod build_loop;
pub mod builder;
pub mod cas;
pub mod changelog;
pub mod cli;
pub mod constants;
pub mod daemon;
pub mod logging;
pub mod nix;
pub mod ops;
pub mod osstrlines;
pub mod pathreduction;
pub mod project;
pub mod run_async;
pub mod socket;
pub mod sqlite;
pub mod thread;
pub mod watch;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

// OUT_DIR and build_rev.rs are generated by cargo, see ../build.rs
include!(concat!(env!("OUT_DIR"), "/build_rev.rs"));

/// Path guaranteed to be absolute by construction.
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct AbsPathBuf(PathBuf);

impl AbsPathBuf {
    /// Convert from a path to an absolute path.
    ///
    /// If the path is not absolute, the original `PathBuf`
    /// is returned (similar to `OsString.into_string()`)
    pub fn new(path: PathBuf) -> Result<Self, PathBuf> {
        if path.is_absolute() {
            Ok(Self::new_unchecked_normalized(&path))
        } else {
            Err(path)
        }
    }

    /// Checks if `file` exists
    ///
    /// - in the current directory if a relative path
    /// - or at the given absolute path
    ///
    /// If it doesn’t exist, returns `None`.
    /// If it exists, returns its absolute path.
    ///
    /// `Err` if current directory can’t be found.
    pub fn new_from_current_directory(filepath: &Path) -> anyhow::Result<Option<AbsPathBuf>> {
        let path = AbsPathBuf::new(std::env::current_dir()?)
            .unwrap_or_else(|orig| {
                panic!(
                    "Expected `env::current_dir` to return an absolute path, but was {}",
                    orig.display()
                )
            })
            .join(filepath);
        Ok(if path.as_path().is_file() {
            Some(path)
        } else {
            None
        })
    }

    /// Convert from a known absolute path.
    ///
    /// Passing a relative path is a programming bug (unchecked).
    pub fn new_unchecked(path: &PathBuf) -> Self {
        Self::new_unchecked_normalized(path)
    }

    fn new_unchecked_normalized(path: &Path) -> Self {
        let mut normalized = PathBuf::new();
        // I didn’t find a better way to normalize a path (remove double `/` and `/./` and the like)
        for c in path.components() {
            normalized.push(c)
        }
        AbsPathBuf(normalized)
    }

    /// The absolute path, as `&Path`.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Proxy through the `Display` class for `PathBuf`.
    pub fn display(&self) -> std::path::Display {
        self.0.display()
    }

    /// Print a path to a json string, assuming it is UTF-8, converting any non-utf codeblocks to replacement characters
    pub fn to_json_value(&self) -> serde_json::Value {
        path_to_json_string(self.0.as_path())
    }

    /// Joins a path to the end of this absolute path.
    /// If the path is absolute, it will replace this absolute path.
    pub fn join<P: AsRef<Path>>(&self, pb: P) -> Self {
        let mut new = self.0.to_owned();
        new.push(pb);
        Self::new_unchecked_normalized(&new)
    }

    /// Proxy through `with_file_name` for `PathBuf`
    pub fn with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Self {
        // replacing the file name will never make the path relative
        Self::new_unchecked_normalized(&self.0.with_file_name(file_name))
    }
}

impl AsRef<Path> for AbsPathBuf {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

/// A .nix file.
///
/// Is guaranteed to have an absolute path by construction. We normalize its path, but do not resolve symlinks.
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct NixFile(AbsPathBuf);

impl NixFile {
    /// Absolute path of this file.
    pub fn as_absolute_path(&self) -> &Path {
        self.0.as_path()
    }

    /// `display` the path.
    pub fn display(&self) -> std::path::Display {
        self.0.display()
    }

    /// Print a path to a json string, assuming it is UTF-8, converting any non-utf codeblocks to replacement characters
    pub fn to_json_value(&self) -> serde_json::Value {
        path_to_json_string(self.0.as_path())
    }
}

/// Print a path to a json string, assuming it is UTF-8, converting any non-utf codeblocks to replacement characters
fn path_to_json_string(p: &Path) -> serde_json::Value {
    let s = p.as_os_str().to_string_lossy().into_owned();
    serde_json::json!(s)
}

impl From<AbsPathBuf> for NixFile {
    fn from(abs_path: AbsPathBuf) -> Self {
        NixFile(abs_path)
    }
}

impl slog::Value for NixFile {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self.as_absolute_path().display()))
    }
}

/// A .drv file (generated by `nix-instantiate`).
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct DrvFile(PathBuf);

impl DrvFile {
    /// Underlying `Path`.
    pub fn as_path(&self) -> &Path {
        self.0.as_ref()
    }
}

impl From<PathBuf> for DrvFile {
    fn from(p: PathBuf) -> DrvFile {
        DrvFile(p)
    }
}

/// Struct that will never be constructed (no elements).
/// In newer rustc, this corresponds to the (compiler supported) `!` type.
pub struct Never {}

impl Never {
    /// This will never be called, so we can return anything.
    pub fn never<T>(&self) -> T {
        panic!("can never be called");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn abs_path_buf_normalizes() {
        assert_eq!(
            AbsPathBuf::new_unchecked(&PathBuf::from("/a//b/./c/.///de"))
                .as_path()
                .to_str(),
            Some("/a/b/c/de"),
            "dots and double slashes are removed"
        );
        assert_eq!(
            AbsPathBuf::new_unchecked(&PathBuf::from("/a//b/../c/.///de"))
                .as_path()
                .to_str(),
            Some("/a/b/../c/de"),
            "parent .. is not removed, because it could lead to somewhere different after symlinks are resolved"
        )
    }

    #[test]
    fn test_locate_config_file() {
        let mut path = PathBuf::from("shell.nix");
        let result = AbsPathBuf::new_from_current_directory(&path);
        assert_eq!(
            result
                .unwrap()
                .expect("Should find the shell.nix in this projects' root"),
            AbsPathBuf::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")))
                .unwrap()
                .join("shell.nix")
        );
        path.pop();
        path.push("this-lorri-specific-file-probably-does-not-exist");
        assert_eq!(None, AbsPathBuf::new_from_current_directory(&path).unwrap());
    }
}
