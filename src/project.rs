//! Wrap a nix file and manage corresponding state.

use slog::debug;
use thiserror::Error;

use crate::builder::{OutputPath, RootedPath};
use crate::cas::ContentAddressable;
use crate::{AbsPathBuf, NixFile};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// A “project” knows how to handle the lorri state
/// for a given nix file.
#[derive(Clone)]
pub struct Project {
    /// Absolute path to this project’s nix file.
    pub nix_file: NixFile,

    /// Directory in which this project’s
    /// garbage collection roots are stored.
    gc_root_path: AbsPathBuf,

    /// Hash of the nix file’s absolute path.
    hash: String,

    /// Content-addressable store to save static files in
    pub cas: ContentAddressable,
}

impl Project {
    /// Construct a `Project` from nix file path
    /// and the base GC root directory
    /// (as returned by `Paths.gc_root_dir()`),
    pub fn new(
        nix_file: NixFile,
        gc_root_dir: &AbsPathBuf,
        cas: ContentAddressable,
    ) -> std::io::Result<Project> {
        let hash = format!(
            "{:x}",
            md5::compute(nix_file.as_absolute_path().as_os_str().as_bytes())
        );
        let project_gc_root = gc_root_dir.join(&hash).join("gc_root");

        std::fs::create_dir_all(&project_gc_root)?;

        let nix_file_symlink = project_gc_root.clone().join("nix_file");
        let (remove, create) = match std::fs::read_link(&nix_file_symlink) {
            Ok(path) => {
                if path == nix_file.as_absolute_path() {
                    (false, false)
                } else {
                    (true, true)
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    (false, true)
                } else {
                    (true, true)
                }
            }
        };
        if remove {
            std::fs::remove_file(&nix_file_symlink)?;
        }
        if create {
            std::os::unix::fs::symlink(nix_file.as_absolute_path(), nix_file_symlink)?;
        }

        Ok(Project {
            nix_file,
            gc_root_path: project_gc_root,
            hash,
            cas,
        })
    }

    /// Generate a "unique" ID for this project based on its absolute path.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    // final path in the `self.gc_root_path` directory,
    // the symlink which points to the lorri-keep-env-hack-nix-shell drv (see ./logged-evaluation.nix)
    fn shell_gc_root(&self) -> AbsPathBuf {
        self.gc_root_path.join("shell_gc_root")
    }

    /// Return the filesystem paths for these roots.
    pub fn root_paths(&self) -> OutputPath<RootPath> {
        OutputPath {
            shell_gc_root: RootPath(self.shell_gc_root()),
        }
    }

    /// Create roots to store paths.
    pub fn create_roots(
        &self,
        // Important: this intentionally only allows creating
        // roots to `StorePath`, not to `DrvFile`, because we have
        // no use case for creating GC roots for drv files.
        path: RootedPath,
        user: Username,
        logger: &slog::Logger,
    ) -> Result<OutputPath<RootPath>, AddRootError>
where {
        let store_path = &path.path;

        debug!(logger, "adding root"; "from" => store_path.as_path().to_str(), "to" => self.shell_gc_root().display());
        std::fs::remove_file(&self.shell_gc_root())
            .or_else(|e| AddRootError::remove(e, &self.shell_gc_root().as_path()))?;

        // the forward GC root that points from the store path to our cache gc_roots dir
        std::os::unix::fs::symlink(store_path.as_path(), &self.shell_gc_root()).map_err(|e| {
            AddRootError::symlink(e, store_path.as_path(), self.shell_gc_root().as_path())
        })?;

        // the reverse GC root that points from nix to our cache gc_roots dir
        // TODO: check nix state dir at startup, like USER.
        let nix_var_nix = || AbsPathBuf::new_unchecked(PathBuf::from("/nix/var/nix/"));
        let nix_gc_root_user_dir = std::env::var_os("NIX_STATE_DIR")
            .map_or_else(
                || Ok(nix_var_nix()),
                |path| AbsPathBuf::new(PathBuf::from(path)),
            )
            .unwrap_or_else(|_pb| nix_var_nix())
            .join(PathBuf::from("gcroots/per-user"))
            .join(user.0);

        // The user directory sometimes doesn’t exist,
        // but we can create it (it’s root but `rwxrwxrwx`)
        if !nix_gc_root_user_dir.as_path().is_dir() {
            std::fs::create_dir_all(&nix_gc_root_user_dir.as_path()).map_err(|source| {
                AddRootError {
                    source,
                    msg: format!(
                        "Failed to create missing nix user gc directory: {}",
                        nix_gc_root_user_dir.display()
                    ),
                }
            })?
        }

        // We register a garbage collection root, which points back to our `~/.cache/lorri/gc_roots` directory,
        // so that nix won’t delete our shell environment.
        let nix_gc_root_user_dir_root =
            nix_gc_root_user_dir.join(format!("{}-shell_gc_root", self.hash()));

        debug!(logger, "connecting root"; "from" => self.shell_gc_root().display(), "to" => nix_gc_root_user_dir_root.display());
        std::fs::remove_file(&nix_gc_root_user_dir_root.as_path())
            .or_else(|err| AddRootError::remove(err, &nix_gc_root_user_dir_root.as_path()))?;

        std::os::unix::fs::symlink(&self.shell_gc_root(), &nix_gc_root_user_dir_root.as_path())
            .map_err(|e| {
                AddRootError::symlink(
                    e,
                    self.shell_gc_root().as_path(),
                    &nix_gc_root_user_dir_root.as_path(),
                )
            })?;

        // TODO: don’t return the RootPath here
        Ok(OutputPath {
            shell_gc_root: RootPath(self.shell_gc_root()),
        })
    }
}

/// A path to a gc root.
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct RootPath(pub AbsPathBuf);

impl RootPath {
    /// `display` the path.
    pub fn display(&self) -> std::path::Display {
        self.0.display()
    }
}

impl OutputPath<RootPath> {
    /// Check whether all all GC roots exist.
    pub fn all_exist(&self) -> bool {
        let crate::builder::OutputPath { shell_gc_root } = self;

        shell_gc_root.0.as_path().exists()
    }
}

/// Username of the logged in (OS) user.
#[derive(Clone)]
pub struct Username(OsString);

impl Username {
    /// Read the username from the `USER` env var.
    pub fn from_env_var() -> anyhow::Result<Username> {
        std::env::var_os("USER")
            .ok_or_else(|| anyhow::anyhow!("Environment variable 'USER' must be set"))
            .map(Username)
    }
}

/// Error conditions encountered when adding roots
#[derive(Error, Debug)]
#[error("{msg}: {source}")]
pub struct AddRootError {
    #[source]
    source: std::io::Error,
    msg: String,
}

impl AddRootError {
    /// Ignore NotFound errors (it is after all a remove), and otherwise
    /// return an error explaining a delete on path failed.
    fn remove(source: std::io::Error, path: &Path) -> Result<(), AddRootError> {
        if source.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(AddRootError {
                source,
                msg: format!("Failed to delete {}", path.display()),
            })
        }
    }

    /// Return an error explaining what symlink failed
    fn symlink(source: std::io::Error, src: &Path, dest: &Path) -> AddRootError {
        AddRootError {
            source,
            msg: format!("Failed to symlink {} to {}", src.display(), dest.display()),
        }
    }
}
