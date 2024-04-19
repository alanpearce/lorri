//! Wrap a nix file and manage corresponding state.

use slog::debug;
use thiserror::Error;

use crate::builder::{OutputPath, RootedPath};
use crate::constants::Paths;
use crate::ops::error::ExitError;
use crate::{AbsPathBuf, NixFile};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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
}

impl Project {
    /// Construct a `Project` from nix file path
    /// and the base GC root directory
    /// (as returned by `Paths.gc_root_dir()`),
    pub fn new_and_gc_nix_files(
        nix_file: NixFile,
        gc_root_dir: &AbsPathBuf,
    ) -> std::io::Result<Project> {
        let p = Self::new_internal(nix_file.clone(), gc_root_dir)?;

        // Adjust the nix_file symlink to point to this project’s nix file

        let nix_file_symlink = p.nix_file();
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
            std::os::unix::fs::symlink(nix_file.as_absolute_path(), &nix_file_symlink)?;
        }

        Ok(p)
    }

    fn new_internal(nix_file: NixFile, gc_root_dir: &AbsPathBuf) -> std::io::Result<Project> {
        let hash = format!(
            "{:x}",
            md5::compute(nix_file.as_absolute_path().as_os_str().as_bytes())
        );
        let project_gc_root = gc_root_dir.join(&hash).join("gc_root");

        std::fs::create_dir_all(&project_gc_root)?;

        Ok(Project {
            nix_file,
            gc_root_path: project_gc_root,
            hash,
        })
    }

    /// Generate a "unique" ID for this project based on its absolute path.
    fn hash(&self) -> &str {
        &self.hash
    }

    /// final path in the `self.gc_root_path` directory,
    /// the symlink which points to the lorri-keep-env-hack-nix-shell drv (see ./logged-evaluation.nix)
    fn shell_gc_root(&self) -> AbsPathBuf {
        self.gc_root_path.join("shell_gc_root")
    }

    /// A symlink from our gc_root_path directory back to the nix file which created this project.
    /// Used to implement garbage collection.
    fn nix_file(&self) -> AbsPathBuf {
        self.gc_root_path.join("nix_file")
    }

    /// Return the filesystem paths for these roots.
    pub fn root_path(&self) -> OutputPath {
        OutputPath::new(RootPath(self.shell_gc_root()))
    }

    /// Create roots to store paths.
    pub fn create_roots(
        &self,
        // Important: this intentionally only allows creating
        // roots to `StorePath`, not to `DrvFile`, because we have
        // no use case for creating GC roots for drv files.
        path: RootedPath,
        nix_gc_root_user_dir: NixGcRootUserDir,
        logger: &slog::Logger,
    ) -> Result<OutputPath, AddRootError>
where {
        let store_path = &path.path;

        debug!(logger, "adding root"; "from" => store_path.as_path().to_str(), "to" => self.shell_gc_root().display());
        std::fs::remove_file(self.shell_gc_root())
            .or_else(|e| AddRootError::remove(e, self.shell_gc_root().as_path()))?;

        // the forward GC root that points from the store path to our cache gc_roots dir
        std::os::unix::fs::symlink(store_path.as_path(), self.shell_gc_root()).map_err(|e| {
            AddRootError::symlink(e, store_path.as_path(), self.shell_gc_root().as_path())
        })?;

        // the reverse GC root that points from nix to our cache gc_roots dir

        // We register a garbage collection root, which points back to our `~/.cache/lorri/gc_roots` directory,
        // so that nix won’t delete our shell environment.
        let nix_gc_root_user_dir_root =
            nix_gc_root_user_dir
                .0
                .join(format!("{}-{}", self.hash(), "shell_gc_root"));

        debug!(logger, "connecting root"; "from" => self.shell_gc_root().display(), "to" => nix_gc_root_user_dir_root.display());
        std::fs::remove_file(nix_gc_root_user_dir_root.as_path())
            .or_else(|err| AddRootError::remove(err, nix_gc_root_user_dir_root.as_path()))?;

        std::os::unix::fs::symlink(self.shell_gc_root(), nix_gc_root_user_dir_root.as_path())
            .map_err(|e| {
                AddRootError::symlink(
                    e,
                    self.shell_gc_root().as_path(),
                    nix_gc_root_user_dir_root.as_path(),
                )
            })?;

        Ok(OutputPath::new(RootPath(self.shell_gc_root())))
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

/// Username of the logged in (OS) user.
#[derive(Clone)]
pub struct Username(OsString);

impl Username {
    /// Read the username from the `USER` env var.
    pub fn from_env_var() -> anyhow::Result<Username> {
        std::env::var_os("USER")
            .ok_or_else(|| anyhow::anyhow!(r##"Environment variable 'USER' must be set"##))
            .map(Username)
    }
}

/** `/nix/var/nix/gcroots/per-user/<username>` */
#[derive(Clone)]
pub struct NixGcRootUserDir(AbsPathBuf);

impl NixGcRootUserDir {
    /// Try to create the user gcroot directory, or throw a useful error message.
    pub fn get_or_create(username: &Username) -> Result<Self, ExitError> {
        let nix_var_nix = || AbsPathBuf::new_unchecked(&PathBuf::from("/nix/var/nix/"));

        let nix_gc_root_user_dir_root = std::env::var_os("NIX_STATE_DIR")
            .map_or_else(
                || Ok(nix_var_nix()),
                |path| AbsPathBuf::new(PathBuf::from(path)),
            )
            .unwrap_or_else(|_pb| nix_var_nix())
            .join(PathBuf::from("gcroots/per-user"));
        let nix_gc_root_user_dir = nix_gc_root_user_dir_root.join(&username.0);

        // The user directory sometimes doesn’t exist,
        // but we can create it for older nix versions (it’s root but `rwxrwxrwx`)
        // Newer nix versions make the directory `rwxr-xr-x`, meaning we need the user to intervene.
        if !nix_gc_root_user_dir.as_path().is_dir() {
            // check whether we are allowed to create the directory
            let st_mode = unsafe {
                let mut stat = std::mem::MaybeUninit::<nix::libc::stat>::uninit();
                let path = CString::new(nix_gc_root_user_dir_root.as_path().as_os_str().as_bytes())
                    .unwrap();

                if 0 != nix::libc::stat(path.as_ptr(), stat.as_mut_ptr()) {
                    Err(
                        ExitError::panic(anyhow::Error::new(std::io::Error::last_os_error()).context(format!("Cannot stat user roots directory for permission to create a new lorri user dir: {}", nix_gc_root_user_dir_root.display())) ))?;
                }
                stat.assume_init().st_mode
            };

            if 0 != (st_mode & nix::libc::S_IWOTH) {
                std::fs::create_dir_all(nix_gc_root_user_dir.as_path()).map_err(|source| {
                    ExitError::panic(anyhow::Error::new(source).context(format!(
                        "Failed to create missing nix user gc directory: {}",
                        nix_gc_root_user_dir.display()
                    )))
                })?;
            } else {
                Err(ExitError::environment_problem(anyhow::Error::msg(format!(
                    r###"
We cannot create a user dir for your user account in {}, because newer nix versions require sudo for this.

Please run the following commands once to set up lorri:
```
$ sudo mkdir {}
$ sudo chown {} {}
```
"###,
                    nix_gc_root_user_dir_root.display(),
                    nix_gc_root_user_dir.display(),
                    &username.0.clone().to_string_lossy(),
                    nix_gc_root_user_dir.display()
                ))))?
            }
        }
        Ok(Self(nix_gc_root_user_dir))
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

/// Represents a gc root along with some metadata, used for json output of lorri gc info
pub struct GcRootInfo {
    /// directory where root is stored
    pub gc_dir: AbsPathBuf,
    /// nix file from which the root originates. If None, then the root is considered dead.
    pub nix_file: Option<PathBuf>,
    /// timestamp of the last build
    pub timestamp: SystemTime,
    /// whether `nix_file` still exists
    pub alive: bool,
}

impl GcRootInfo {
    /// Format for printing to stdout
    pub fn format_pretty_oneline(&self) -> String {
        let target = match &self.nix_file {
            Some(p) => p.display().to_string(),
            None => "(?)".to_owned(),
        };
        let age = match self.timestamp.elapsed() {
            Err(_) => "future".to_owned(),
            Ok(d) => {
                let days = d.as_secs() / (24 * 60 * 60);
                format!("{} days ago", days)
            }
        };
        let alive = if self.alive { "" } else { "[dead]" };
        format!(
            "{} -> {} {} ({})",
            self.gc_dir.display(),
            target,
            alive,
            age
        )
    }
}

/// Returns a list of existing gc roots along with some metadata
pub fn list_roots(logger: &slog::Logger, paths: &Paths) -> Result<Vec<GcRootInfo>, ExitError> {
    let mut res = Vec::new();
    let gc_root_dir = paths.gc_root_dir();
    for entry in std::fs::read_dir(gc_root_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            debug!(
                logger,
                "Skipping {} which should be a directory",
                entry.path().display()
            );
            continue;
        }
        let gc_dir = AbsPathBuf::new(entry.path()).expect("entry.path() should always be absolute");
        let gc_root_dir = gc_dir.join("gc_root");
        if !std::fs::metadata(&gc_root_dir).map_or(false, |m| m.is_dir()) {
            debug!(
                logger,
                "Skipping {} which should be a directory",
                gc_root_dir.display()
            );
            continue;
        };
        let timestamp = match std::fs::symlink_metadata(gc_root_dir.join("shell_gc_root")) {
            Err(_) => {
                // no gc root, so nothing to report
                continue;
            }
            Ok(m) => m.modified().unwrap_or(std::time::UNIX_EPOCH),
        };
        let nix_file_symlink = gc_root_dir.join("nix_file");
        let nix_file = std::fs::read_link(&nix_file_symlink);
        let alive = match &nix_file {
            Err(_) => false,
            Ok(path) => match std::fs::metadata(path) {
                Ok(m) => m.is_file(),
                Err(_) => false,
            },
        };
        let nix_file = match nix_file {
            Err(_) => None,
            Ok(p) => Some(p),
        };
        res.push(GcRootInfo {
            gc_dir,
            nix_file,
            timestamp,
            alive,
        });
    }
    Ok(res)
}
