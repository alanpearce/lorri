//! Ops are command-line callables.

mod direnv;
pub mod error;

use crate::build_loop::BuildLoop;
use crate::build_loop::Event;
use crate::build_loop::Reason;
use crate::builder::OutputPath;
use crate::cas::ContentAddressable;
use crate::changelog;
use crate::cli;
use crate::cli::ShellOptions;
use crate::cli::StartUserShellOptions_;
use crate::cli::WatchOptions;
use crate::constants::Paths;
use crate::daemon::client::{self, DaemonInfo};
use crate::daemon::Daemon;
use crate::nix;
use crate::nix::options::NixOptions;
use crate::nix::CallOpts;
use crate::ops::direnv::{DirenvVersion, MIN_DIRENV_VERSION};
use crate::ops::error::{ExitAs, ExitError, ExitErrorType};
use crate::path_to_json_string;
use crate::project::GcRootInfo;
use crate::project::{NixGcRootUserDir, Project};
use crate::run_async::Async;
use crate::socket::path::SocketPath;
use crate::sqlite::Sqlite;
use crate::NixFile;
use crate::VERSION_BUILD_REV;
use crate::{builder, project};

use std::ffi::OsStr;
use std::fmt::Debug;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use std::{collections::HashSet, fs::File};
use std::{env, fs, io};

use anyhow::Context;
use crossbeam_channel as chan;

use itertools::Itertools;
use serde_json::json;
use slog::{debug, info, warn};
use thiserror::Error;

/// `./trivial-shell.nix`
pub const TRIVIAL_SHELL_SRC: &str = include_str!("./trivial-shell.nix");
/// `./default-envrc`
pub const DEFAULT_ENVRC: &str = include_str!("./default-envrc");

/// Set up necessary directories or fail.
pub fn get_paths() -> Result<crate::constants::Paths, error::ExitError> {
    crate::constants::Paths::initialize().map_err(|e| {
        error::ExitError::user_error(
            anyhow::Error::new(e).context("Cannot initialize the lorri paths"),
        )
    })
}

/// Run a BuildLoop for `shell.nix`, watching for input file changes.
/// Can be used together with `direnv`.

/// See the documentation for lorri::cli::Command::Daemon for details.
pub fn op_daemon(opts: crate::cli::DaemonOptions, logger: &slog::Logger) -> Result<(), ExitError> {
    let extra_nix_options = match opts.extra_nix_options {
        None => NixOptions::empty(),
        Some(v) => NixOptions {
            builders: v.builders,
            substituters: v.substituters,
        },
    };

    let username = project::Username::from_env_var().map_err(ExitError::environment_problem)?;
    let nix_gc_root_user_dir = project::NixGcRootUserDir::get_or_create(&username)?;

    let (mut daemon, build_rx) = Daemon::new(extra_nix_options);
    let logger2 = logger.clone();
    let build_handle = std::thread::spawn(move || {
        for msg in build_rx {
            info!(logger2, "build status"; "message" => ?msg);
        }
    });
    info!(logger, "ready");

    let paths = crate::ops::get_paths()?;
    daemon.serve(
        &SocketPath::from(paths.daemon_socket_file().clone()),
        &paths.sqlite_db,
        paths.gc_root_dir(),
        paths.cas_store().clone(),
        nix_gc_root_user_dir,
        logger,
    )?;
    build_handle
        .join()
        .expect("failed to join build status thread");
    Ok(())
}

/// Emit shell script intended to be evaluated as part of direnv's .envrc
///
/// See the documentation for lorri::cli::Command::Direnv for more
/// details.
pub fn op_direnv<W: std::io::Write>(
    project: Project,
    paths: &Paths,
    mut shell_output: W,
    logger: &slog::Logger,
) -> Result<(), ExitError> {
    check_direnv_version()?;

    let root_paths = project.root_path();
    let paths_are_cached: bool = root_paths.exists();

    let ping_sent = {
        let address = crate::ops::get_paths()?.daemon_socket_file().clone();
        debug!(logger, "connecting to socket"; "socket" => address.as_path().display());
        client::create::<client::Ping>(paths, client::Timeout::from_millis(500), logger)
            .map_err(ExitError::from)
            .and_then(|c| {
                c.write(&client::Ping {
                    nix_file: project.nix_file,
                    rebuild: client::Rebuild::OnlyIfNotYetWatching,
                })?;
                Ok(())
            })
            // TODO: maybe ping should indeed return something so we can at least check whether it parses the message and the version is right. Right now this collapses all of that into a bool …
            .is_ok()
    };

    match (ping_sent, paths_are_cached) {
        (true, true) => {}

        // Ping sent & paths aren't cached: once the environment is created
        // the direnv environment will be updated automatically.
        (true, false) =>
            info!(
                logger,
                "lorri has not completed an evaluation for this project yet"
            ),

        // Ping not sent and paths are cached: we can load a stale environment
        // When the daemon is started, we'll send a fresh ping.
        (false, true) =>
            info!(
                logger,
                "lorri daemon is not running, loading a cached environment"
            ),

        // Ping not sent and paths are not cached: we can't load anything,
        // but when the daemon in started we'll send a ping and eventually
        // load a fresh environment.
        (false, false) =>
            warn!(logger, "lorri daemon is not running and this project has not yet been evaluated, please run `lorri daemon`"),
    }

    // direnv interprets stdout as a script that it evaluates. That is why (1) the logger for
    // `lorri direnv` outputs to stderr by default (to avoid corrupting the script) and (2) we
    // can't use the stderr logger here.
    // In production code, `shell_output` will be stdout so direnv can interpret the output.
    // `shell_output` is an argument so that testing code can inject a different `std::io::Write`
    // in order to inspect the output.
    writeln!(
        shell_output,
        r#"
EVALUATION_ROOT="{}"

watch_file "{}"
watch_file "$EVALUATION_ROOT"

{}"#,
        root_paths.display_shell_gc_root(),
        crate::ops::get_paths()?
            .daemon_socket_file()
            .as_path()
            .to_str()
            .expect("Socket path is not UTF-8 clean!"),
        include_str!("./ops/direnv/envrc.bash")
    )
    .expect("failed to write shell output");

    // direnv provides us with an environment variable if we are inside of its envrc execution.
    // Thus we can show a warning if the user runs it on their command line.
    if std::env::var("DIRENV_IN_ENVRC") != Ok("1".to_string()) {
        warn!(logger, "`lorri direnv` should be executed by direnv from within an `.envrc` file. Run `lorri init` to get started.")
    }

    Ok(())
}

/// Checks `direnv version` against the minimal version lorri requires.
fn check_direnv_version() -> Result<(), ExitError> {
    let out = with_command("direnv", |mut cmd| cmd.arg("version").output())?;
    let version = std::str::from_utf8(&out.stdout)
        .map_err(|_| ())
        .and_then(|utf| utf.trim_end().parse::<DirenvVersion>())
        .map_err(|()| {
            ExitError::environment_problem(anyhow::anyhow!(
                "Could not figure out the current `direnv` version (parse error)"
            ))
        })?;
    if version < MIN_DIRENV_VERSION {
        Err(ExitError::environment_problem(anyhow::anyhow!(
            "`direnv` is version {}, but >= {} is required for lorri to function",
            version,
            MIN_DIRENV_VERSION
        )))
    } else {
        Ok(())
    }
}

/// constructs a `Command` out of `executable`
/// Recognizes the case in which the executable is missing,
/// and converts it to a corresponding `ExitError`.
fn with_command<T, F>(executable: &str, cmd: F) -> Result<T, ExitError>
where
    F: FnOnce(Command) -> std::io::Result<T>,
{
    let res = cmd(Command::new(executable));
    res.map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => {
            ExitError::missing_executable(anyhow::anyhow!("`{}`: executable not found", executable))
        }
        _ => ExitError::temporary(
            anyhow::Error::new(err).context(format!("Could not start `{}`", executable)),
        ),
    })
}

/// The info callable is for printing
///
/// See the documentation for lorri::cli::Command::Info for more
/// details.
pub fn op_info(paths: &Paths, project: Project, logger: &slog::Logger) -> Result<(), ExitError> {
    let root_path = project.root_path();
    let daemon_status =
        match client::create::<client::DaemonInfo>(paths, client::Timeout::from_millis(50), logger)
        {
            Err(init_error) => format!("`lorri daemon` is not up: {}", init_error),
            Ok(client) => match client.comunicate(&DaemonInfo {}) {
                Ok(()) => "`lorri daemon` is running".to_string(),
                Err(err) => format!("Problem connecting to the `lorri daemon`: {}", err),
            },
        };

    let gc_root = if root_path.exists() {
        format!("{}", root_path.display_shell_gc_root())
    } else {
        "GC roots do not exist. Has the project been built with lorri yet?".to_string()
    };

    print!(
        "\
Project Shell File: {}
Project Garbage Collector Root: {}

General:
Lorri User GC Root Dir: {}
Lorri Daemon Socket: {}
Lorri Daemon Status: {}
",
        project.nix_file.display(),
        gc_root,
        paths.gc_root_dir().display(),
        paths.daemon_socket_file().display(),
        daemon_status
    );

    Ok(())
}

/// Bootstrap a new lorri project
///
/// See the documentation for lorri::cli::Command::Init for
/// more details
pub fn op_init(logger: &slog::Logger) -> Result<(), ExitError> {
    create_if_missing(
        Path::new("./shell.nix"),
        TRIVIAL_SHELL_SRC,
        "Make sure shell.nix is of a form that works with nix-shell.",
        logger,
    )
    .map_err(ExitError::user_error)?;

    create_if_missing(
        Path::new("./.envrc"),
        DEFAULT_ENVRC,
        &format!("Please add the following code to the top of your .envrc to set up lorri support (with fallback for plain nix):\n```bash\n{}```\n.", DEFAULT_ENVRC),
        logger,
    )
    .map_err(ExitError::user_error)?;

    info!(logger, "done");
    Ok(())
}

fn create_if_missing(
    path: &Path,
    contents: &str,
    msg: &str,
    logger: &slog::Logger,
) -> Result<(), io::Error> {
    if path.exists() {
        info!(logger, "file {} already exists, skipping", path.display(); "path" => path.to_str(), "message" => msg);
        Ok(())
    } else {
        let mut f = File::create(path)?;
        f.write_all(contents.as_bytes())?;
        info!(logger, "wrote file"; "path" => path.to_str());
        Ok(())
    }
}

/// Run a BuildLoop for `shell.nix`, watching for input file changes.
///
/// Can be used together with `direnv`.
/// See the documentation for lorri::cli::Command::Ping_ for details.
pub fn op_ping(paths: &Paths, nix_file: NixFile, logger: &slog::Logger) -> Result<(), ExitError> {
    client::create(paths, client::Timeout::from_millis(500), logger)?.write(&client::Ping {
        nix_file,
        rebuild: client::Rebuild::Always,
    })?;
    Ok(())
}

/// Open up a project shell
///
/// This is the entry point for the `lorri shell` command.
///
/// # Overview
///
/// `lorri shell` launches the user's shell with the project environment set up. "The user's shell"
/// here just means whatever binary $SHELL points to. Concretely we get the following process tree:
///
/// `lorri shell`
/// ├── builds the project environment if --cached is false
/// ├── writes a bash init script that loads the project environment
/// ├── SPAWNS bash with the init script as its `--rcfile`
/// │   └── EXECS `lorri internal start-user-shell`
/// │       ├── (*) performs shell-specific setup for $SHELL
/// │       └── EXECS into user shell $SHELL
/// │           └── interactive user shell
/// └── `lorri shell` terminates
///
/// This setup allows lorri to support almost any shell with minimal additional work. Only the step
/// marked (*) must be adjusted, and only in case we want to customize the shell, e.g. changing the
/// way the prompt looks.
pub fn op_shell(
    project: Project,
    cas: &ContentAddressable,
    opts: ShellOptions,
    logger: &slog::Logger,
) -> Result<(), ExitError> {
    let lorri = env::current_exe()
        .with_context(|| "failed to determine lorri executable's path")
        .map_err(ExitError::environment_problem)?;
    let shell = env::var_os("SHELL").ok_or_else(|| {
        ExitError::environment_problem(anyhow::anyhow!(
            "`lorri shell` requires the `SHELL` environment variable to be set"
        ))
    })?;
    let username = project::Username::from_env_var().map_err(ExitError::environment_problem)?;
    let nix_gc_root_user_dir = project::NixGcRootUserDir::get_or_create(&username)?;
    let cached = {
        if !project.root_path().exists() {
            Err(ExitError::temporary(anyhow::anyhow!(
                "project has not previously been built successfully",
            )))
        } else {
            Ok(project.root_path())
        }
    };
    let mut bash_cmd = bash_cmd(
        if opts.cached {
            cached?
        } else {
            build_root(&project, cached.is_ok(), nix_gc_root_user_dir, cas, logger)?
        },
        cas,
        logger,
    )?;

    debug!(logger, "bash_cmd : {:?}", bash_cmd);
    let status = bash_cmd
        .args([
            OsStr::new("-c"),
            OsStr::new(
                "exec \"$1\" internal start-user-shell --shell-path=\"$2\" --shell-file=\"$3\"",
            ),
            OsStr::new("--"),
            &lorri.as_os_str(),
            &shell,
            project.nix_file.as_absolute_path().as_os_str(),
        ])
        .status()
        .expect("failed to execute bash");

    if !status.success() {
        Err(ExitError::panic(anyhow::anyhow!(
            "cannot run lorri shell: failed to execute internal shell command (error: {})",
            status
        )))
    } else {
        Ok(())
    }
}

fn build_root(
    project: &Project,
    cached: bool,
    nix_gc_root_user_dir: NixGcRootUserDir,
    cas: &ContentAddressable,
    logger: &slog::Logger,
) -> Result<OutputPath, ExitError> {
    let logger2 = logger.clone();
    let project2 = project.clone();
    let cas2 = cas.clone();

    let run_result = crate::thread::race(
        logger,
        move |_ignored_stop| {
            Ok(builder::instantiate_and_build(
                &project2.nix_file,
                &cas2,
                &crate::nix::options::NixOptions::empty(),
                &logger2,
            ))
        },
        // display a a progress bar on stderr while the shell is loading
        move |stop| {
            // Keep track of the start time to display a hint to the user that they can use `--cached`,
            // but only if a cached version of the environment exists
            let hint_time = Instant::now() + Duration::from_secs(3);
            eprint!("lorri: building environment");
            loop {
                let now = Instant::now();

                let show_hint_after = if cached && hint_time > now {
                    chan::after(hint_time - now)
                } else {
                    chan::never()
                };

                chan::select!(
                    recv(stop) -> stop => {
                        eprintln!(". done");
                        return Err(stop.unwrap());
                    },
                    recv(show_hint_after) -> _ => {
                        eprintln!(
                            "\nHint: you can use `lorri shell --cached` to use the most recent \
                             environment that was built successfully."
                        );
                    },
                    recv(chan::after(Duration::from_millis(500))) -> _ => {
                    // Indicate progress
                    eprint!(".");
                    io::stderr().flush().expect("couldn’t flush‽");
                                    }
                );
            }
        },
    );

    let run_result = run_result
        .map_err(|e| {
            if cached {
                ExitError::temporary(anyhow::anyhow!(
                    "Build failed. Hint: try running `lorri shell --cached` to use the most \
                     recent environment that was built successfully.\n\
                     Build error: {}",
                    e
                ))
            } else {
                ExitError::temporary(anyhow::anyhow!(
                    "Build failed. No cached environment available.\n\
                     Build error: {}",
                    e
                ))
            }
        })?
        .result;

    Ok(project
        .create_roots(run_result, nix_gc_root_user_dir, &logger)
        .map_err(|e| {
            ExitError::temporary(anyhow::Error::new(e).context("rooting the environment failed"))
        })?)
}

/// Instantiates a `Command` to start bash.
pub fn bash_cmd(
    project_root: OutputPath,
    cas: &ContentAddressable,
    logger: &slog::Logger,
) -> Result<Command, ExitError> {
    let init_file = cas
        .file_from_string(&format!(
            r#"
EVALUATION_ROOT="{}"

{}"#,
            project_root.display_shell_gc_root(),
            include_str!("./ops/direnv/envrc.bash")
        ))
        .expect("failed to write shell output");

    debug!(logger,"building bash via runtime closure"; "closure" => crate::RUN_TIME_CLOSURE);
    let bash_path = CallOpts::expression(&format!("(import {}).path", crate::RUN_TIME_CLOSURE))
        .value::<PathBuf>()
        .expect("failed to get runtime closure path");

    let mut cmd = Command::new(bash_path.join("bash"));
    cmd.env(
        "BASH_ENV",
        init_file
            .as_path()
            .to_str()
            .expect("script file path not UTF-8 clean"),
    );
    Ok(cmd)
}

/// Helper command to create a user shell
///
/// See the documentation for `crate::ops::shell`.
pub fn op_start_user_shell(
    logger: &slog::Logger,
    cas: &ContentAddressable,
    opts: StartUserShellOptions_,
) -> Result<(), ExitError> {
    // This temporary directory will not be cleaned up by lorri because we exec into the shell
    // process, which means that destructors will not be run. However, (1) the temporary files
    // lorri creates in this directory are only a few hundred bytes long; (2) the directory will be
    // cleaned up on reboot or whenever the OS decides to purge temporary directories.
    let tempdir = tempfile::tempdir().expect("failed to create temporary directory");
    let e = shell_cmd(logger, opts.shell_path.as_ref(), cas, tempdir.path()).exec();

    // 'exec' will never return on success, so if we get here, we know something has gone wrong.
    panic!("failed to exec into '{}': {}", opts.shell_path.display(), e);
}

fn shell_cmd(
    logger: &slog::Logger,
    shell_path: &Path,
    cas: &ContentAddressable,
    tempdir: &Path,
) -> Command {
    let mut cmd = Command::new(shell_path);

    match shell_path
        .file_name()
        .expect("shell path must point to a file")
        .to_str()
        .expect("shell path is not UTF-8 clean")
    {
        "bash" => {
            // To override the prompt, we need to set PS1 *after* all other setup scripts have run.
            // That makes it necessary to create our own setup script to be passed via --rcfile.
            let rcfile = cas
                .file_from_string(
                    // Using --rcfile disables sourcing of default setup scripts, so we source them
                    // explicitly here.
                    r#"
[ -e /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -e ~/.bashrc ] && . ~/.bashrc
PS1="(lorri) $PS1"
"#,
                )
                .expect("failed to write bash init script");
            cmd.args([
                "--rcfile",
                rcfile
                    .as_path()
                    .to_str()
                    .expect("file path not UTF-8 clean"),
            ]);
        }
        "zsh" => {
            // Zsh does not support anything like bash's --rcfile. However, zsh sources init
            // scripts from $ZDOTDIR by default. So we set $ZDOTDIR to a directory under lorri's
            // control, follow the default sourcing procedure, and then set the PS1.
            fs::write(
                tempdir.join(".zshrc"),
                // See "STARTUP/SHUTDOWN FILES" section of the zshall man page as well as
                // https://superuser.com/a/591440/318156.
                r#"
unset RCS # disable automatic sourcing of startup scripts

# reset ZDOTDIR
if [ ! -z ${ZDOTDIR_BEFORE} ]; then
    ZDOTDIR="${ZDOTDIR_BEFORE}"
else
    unset ZDOTDIR
fi

ZDOTDIR_OR_HOME="${ZDOTDIR:-${HOME}}"
test -f "$ZDOTDIR_OR_HOME/.zshenv" && . "$ZDOTDIR_OR_HOME/.zshenv"
test -f "/etc/zshrc"               && . "/etc/zshrc"
ZDOTDIR_OR_HOME="${ZDOTDIR:-${HOME}}"
test -f "$ZDOTDIR_OR_HOME/.zshrc"  && . "$ZDOTDIR_OR_HOME/.zshrc"

PS1="(lorri) ${PS1}"
"#,
            )
            .expect("failed to write zsh init script");
            if let Ok(d) = env::var("ZDOTDIR") {
                cmd.env("ZDOTDIR_BEFORE", d);
            }
            cmd.env("ZDOTDIR", tempdir);
        }
        // Add handling for other supported shells here.
        _ => {
            warn!(logger, "We can only open shells for bash and zsh at the moment, try using our direnv support instead. It supports as many shells as direnv does!")
        }
    }
    cmd
}

/// Options for the kinds of events to report
#[derive(Debug)]
pub enum EventKind {
    /// Report only live events - those that happen after invocation
    Live,
    /// Report events recorded for projects up until invocation
    Snapshot,
    /// Report all events
    All,
}

impl FromStr for EventKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(EventKind::All),
            "live" => Ok(EventKind::Live),
            "snapshot" => Ok(EventKind::Snapshot),
            _ => Err(format!("{} not in all,live,snapshot", s)),
        }
    }
}

/// Run to output a stream of build events in a machine-parseable form.
///
/// See the documentation for lorri::cli::Command::StreamEvents_ for more
/// details.
pub fn op_stream_events(
    paths: &Paths,
    kind: EventKind,
    logger: &slog::Logger,
) -> Result<(), ExitError> {
    let (tx_event, rx_event) = chan::unbounded::<Event>();

    let thread = {
        let address = crate::ops::get_paths()?.daemon_socket_file().clone();
        debug!(logger, "connecting to socket"; "socket" => address.as_path().display());
        let logger2 = logger.clone();
        let paths2 = (*paths).clone();
        // This async will not block when it is dropped,
        // since it only reads messages and don’t want to block exit in the Snapshot case.
        Async::<Result<(), ExitError>>::run_and_linger(logger, move || {
            let client = client::create::<client::StreamEvents>(
                &paths2,
                // infinite timeout because we are listening indefinitely
                client::Timeout::Infinite,
                &logger2,
            )?;

            client.write(&client::StreamEvents {})?;
            loop {
                let res = client.read();
                tx_event
                    .send(
                        // TODO: error
                        res.map_err(|err| ExitError::temporary(anyhow::Error::new(err)))?,
                    )
                    .expect("tx_event hung up!");
            }
        })
    };

    let mut snapshot_done = false;
    loop {
        chan::select! {
            recv(rx_event) -> event => match event.expect("rx_event hung up!") {
                Event::SectionEnd => {
                    debug!(logger, "SectionEnd");
                    match kind {
                        // If we only want the snapshot, quit the program
                        EventKind::Snapshot => break Ok(()),
                        // Else we now start sending the incremental data
                        _ => { snapshot_done = true; },
                    }
                }
                ev => match (snapshot_done, &kind) {
                    (_, EventKind::All) | (false, EventKind::Snapshot) | (true, EventKind::Live) => {
                        let json: serde_json::Value = match ev {
                            Event::SectionEnd => json!({"SectionEnd":{}}),
                            Event::Started { nix_file, reason } =>
                              json!({
                                "Started": {
                                    "nix_file": nix_file.to_json_value(),
                                    "reason": match reason {
                                        Reason::PingReceived => json!({"PingReceived": {}}),
                                        Reason::FilesChanged(files) => json!({"FilesChanged": files.iter().map(|p| path_to_json_string(p)).collect::<Vec<serde_json::Value>>()})
                                    }
                                }
                              }),
                            Event::Completed { nix_file, rooted_output_paths } => json!({
                              "Completed": {
                                "nix_file": nix_file.to_json_value(),
                                "rooted_output_paths": rooted_output_paths.to_json_value()
                              }
                            }),
                            Event::Failure { nix_file, failure } => json!({
                              "Failure": {
                                "nix_file": nix_file.to_json_value(),
                                "failure": { "message": format!("{}",  failure) }
                              }
                            }),
                            };

                        serde_json::to_writer(
                            std::io::stdout(),
                            &json
                        )
                            .expect("couldn't serialize event");
                        writeln!(std::io::stdout()).expect("couldn't serialize event");
                        std::io::stdout().flush().expect("couldn't flush serialized event");
                    }
                    _ => (),
                },
            },
            recv(thread.chan()) -> finished => match finished.expect("send-events hung up!") {
                Ok(()) => panic!("send-events should never finish!"),
                // error in the async, time to quit
                err => err?
            }
        }
    }
}

/// The source to upgrade to.
enum UpgradeSource {
    /// A branch in the upstream git repo
    Branch(String),
    /// A local path
    Local(PathBuf),
}

#[derive(Error, Debug)]
enum UpgradeSourceError {
    /// The local path given by the user could not be found
    #[error("Cannot upgrade to local repostory {0}: path not found")]
    LocalPathNotFound(PathBuf),
    /// We couldn’t find local_path/release.nix, it is not a lorri repo.
    #[error("{0} does not exist, are you sure this is a lorri repository?")]
    ReleaseNixDoesntExist(PathBuf),
    /// An other error happened when canonicalizing the given path.
    #[error("Problem accessing local repository")]
    CantCanonicalizeLocalPath(#[source] std::io::Error),
}

impl ExitAs for UpgradeSourceError {
    fn exit_as(&self) -> ExitErrorType {
        use ExitErrorType::*;
        use UpgradeSourceError::*;
        match self {
            LocalPathNotFound(_) => UserError,
            CantCanonicalizeLocalPath(_) => Temporary,
            ReleaseNixDoesntExist(_) => UserError,
        }
    }
}

impl UpgradeSource {
    /// Convert from the cli argument to a form we can pass to ./upgrade.nix.
    fn from_cli_argument(upgrade_target: cli::UpgradeTo) -> Result<Self, UpgradeSourceError> {
        // if no source was given, we default to the rolling-release branch
        let src = upgrade_target
            .source
            .unwrap_or(cli::UpgradeSource::RollingRelease);
        Ok(match src {
            cli::UpgradeSource::RollingRelease => {
                UpgradeSource::Branch("rolling-release".to_string())
            }
            cli::UpgradeSource::Master => UpgradeSource::Branch("canon".to_string()),
            cli::UpgradeSource::Canon => UpgradeSource::Branch("canon".to_string()),
            cli::UpgradeSource::Branch(b) => UpgradeSource::Branch(b.branch),
            cli::UpgradeSource::Local(dest) => {
                // make it absolute to not confuse ./upgrade.nix
                (match std::fs::canonicalize(dest.path.clone()) {
                    Ok(abspath) => {
                        // Check whether we actually have something like a lorri repository
                        let release_nix = abspath.join("release.nix");
                        if release_nix.exists() {
                            Ok(UpgradeSource::Local(abspath))
                        } else {
                            Err(UpgradeSourceError::ReleaseNixDoesntExist(release_nix))
                        }
                    }
                    Err(err) => Err(match err.kind() {
                        std::io::ErrorKind::NotFound => {
                            UpgradeSourceError::LocalPathNotFound(dest.path)
                        }
                        _ => UpgradeSourceError::CantCanonicalizeLocalPath(err),
                    }),
                })?
            }
        })
    }
}

/// Upgrade lorri by using nix-env to install from Git.
///
/// This is useful for pointing users to an fix to a reported bug,
/// or for users who want to follow the lorri canon locally.
///
/// Originally it was used as pre-release, that’s why there is support
/// for updating to a special rolling-release branch.
pub fn op_upgrade(
    upgrade_target: cli::UpgradeTo,
    cas: &ContentAddressable,
    logger: &slog::Logger,
) -> Result<(), ExitError> {
    /*
    1. nix-instantiate the expression
    2. get all the changelog entries from <currentnumber> to <maxnumber>
    3. nix-build the expression's package attribute
    4. nix-env -i the package
     */
    let upgrade_expr = cas
        .file_from_string(include_str!("./ops/upgrade.nix"))
        .expect("could not write to CAS");

    let expr = {
        let src = UpgradeSource::from_cli_argument(upgrade_target)?;

        match src {
            UpgradeSource::Branch(ref b) => println!("Upgrading from branch: {}", b),
            UpgradeSource::Local(ref p) => println!("Upgrading from local path: {}", p.display()),
        }

        let mut expr = nix::CallOpts::file(upgrade_expr.as_path());

        match src {
            UpgradeSource::Branch(b) => {
                expr.argstr("type", "branch");
                expr.argstr("branch", b);
            }
            UpgradeSource::Local(p) => {
                expr.argstr("type", "local");
                expr.argstr("path", p);
            }
        }
        // ugly hack to prevent expr from being mutable outside,
        // since I can't sort out how to chain argstr and still
        // keep a reference
        expr
    };

    let changelog: changelog::Log = expr.clone().attribute("changelog").value().unwrap();

    println!("Changelog when upgrading from {}:", VERSION_BUILD_REV);
    for entry in changelog.entries.iter().rev() {
        if VERSION_BUILD_REV < entry.version {
            println!();
            println!("{}:", entry.version);
            for line in entry.changes.lines() {
                println!("    {}", line);
            }
        }
    }

    println!("Building ...");
    match expr.clone().attribute("package").path(logger) {
        Ok((build_result, gc_root)) => {
            let status = Command::new("nix-env")
                .arg("--install")
                .arg(build_result.as_path())
                .status()
                // TODO: check existence of commands at the beginning
                .expect("Error: failed to execute nix-env --install");
            // we can drop the temporary gc root
            drop(gc_root);

            if status.success() {
                info!(logger, "upgrade successful");
                Ok(())
            } else {
                Err(ExitError::expected_error(anyhow::anyhow!(
                    "\nError: nix-env command was not successful!\n{:#?}",
                    status
                )))
            }
        }
        // our update expression is broken, crash
        Err(e) => panic!("Failed to build the update! {:#?}", e),
    }
}

/// Run a BuildLoop for `shell.nix`, watching for input file changes.
/// Can be used together with `direnv`.
///
/// See the documentation for lorri::cli::Command::Shell for more
/// details.
pub fn op_watch(
    project: Project,
    cas: &ContentAddressable,
    opts: WatchOptions,
    logger: &slog::Logger,
) -> Result<(), ExitError> {
    let username = project::Username::from_env_var().map_err(ExitError::temporary)?;
    let nix_gc_root_user_dir = project::NixGcRootUserDir::get_or_create(&username)?;
    if opts.once {
        main_run_once(project, nix_gc_root_user_dir, cas, logger)
    } else {
        main_run_forever(project, nix_gc_root_user_dir, cas, logger)
    }
}

fn main_run_once(
    project: Project,
    nix_gc_root_user_dir: NixGcRootUserDir,
    cas: &ContentAddressable,
    logger: &slog::Logger,
) -> Result<(), ExitError> {
    // TODO: add the ability to pass extra_nix_options to watch
    let mut build_loop = BuildLoop::new(
        &project,
        NixOptions::empty(),
        nix_gc_root_user_dir,
        cas.clone(),
        logger.clone(),
    )
    .map_err(ExitError::temporary)?;
    match build_loop.once() {
        Ok(msg) => {
            info!(logger, "build message"; "message" => ?msg);
            Ok(())
        }
        Err(e) => {
            if e.is_actionable() {
                // TODO: implement std::io::Error for BuildError to get a backtrace
                Err(ExitError::expected_error(anyhow::anyhow!("{:#?}", e)))
            } else {
                // TODO: implement std::io::Error for BuildError to get a backtrace
                Err(ExitError::temporary(anyhow::Error::msg(e)))
            }
        }
    }
}

/// Print or remove gc roots depending on cli options.
pub fn op_gc(
    logger: &slog::Logger,
    paths: &Paths,
    opts: crate::cli::GcOptions,
) -> Result<(), ExitError> {
    let infos = Project::list_roots(logger, paths)?;
    let mut conn = Sqlite::new_connection(&paths.sqlite_db);
    match opts.action {
        cli::GcSubcommand::Info => {
            if opts.json {
                serde_json::to_writer(
                    std::io::stdout(),
                    &infos
                        .iter()
                        .map(|(info, _project)| {
                            json!({
                                "gc_dir": info.gc_dir.to_json_string(),
                                "nix_file": info.nix_file.to_json_string(),
                                "timestamp": info.timestamp,
                                "alive": info.alive
                            })
                        })
                        .collect::<Vec<_>>(),
                )
                .expect("could not serialize gc roots");
            } else {
                for (info, _project) in infos {
                    println!("{}", info.format_pretty_oneline());
                }
            }
        }
        cli::GcSubcommand::Rm {
            shell_file,
            all,
            older_than,
            dry_run,
        } => {
            let files_to_remove: HashSet<PathBuf> = shell_file.into_iter().collect();
            let to_remove: Vec<(GcRootInfo, Project)> = infos
                .into_iter()
                .filter(|(info, _project)| {
                    all || !info.alive
                        || files_to_remove.contains(info.nix_file.as_path())
                        || older_than.map_or(false, |limit| {
                            match info.timestamp {
                                // always remove gcroots for which we could not figure out a timestamp
                                None => true,
                                Some(t) => t.elapsed().map_or(false, |actual| actual > limit),
                            }
                        })
                })
                .collect();
            let mut result = Vec::new();
            if dry_run {
                if to_remove.len() > 0 {
                    println!("--dry-run: Would delete the following GC roots:");
                    for (info, _project) in to_remove {
                        println!("{}", info.format_pretty_oneline());
                    }
                } else {
                    println!("--dry-run: Would not delete any GC roots");
                }
            } else {
                for (info, project) in to_remove {
                    match project.remove_project(&mut conn) {
                        Ok(()) => result.push(Ok(info)),
                        Err(e) => result.push(Err((info, e.to_string()))),
                    }
                }
                if opts.json {
                    let res = result
                        .into_iter()
                        .map(|r| match r {
                            Err((info, err)) => json!({
                                // Error, if any
                                "error": err,
                                // The root we tried to remove
                                "root": {
                                    "gc_dir": info.gc_dir,
                                    "nix_file": info.nix_file.to_json_string(),
                                    // we use the Serialize instance for SystemTime
                                    "timestamp": info.timestamp,
                                    "alive": info.alive
                                }
                            }),
                            Ok(info) => json!({
                                "error": null,
                                "root": {
                                    "gc_dir": info.gc_dir,
                                    "nix_file": info.nix_file.to_json_string(),
                                    // we use the Serialize instance for SystemTime
                                    "timestamp": info.timestamp,
                                    "alive": info.alive
                                }
                            }),
                        })
                        .collect::<Vec<_>>();
                    serde_json::to_writer(std::io::stdout(), &res)
                        .expect("failed to serialize result");
                } else {
                    let (ok, err): (Vec<_>, Vec<_>) = result.into_iter().partition_result();
                    println!("Removed {} gc roots.", ok.len());
                    if err.len() > 0 {
                        for (info, e) in err {
                            warn!(
                                logger,
                                "Failed to remove gc root: {}: {}",
                                info.gc_dir.display(),
                                e
                            )
                        }
                    }
                    if ok.len() > 0 {
                        println!("Remember to run nix-collect-garbage to actually free space.");
                    }
                }
            }
        }
    }
    Ok(())
}

fn main_run_forever(
    project: Project,
    nix_gc_root_user_dir: NixGcRootUserDir,
    cas: &ContentAddressable,
    logger: &slog::Logger,
) -> Result<(), ExitError> {
    let (tx_build_results, rx_build_results) = chan::unbounded();
    let (tx_ping, rx_ping) = chan::unbounded();
    let logger2 = logger.clone();
    let cas2 = cas.clone();
    // TODO: add the ability to pass extra_nix_options to watch
    let build_thread = {
        Async::run(logger, move || {
            match BuildLoop::new(
                &project,
                NixOptions::empty(),
                nix_gc_root_user_dir,
                cas2,
                logger2,
            ) {
                Ok(mut bl) => bl.forever(tx_build_results, rx_ping).never(),
                Err(e) => Err(ExitError::temporary(e)),
            }
        })
    };

    // We ping the build loop once, to make it run the first build immediately
    tx_ping.send(()).expect("could not send ping to build_loop");

    for msg in rx_build_results {
        info!(logger, "build message"; "message" => ?msg);
    }

    build_thread.block()
}
