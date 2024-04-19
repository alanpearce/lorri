//! TODO
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
    time::{Duration, SystemTime},
};

use rusqlite as sqlite;
use slog::info;
use sqlite::named_params;

use crate::{ops::error::ExitError, project::list_roots};

/// Migrate the GC roots into our sqlite
pub fn migrate_gc_roots(logger: &slog::Logger) -> Result<(), ExitError> {
    let conn = sqlite::Connection::open_in_memory().expect("cannot open sqlite db");
    conn.execute_batch(
        r#"CREATE TABLE gc_roots(
                    id INTEGER PRIMARY KEY,
                    nix_file PATH,
                    last_updated EPOCH_TIME
            );
            "#,
    )
    .unwrap();

    let infos = list_roots(logger)?;

    let mut stmt = conn
        .prepare("INSERT INTO gc_roots (nix_file, last_updated) VALUES (:nix_file, :last_updated);")
        .unwrap();
    for info in infos {
        let ts = info
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("expect file timestamp to be a unix timestamp")
            .as_secs();
        stmt.execute(named_params! {
            ":nix_file": info.nix_file.map(|pb| pb.as_os_str().as_bytes().to_owned()),
            ":last_updated": ts
        })
        .expect("cannot insert");
    }

    let mut stmt = conn
        .prepare("SELECT nix_file, last_updated from gc_roots")
        .unwrap();
    let mut res = stmt
        .query_map((), |row| {
            let nix_file = row
                .get::<_, Option<Vec<u8>>>("nix_file")
                .unwrap()
                .map(|v: Vec<u8>| OsString::from_vec(v));
            let t = row.get::<_, Option<u64>>("last_updated").unwrap().map(|u| {
                SystemTime::elapsed(&(SystemTime::UNIX_EPOCH + Duration::from_secs(u))).unwrap()
            });
            Ok((nix_file, t, t.map(ago)))
        })
        .unwrap()
        .filter_map(|r| match r {
            Err(_) => None,
            Ok(r) => r.0.map(|nix| (nix, r.1, r.2)),
        })
        .collect::<Vec<_>>();
    res.sort_by_key(|r| r.1);
    info!(logger, "We have these nix files: {:#?}", res);

    Ok(())
}

fn ago(dur: Duration) -> String {
    let secs = dur.as_secs();
    let mins = dur.as_secs() / 60;
    let hours = dur.as_secs() / (60 * 60);
    let days = dur.as_secs() / (60 * 60 * 24);

    if days > 0 {
        return format!("{} days ago", days);
    }
    if hours > 0 {
        return format!("{} hours ago", hours);
    }
    if mins > 0 {
        return format!("{} minutes ago", mins);
    }

    format!("{} seconds ago", secs)
}
