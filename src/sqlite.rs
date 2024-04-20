//! TODO
use std::time::SystemTime;

use anyhow::Context;
use rusqlite as sqlite;
use sqlite::named_params;

use crate::{constants::Paths, ops::error::ExitError, project::Project, AbsPathBuf};

/// TODO
pub struct Sqlite {
    conn: sqlite::Connection,
    sqlite_path: AbsPathBuf,
}

impl Sqlite {
    /// Connect to sqlite
    pub fn new_connection(sqlite_path: &AbsPathBuf) -> sqlite::Result<Self> {
        let new = Self::new_connection_internal(sqlite_path)?;
        new.conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS gc_roots (
                        id INTEGER PRIMARY KEY,
                        nix_file PATH UNIQUE,
                        last_updated EPOCH_TIME
                );
                "#,
        )?;

        Ok(new)
    }

    fn new_connection_internal(sqlite_path: &AbsPathBuf) -> sqlite::Result<Self> {
        let conn = sqlite::Connection::open(sqlite_path.as_path())?;

        Ok(Self {
            conn,
            sqlite_path: sqlite_path.clone(),
        })
    }

    /// Clone this by creating a new connection to the database
    pub fn clone(&self) -> sqlite::Result<Self> {
        Self::new_connection_internal(&self.sqlite_path)
    }

    /// Return the path to the sqlite file
    pub fn sqlite_path(&self) -> AbsPathBuf {
        self.sqlite_path.clone()
    }

    /// Migrate the GC roots into our sqlite
    pub fn migrate_gc_roots(&self, logger: &slog::Logger, paths: &Paths) -> Result<(), ExitError> {
        let infos = Project::list_roots(logger, paths, self.clone()?)?;

        self.conn.execute("DELETE FROM gc_roots", ()).unwrap();

        let mut stmt = self
            .conn
            .prepare(
                r##"
                    INSERT INTO gc_roots (nix_file, last_updated)
                    VALUES (:nix_file, :last_updated)
                    -- paths might be duplicate because we didn’t use to normalize file paths as much
                    ON CONFLICT DO NOTHING"##,
            )
            .unwrap();
        for (info, _project) in infos {
            let ts = info.timestamp.map(|t| {
                t.duration_since(SystemTime::UNIX_EPOCH)
                    .expect("expect file timestamp to be a unix timestamp")
                    .as_secs()
            });
            stmt.execute(named_params! {
                ":nix_file": info.nix_file.to_sql(),
                ":last_updated": ts
            })
            .expect("cannot insert");
        }

        // let mut stmt = self
        //     .conn
        //     .prepare("SELECT nix_file, last_updated from gc_roots")
        //     .unwrap();
        // let mut res = stmt
        //     .query_map((), |row| {
        //         let nix_file = row
        //             .get::<_, Option<Vec<u8>>>("nix_file")
        //             .unwrap()
        //             .map(|v: Vec<u8>| OsString::from_vec(v));
        //         let t = row.get::<_, Option<u64>>("last_updated").unwrap().map(|u| {
        //             SystemTime::elapsed(&(SystemTime::UNIX_EPOCH + Duration::from_secs(u))).unwrap()
        //         });
        //         Ok((nix_file, t, t.map(ago)))
        //     })
        //     .unwrap()
        //     .filter_map(|r| match r {
        //         Err(_) => None,
        //         Ok(r) => r.0.map(|nix| (nix, r.1, r.2)),
        //     })
        //     .collect::<Vec<_>>();
        // res.sort_by_key(|r| r.1);
        // info!(logger, "We have these nix files: {:#?}", res);

        Ok(())
    }

    /// Run the given code in the context of a transaction, automatically aborting the transaction if the function returns `Err`, comitting if it returns `Ok`.
    pub fn in_transaction<F, A, E>(&mut self, f: F) -> anyhow::Result<Result<A, E>>
    where
        F: FnOnce(&sqlite::Transaction) -> Result<A, E>,
    {
        ({
            let t = self.conn.transaction()?;
            match f(&t) {
                Err(e) => {
                    t.rollback()?;
                    Ok(Err(e))
                }
                Ok(o) => {
                    t.commit()?;
                    Ok(Ok(o))
                }
            }
        } as sqlite::Result<Result<A, E>>)
            .context("executing sqlite transaction failed")
    }
}
