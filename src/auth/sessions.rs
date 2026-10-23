//! Read-only lookup in the engine's `auth_sessions` table (the Node engine owns all writes).
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;

/// The columns `SessionStore.verify` / `loadActiveSession` read.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRow {
    pub subject: String,
    pub method: String,
    pub scopes: Vec<String>,
    /// `expires_at` (ISO-8601 text) as epoch milliseconds, parsed by SQLite.
    pub expires_at_ms: i64,
    pub revoked_at: Option<String>,
}

pub struct Store(Connection);

impl Store {
    /// Read-only open is safe alongside the engine's writer because the DB is in WAL mode.
    pub fn open_readonly(path: &Path) -> rusqlite::Result<Store> {
        let c = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        c.busy_timeout(std::time::Duration::from_millis(100))?;
        Ok(Store(c))
    }

    pub fn lookup(&self, session_id: &str) -> rusqlite::Result<Option<SessionRow>> {
        self.0
            .prepare_cached(
                // An unparsable expires_at is NULL here, which fails the row read (fail closed).
                "SELECT subject, method, scopes,
                        CAST(ROUND(unixepoch(expires_at, 'subsec') * 1000) AS INTEGER), revoked_at
                 FROM auth_sessions WHERE session_id = ?1",
            )?
            .query_row([session_id], |r| {
                let scopes: String = r.get(2)?;
                Ok(SessionRow {
                    subject: r.get(0)?,
                    method: r.get(1)?,
                    scopes: serde_json::from_str(&scopes).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            e.into(),
                        )
                    })?,
                    expires_at_ms: r.get(3)?,
                    revoked_at: r.get(4)?,
                })
            })
            .optional()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Copied from Vekrel-Engine `apps/server/src/persistence/Migrations/031_AuthAuthorizationScopes.ts`
    /// plus the two columns `041_AuthSessionClientConnection.ts` adds.
    pub(crate) const DDL: &str = "
        CREATE TABLE auth_sessions (
          session_id TEXT PRIMARY KEY,
          subject TEXT NOT NULL,
          scopes TEXT NOT NULL,
          method TEXT NOT NULL,
          client_label TEXT,
          client_ip_address TEXT,
          client_user_agent TEXT,
          client_device_type TEXT NOT NULL DEFAULT 'unknown',
          client_os TEXT,
          client_browser TEXT,
          issued_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          last_connected_at TEXT,
          revoked_at TEXT,
          client_surface TEXT,
          client_app_version TEXT
        );
        CREATE INDEX idx_auth_sessions_active ON auth_sessions(revoked_at, expires_at, issued_at);";

    #[test]
    fn finds_an_inserted_row() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("statev2.sqlite");
        let c = Connection::open(&db).unwrap();
        c.execute_batch(DDL).unwrap();
        c.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at)
             VALUES ('s1', 'browser', '[\"a\",\"b\"]', 'browser-session-cookie', '2026-01-01T00:00:00.000Z', '2026-02-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        let s = Store::open_readonly(&db).unwrap();
        assert_eq!(
            s.lookup("s1").unwrap(),
            Some(SessionRow {
                subject: "browser".into(),
                method: "browser-session-cookie".into(),
                scopes: vec!["a".into(), "b".into()],
                expires_at_ms: 1_769_904_000_000,
                revoked_at: None,
            })
        );
        assert_eq!(s.lookup("nope").unwrap(), None);
    }

    #[test]
    fn missing_db_is_an_error() {
        assert!(Store::open_readonly(Path::new("/nonexistent/vekrel/statev2.sqlite")).is_err());
    }
}
