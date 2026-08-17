// src/database.rs
// ─────────────────────────────────────────────────────────────────────────────
// FIX 3 — Metadata (site name) plaintext leak:
//
// Old schema: `site TEXT NOT NULL`  ← readable without master password
//
// New schema:
//   site_enc   TEXT  — AES-GCM encrypted site name (confidential)
//   site_idx   TEXT  — PRF(index_key, lowercase(site)) (for search, 32-byte hex)
//
// Search: compute PRF of the query → compare against stored idx values.
//         This leaks only "query matches this entry" under active search,
//         not the actual site name.
//
// FIX 4 — PasswordEntry plain String fields:
//
// Old:  pub password: String  ← all passwords in RAM while vault is open
//
// New:  username/password/notes stored as encrypted blobs (String) in
//       EncryptedEntry. They are only decrypted on demand (reveal/copy),
//       never stored as plaintext in any long-lived struct.
//       The UI holds Vec<EncryptedEntry>; decryption happens transiently.
// ─────────────────────────────────────────────────────────────────────────────

use rusqlite::{Connection, params};
use anyhow::{Context, Result};
use crate::crypto::{
    DerivedKey, derive_key, encrypt_str, decrypt_str, generate_salt,
    verify_master_password, VERIFY_PLAINTEXT, derive_index_key, site_hmac,
};
use secrecy::SecretVec;
use std::path::PathBuf;

// ── EncryptedEntry — safe at-rest representation ──────────────────────────────
// All sensitive fields remain as encrypted blobs. The UI stores these and
// only decrypts individual fields when the user requests them (copy/view).
// This means at no point does the application hold all passwords in RAM
// simultaneously as plaintext.
#[derive(Debug, Clone)]
pub struct EncryptedEntry {
    pub id:           i64,
    pub site_enc:     String,  // AES-GCM encrypted site name
    pub site_idx:     String,  // PRF token for search (not the site name)
    pub username_enc: String,
    pub password_enc: String,
    pub notes_enc:    String,
    pub created_at:   String,
    pub updated_at:   String,
}

impl EncryptedEntry {
    /// Decrypt site name. Result is a transient String — caller should zeroize
    /// after use if treating as sensitive (site names are usually low-sensitivity).
    pub fn decrypt_site(&self, key: &DerivedKey) -> Result<String> {
        decrypt_str(&self.site_enc, key)
    }

    /// Decrypt username. Returned String should be used and dropped promptly.
    pub fn decrypt_username(&self, key: &DerivedKey) -> Result<String> {
        decrypt_str(&self.username_enc, key)
    }

    /// Decrypt password. Returned String should be used and dropped promptly.
    /// For clipboard copy: copy → overwrite the String bytes → drop.
    pub fn decrypt_password(&self, key: &DerivedKey) -> Result<String> {
        decrypt_str(&self.password_enc, key)
    }

    /// Decrypt notes.
    pub fn decrypt_notes(&self, key: &DerivedKey) -> Result<String> {
        decrypt_str(&self.notes_enc, key)
    }
}

// ── DecryptedFields — short-lived, zeroize on drop ───────────────────────────
// Used only in the modal "View Entry" context. Dropped as soon as the modal
// closes. Fields implement Zeroize so data is wiped on drop.
use zeroize::Zeroize;

#[derive(Default)]
pub struct DecryptedFields {
    pub site:     String,
    pub username: String,
    pub password: String,
    pub notes:    String,
}

impl Drop for DecryptedFields {
    fn drop(&mut self) {
        self.site.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();
    }
}

impl DecryptedFields {
    pub fn from_entry(entry: &EncryptedEntry, key: &DerivedKey) -> Result<Self> {
        Ok(Self {
            site:     entry.decrypt_site(key)?,
            username: entry.decrypt_username(key)?,
            password: entry.decrypt_password(key)?,
            notes:    entry.decrypt_notes(key)?,
        })
    }
}

// ── Database ──────────────────────────────────────────────────────────────────
pub struct Database {
    conn:    Connection,
    pub db_path: PathBuf,
}

impl Database {
    pub fn open(path: &PathBuf) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("Cannot open DB at {}", path.display()))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .context("PRAGMA setup failed")?;

        let db = Self { conn, db_path: path.clone() };
        db.create_schema()?;
        Ok(db)
    }

    fn create_schema(&self) -> Result<()> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS vault_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                site_enc     TEXT    NOT NULL,
                site_idx     TEXT    NOT NULL,
                username_enc TEXT    NOT NULL,
                password_enc TEXT    NOT NULL,
                notes_enc    TEXT    NOT NULL DEFAULT '',
                created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
                updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_entries_siteidx ON entries(site_idx);
        ").context("Schema creation failed")
    }

    // ── Vault lifecycle ───────────────────────────────────────────────────────
    pub fn is_initialised(&self) -> bool {
        self.conn.query_row(
            "SELECT value FROM vault_meta WHERE key='salt'", [], |_| Ok(())
        ).is_ok()
    }

    pub fn initialise_vault(&self, master_password: &SecretVec<u8>) -> Result<DerivedKey> {
        let salt = generate_salt();
        let key  = derive_key(master_password, &salt)?;

        let salt_hex          = hex::encode(salt);
        let verification_blob = encrypt_str(VERIFY_PLAINTEXT, &key)?;

        // Store the index key (encrypted) so it survives re-opens
        let idx_key = derive_index_key(&key);
        let idx_key_enc = encrypt_str(&hex::encode(idx_key), &key)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO vault_meta(key,value) VALUES('salt',?1)", params![salt_hex])?;
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_meta(key,value) VALUES('verify',?1)", params![verification_blob])?;
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_meta(key,value) VALUES('idx_key',?1)", params![idx_key_enc])?;

        Ok(key)
    }

    pub fn unlock(&self, master_password: &SecretVec<u8>) -> Result<DerivedKey> {
        let salt_hex: String = self.conn.query_row(
            "SELECT value FROM vault_meta WHERE key='salt'", [], |r| r.get(0)
        ).context("No salt — vault not initialised")?;

        let verify_blob: String = self.conn.query_row(
            "SELECT value FROM vault_meta WHERE key='verify'", [], |r| r.get(0)
        ).context("No verification blob")?;

        let salt = hex::decode(&salt_hex).context("Corrupt salt")?;
        verify_master_password(master_password, &salt, &verify_blob)
    }

    /// Load the index key (32 bytes) from the DB.
    fn load_index_key(&self, key: &DerivedKey) -> Result<[u8; 32]> {
        let enc: String = self.conn.query_row(
            "SELECT value FROM vault_meta WHERE key='idx_key'", [], |r| r.get(0)
        ).context("No index key stored")?;

        let hex_str = decrypt_str(&enc, key)?;
        let bytes = hex::decode(&hex_str).context("Corrupt index key")?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        Ok(out)
    }

    // ── CRUD ──────────────────────────────────────────────────────────────────
    pub fn add_entry(
        &self, site: &str, username: &str, password: &str, notes: &str,
        key: &DerivedKey,
    ) -> Result<i64> {
        let idx_key      = self.load_index_key(key)?;
        let site_enc     = encrypt_str(site, key)?;
        let site_idx     = site_hmac(&idx_key, site);
        let username_enc = encrypt_str(username, key)?;
        let password_enc = encrypt_str(password, key)?;
        let notes_enc    = encrypt_str(notes, key)?;

        self.conn.execute(
            "INSERT INTO entries(site_enc,site_idx,username_enc,password_enc,notes_enc)
             VALUES(?1,?2,?3,?4,?5)",
            params![site_enc, site_idx, username_enc, password_enc, notes_enc],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn update_entry(
        &self, id: i64, site: &str, username: &str, password: &str, notes: &str,
        key: &DerivedKey,
    ) -> Result<()> {
        let idx_key      = self.load_index_key(key)?;
        let site_enc     = encrypt_str(site, key)?;
        let site_idx     = site_hmac(&idx_key, site);
        let username_enc = encrypt_str(username, key)?;
        let password_enc = encrypt_str(password, key)?;
        let notes_enc    = encrypt_str(notes, key)?;

        self.conn.execute(
            "UPDATE entries SET site_enc=?1,site_idx=?2,username_enc=?3,
             password_enc=?4,notes_enc=?5,updated_at=datetime('now') WHERE id=?6",
            params![site_enc, site_idx, username_enc, password_enc, notes_enc, id],
        )?;
        Ok(())
    }

    pub fn delete_entry(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM entries WHERE id=?1", params![id])?;
        Ok(())
    }

    /// Load all entries as encrypted blobs — no decryption happens here.
    pub fn list_entries_encrypted(&self) -> Result<Vec<EncryptedEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id,site_enc,site_idx,username_enc,password_enc,notes_enc,
                    created_at,updated_at FROM entries ORDER BY site_idx ASC"
        )?;

        let entries = stmt.query_map([], |row| Ok(EncryptedEntry {
            id:           row.get(0)?,
            site_enc:     row.get(1)?,
            site_idx:     row.get(2)?,
            username_enc: row.get(3)?,
            password_enc: row.get(4)?,
            notes_enc:    row.get(5)?,
            created_at:   row.get(6)?,
            updated_at:   row.get(7)?,
        }))?
        .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Search: compute PRF of the query, filter by site_idx.
    /// Returns EncryptedEntry rows — caller decrypts only what it needs.
    pub fn search_entries_encrypted(
        &self, query: &str, key: &DerivedKey,
    ) -> Result<Vec<EncryptedEntry>> {
        let idx_key = self.load_index_key(key)?;
        let token   = site_hmac(&idx_key, query);

        // Exact token match (full site name query).
        // For substring search we fall back to loading all and decrypting sites —
        // this is unavoidable with encrypted metadata; we do it lazily.
        let mut stmt = self.conn.prepare(
            "SELECT id,site_enc,site_idx,username_enc,password_enc,notes_enc,
                    created_at,updated_at FROM entries WHERE site_idx=?1"
        )?;

        let exact: Vec<EncryptedEntry> = stmt.query_map(params![token], |row| {
            Ok(EncryptedEntry {
                id:           row.get(0)?,
                site_enc:     row.get(1)?,
                site_idx:     row.get(2)?,
                username_enc: row.get(3)?,
                password_enc: row.get(4)?,
                notes_enc:    row.get(5)?,
                created_at:   row.get(6)?,
                updated_at:   row.get(7)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        if !exact.is_empty() { return Ok(exact); }

        // Substring fallback: decrypt all site names, filter in-process.
        // No site names touch the DB in plaintext.
        let all = self.list_entries_encrypted()?;
        let q   = query.to_lowercase();
        let mut matches = Vec::new();
        for entry in all {
            if let Ok(site) = entry.decrypt_site(key) {
                if site.to_lowercase().contains(&q) {
                    matches.push(entry);
                }
            }
        }
        Ok(matches)
    }

    pub fn default_path() -> PathBuf {
        let mut p = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("."))
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        p.push("rustpass.db");
        p
    }
}
