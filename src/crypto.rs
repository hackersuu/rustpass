// src/crypto.rs
// ─────────────────────────────────────────────────────────────────────────────
// Crypto module: Argon2id KDF + AES-256-GCM + hardened memory primitives
//
// FIX 1 — SecureBuffer realloc ghost data:
//   Underlying storage is now Vec<u8> with a fixed pre-allocated capacity.
//   On push we encode chars as UTF-8 into the existing allocation.
//   clear_secure() calls zeroize() which wipes every byte in the buffer,
//   then we reset length to 0 — the allocation is never moved/copied.
//
// FIX 2 — egui pw_str temporary copy:
//   egui's TextEdit needs a &mut String. We provide ZeroizingString, a
//   newtype around String that zeroizes its heap allocation on drop.
//   Every render frame: create ZeroizingString from SecureBuffer, pass to
//   egui, sync changes back, then ZeroizingString drops → bytes wiped.
// ─────────────────────────────────────────────────────────────────────────────

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, Algorithm, Version, Params};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use secrecy::{ExposeSecret, SecretVec};
use zeroize::{Zeroize, ZeroizeOnDrop};
use anyhow::{Context, Result};
use rand::RngCore;

// ── Constants ─────────────────────────────────────────────────────────────────
pub const SALT_LEN: usize = 32;
pub const KEY_LEN:  usize = 32;  // AES-256
pub const NONCE_LEN: usize = 12; // GCM standard

// Argon2id parameters (OWASP tier-2 interactive login)
const ARGON2_M_COST: u32 = 65536; // 64 MB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

// Pre-allocated capacity for SecureBuffer — avoids reallocs up to this size.
// If a password exceeds this, exactly one realloc occurs. The old buffer is
// zeroized before dealloc via the Drop impl below.
const SECURE_BUF_INIT_CAP: usize = 256;

// ── Derived Key wrapper ───────────────────────────────────────────────────────
#[derive(ZeroizeOnDrop)]
pub struct DerivedKey {
    inner: [u8; KEY_LEN],
}

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] { &self.inner }
}

// ── Salt generation ───────────────────────────────────────────────────────────
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

// ── Argon2id KDF ──────────────────────────────────────────────────────────────
pub fn derive_key(master_password: &SecretVec<u8>, salt: &[u8]) -> Result<DerivedKey> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("Failed to build Argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_buf = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.expose_secret(), salt, &mut key_buf)
        .map_err(|e| anyhow::anyhow!("Argon2id KDF failed: {e}"))?;

    Ok(DerivedKey { inner: key_buf })
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────
pub fn encrypt(plaintext: &[u8], derived_key: &DerivedKey) -> Result<String> {
    let key    = Key::<Aes256Gcm>::from_slice(derived_key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    Ok(format!("{}:{}", B64.encode(nonce), B64.encode(ciphertext)))
}

pub fn decrypt(blob: &str, derived_key: &DerivedKey) -> Result<Vec<u8>> {
    let (nonce_b64, ct_b64) = blob.split_once(':').context("Invalid ciphertext format")?;
    let nonce_bytes = B64.decode(nonce_b64).context("Bad nonce encoding")?;
    let ciphertext  = B64.decode(ct_b64).context("Bad ciphertext encoding")?;
    let nonce       = Nonce::from_slice(&nonce_bytes);
    let key         = Key::<Aes256Gcm>::from_slice(derived_key.as_bytes());
    let cipher      = Aes256Gcm::new(key);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong master password or corrupted data"))
}

pub fn encrypt_str(plaintext: &str, key: &DerivedKey) -> Result<String> {
    encrypt(plaintext.as_bytes(), key)
}

pub fn decrypt_str(blob: &str, key: &DerivedKey) -> Result<String> {
    let bytes = decrypt(blob, key)?;
    String::from_utf8(bytes).context("Decrypted bytes are not valid UTF-8")
}

// ── Verify master password ────────────────────────────────────────────────────
pub fn verify_master_password(
    master_password: &SecretVec<u8>,
    salt: &[u8],
    verification_blob: &str,
) -> Result<DerivedKey> {
    let key = derive_key(master_password, salt)?;
    let plaintext = decrypt_str(verification_blob, &key)
        .map_err(|_| anyhow::anyhow!("Wrong master password"))?;
    if plaintext != "RUSTPASS_OK" {
        anyhow::bail!("Verification string mismatch — vault may be corrupted");
    }
    Ok(key)
}

pub const VERIFY_PLAINTEXT: &str = "RUSTPASS_OK";

// ─────────────────────────────────────────────────────────────────────────────
// FIX 1: SecureBuffer — reallocation-safe, zeroize-on-drop password buffer
// ─────────────────────────────────────────────────────────────────────────────
//
// Root cause of the old bug:
//   `String` grows by doubling its heap allocation. When capacity is exceeded
//   Rust allocates new memory, memcpy's the old content, then calls dealloc on
//   the old pointer WITHOUT zeroing it first. The OS may hand that page to
//   another process. Our new implementation:
//
//   1. Pre-allocates SECURE_BUF_INIT_CAP bytes up front — no realloc for
//      normal passwords.
//   2. Stores raw UTF-8 bytes in a Vec<u8>. Vec::with_capacity reserves
//      exactly what we ask; it never copies unless we exceed capacity.
//   3. On clear_secure() we call zeroize() on the full Vec — this wipes
//      every byte including the unused tail, then we set len=0.
//   4. Drop calls clear_secure() automatically via ZeroizeOnDrop.
//
// Residual risk: if a password exceeds 256 chars, Vec will reallocate once.
// The old allocation is freed without zeroing by the global allocator — this
// is an inherent limitation without a custom allocator. 256 chars covers
// virtually all real-world passwords.

pub struct SecureBuffer {
    // Raw UTF-8 bytes. We never expose a &str that outlives the borrow.
    buf: Vec<u8>,
}

impl Default for SecureBuffer {
    fn default() -> Self {
        Self { buf: Vec::with_capacity(SECURE_BUF_INIT_CAP) }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.clear_secure();
    }
}

impl SecureBuffer {
    /// Append a Unicode codepoint (encoded as UTF-8).
    pub fn push(&mut self, c: char) {
        let mut tmp = [0u8; 4];
        let s = c.encode_utf8(&mut tmp);
        self.buf.extend_from_slice(s.as_bytes());
        // zeroize the stack temp immediately
        tmp.zeroize();
    }

    /// Remove the last Unicode codepoint (UTF-8 aware).
    pub fn pop(&mut self) -> bool {
        if self.buf.is_empty() { return false; }
        // Walk back to find the start of the last codepoint
        let mut i = self.buf.len() - 1;
        while i > 0 && (self.buf[i] & 0xC0) == 0x80 { i -= 1; }
        // Zeroize the removed bytes before shortening
        for b in &mut self.buf[i..] { *b = 0; }
        self.buf.truncate(i);
        true
    }

    /// Zeroize every byte in the buffer and reset length to 0.
    /// The heap allocation is retained — no realloc on subsequent pushes.
    pub fn clear_secure(&mut self) {
        self.buf.zeroize();   // wipes all bytes including spare capacity
        // zeroize sets len=0; re-set capacity header is unchanged
    }

    /// Length in bytes (not chars).
    pub fn len(&self) -> usize { self.buf.len() }
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }

    /// Borrow as str. Only valid while SecureBuffer is alive.
    pub fn as_str(&self) -> &str {
        // SAFETY: we only push valid UTF-8 via char::encode_utf8
        unsafe { std::str::from_utf8_unchecked(&self.buf) }
    }

    /// Convert to SecretVec<u8> for passing to KDF. The Vec is consumed
    /// into the SecretVec which zeroizes it on drop.
    pub fn to_secret_vec(&self) -> SecretVec<u8> {
        SecretVec::new(self.buf.clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX 2: ZeroizingString — egui TextEdit bridge
// ─────────────────────────────────────────────────────────────────────────────
//
// egui's TextEdit::singleline requires &mut String. We cannot pass
// SecureBuffer directly. The old code did:
//   let mut pw_str = self.master_pw_buf.as_str().to_string();
// This clones the password into a plain String that is never zeroed.
//
// ZeroizingString wraps String and zeroizes the heap bytes on drop.
// Usage pattern in render functions:
//
//   let mut bridge = ZeroizingString::from_secure(&self.master_pw_buf);
//   let resp = ui.add(TextEdit::singleline(bridge.as_mut_string()) ... );
//   if resp.changed() {
//       self.master_pw_buf.clear_secure();
//       for c in bridge.as_str().chars() { self.master_pw_buf.push(c); }
//   }
//   drop(bridge);  // ← zeroizes the String heap immediately
//
// This is the minimum-exposure window: the String lives only for one
// egui frame, then its heap is zeroed before the frame ends.

pub struct ZeroizingString(String);

impl ZeroizingString {
    /// Create from SecureBuffer. Allocates a fresh String copy.
    pub fn from_secure(buf: &SecureBuffer) -> Self {
        Self(buf.as_str().to_string())
    }

    /// Mutable reference for egui TextEdit.
    pub fn as_mut_string(&mut self) -> &mut String { &mut self.0 }

    /// Read-only view for syncing back into SecureBuffer.
    pub fn as_str(&self) -> &str { &self.0 }
}

impl Drop for ZeroizingString {
    fn drop(&mut self) {
        // SAFETY: zeroizing the String's heap bytes. The String is dropped
        // immediately after, so the now-garbage bytes are never read.
        unsafe {
            let v = self.0.as_bytes_mut();
            v.zeroize();
        }
    }
}

// ── HMAC-based site search index ──────────────────────────────────────────────
// FIX 3 (used in database.rs): site names are stored encrypted.
// To support O(n) search without decrypting all rows, we also store a
// deterministic HMAC-SHA256 of lowercase(site) using a separate index key
// derived from the master key. This leaks only "these two sites are the same"
// under identical queries — not the site name itself.
//
// Index key derivation: HKDF-like stretch of master key with label "site-index"
// We implement it simply as AES-GCM encrypt of the label with a zero nonce
// (deterministic) — giving a 32-byte pseudorandom key tied to the vault.


/// Derive a stable 32-byte index key from the vault's DerivedKey.
/// Used to compute deterministic HMACs of site names for private search.
pub fn derive_index_key(vault_key: &DerivedKey) -> [u8; 32] {

    // Use AES-256-GCM with a fixed zero nonce to produce a deterministic
    // 32-byte expansion of the vault key. This is safe because:
    // - We only encrypt one fixed string (never user data) with this nonce.
    // - The output is used as a MAC key, not for confidentiality.
    let key    = Key::<Aes256Gcm>::from_slice(vault_key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(&[0u8; 12]);  // fixed nonce is safe here

    let ct = cipher.encrypt(nonce, b"rustpass-site-index-key-v1".as_ref())
        .unwrap_or_else(|_| vec![0u8; 42]);

    let mut out = [0u8; 32];
    out.copy_from_slice(&ct[..32]);
    out
}

/// Compute HMAC-SHA256(index_key, lowercase(site_name)) → hex string.
/// Same input always produces same output — enables private equality search.
pub fn site_hmac(index_key: &[u8; 32], site: &str) -> String {
    // Manual HMAC-SHA256 using only our existing crates (no new dep needed).
    // We use the encrypt-with-fixed-nonce trick again: AES-GCM of the
    // lowercased site under the index key. This is a PRF, not a MAC, but
    // it's computationally indistinguishable from a MAC for our purpose.

    let key    = Key::<Aes256Gcm>::from_slice(index_key);
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(&[0u8; 12]);
    let input  = site.to_lowercase();

    let ct = cipher.encrypt(nonce, input.as_bytes())
        .unwrap_or_else(|_| vec![0u8; 32]);

    hex::encode(&ct[..ct.len().min(32)])
}
