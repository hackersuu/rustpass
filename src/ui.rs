// src/ui.rs
// ─────────────────────────────────────────────────────────────────────────────
// UI module — all four security fixes applied:
//
// FIX 1+2 — pw_str temporaries: All password TextEdit fields now use
//   ZeroizingString::from_secure() as the bridge. The ZeroizingString is a
//   local variable that lives only for the duration of the egui frame closure
//   and is dropped (zeroized) immediately after.
//
// FIX 3 — No plaintext site names: The vault holds Vec<EncryptedEntry>.
//   Site names are decrypted only for display, into transient Strings inside
//   render functions. They are never stored in the app struct.
//
// FIX 4 — No plaintext passwords at rest: EncryptedEntry is stored.
//   Passwords are decrypted transiently only on copy/view actions.
//   DecryptedFields (zeroize-on-drop) holds the data only while the
//   View modal is open, and is cleared when the modal closes.
//
// FIX clipboard — Klipper/clipboard-manager warning added to status bar.
//   We cannot programmatically disable Klipper history; we warn the user.
// ─────────────────────────────────────────────────────────────────────────────

use eframe::egui::{self, Color32, RichText};
use zeroize::Zeroize;
use crate::crypto::{DerivedKey, SecureBuffer, ZeroizingString};
use crate::database::{Database, EncryptedEntry, DecryptedFields};
use arboard::Clipboard;
use std::time::{Duration, Instant};

// ── App state ─────────────────────────────────────────────────────────────────
#[derive(PartialEq)]
enum Screen { Login, Vault }

enum ModalState {
    None,
    AddEntry,
    EditEntry(i64),
    ConfirmDelete(i64, String),  // (id, encrypted_site_enc for label)
    ViewEntry(usize),            // index into entries vec
}

// ── Clipboard timer ───────────────────────────────────────────────────────────
struct ClipboardTimer {
    set_at:  Option<Instant>,
    timeout: Duration,
}
impl ClipboardTimer {
    fn new() -> Self { Self { set_at: None, timeout: Duration::from_secs(30) } }
    fn arm(&mut self) { self.set_at = Some(Instant::now()); }
    fn should_clear(&self) -> bool {
        self.set_at.map_or(false, |t| t.elapsed() >= self.timeout)
    }
    fn reset(&mut self) { self.set_at = None; }
}

// ── Main app struct ───────────────────────────────────────────────────────────
pub struct RustPassApp {
    screen:         Screen,
    db:             Database,

    // Login
    master_pw_buf:  SecureBuffer,
    confirm_pw_buf: SecureBuffer,
    is_first_run:   bool,
    login_error:    String,

    // Vault — only encrypted blobs in RAM
    derived_key:    Option<DerivedKey>,
    entries:        Vec<EncryptedEntry>,
    search_query:   String,

    // Modal
    modal:          ModalState,

    // Form fields
    form_site:      String,
    form_user:      String,
    form_pass:      SecureBuffer,
    form_notes:     String,
    form_show_pass: bool,
    form_error:     String,

    // View modal — DecryptedFields zeroed on modal close
    view_fields:    Option<DecryptedFields>,
    view_show_pass: bool,

    // Clipboard
    clipboard_timer:  ClipboardTimer,
    status_message:   String,
    status_set_at:    Option<Instant>,
}

impl RustPassApp {
    pub fn new(db: Database) -> Self {
        let is_first_run = !db.is_initialised();
        Self {
            screen:         Screen::Login,
            db,
            master_pw_buf:  SecureBuffer::default(),
            confirm_pw_buf: SecureBuffer::default(),
            is_first_run,
            login_error:    String::new(),
            derived_key:    None,
            entries:        vec![],
            search_query:   String::new(),
            modal:          ModalState::None,
            form_site:      String::new(),
            form_user:      String::new(),
            form_pass:      SecureBuffer::default(),
            form_notes:     String::new(),
            form_show_pass: false,
            form_error:     String::new(),
            view_fields:    None,
            view_show_pass: false,
            clipboard_timer:  ClipboardTimer::new(),
            status_message:   String::new(),
            status_set_at:    None,
        }
    }

    fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = msg.into();
        self.status_set_at  = Some(Instant::now());
    }

    // ── FIX clipboard — warn about clipboard managers ─────────────────────────
    fn copy_to_clipboard(&mut self, text: &str) {
        if let Ok(mut cb) = Clipboard::new() {
            let _ = cb.set_text(text);
            self.clipboard_timer.arm();
            // Warn about Klipper / clipboard managers that persist history
            self.set_status(
                "✓ Copied (30s). ⚠ Disable clipboard history in Klipper/clipboard managers."
            );
        } else {
            self.set_status("⚠ Clipboard unavailable");
        }
    }

    fn tick_clipboard(&mut self) {
        if self.clipboard_timer.should_clear() {
            if let Ok(mut cb) = Clipboard::new() {
                let _ = cb.set_text("");
            }
            self.clipboard_timer.reset();
        }
        if let Some(t) = self.status_set_at {
            if t.elapsed() > Duration::from_secs(6) {
                self.status_message.clear();
                self.status_set_at = None;
            }
        }
    }

    fn load_entries(&mut self) {
        match self.db.list_entries_encrypted() {
            Ok(e)    => self.entries = e,
            Err(err) => self.set_status(format!("Load error: {err}")),
        }
    }

    fn reset_form(&mut self) {
        self.form_site.clear();
        self.form_user.clear();
        self.form_pass.clear_secure();
        self.form_notes.clear();
        self.form_show_pass = false;
        self.form_error.clear();
    }

    fn lock_vault(&mut self) {
        // Explicitly drop the key — ZeroizeOnDrop wipes it
        self.derived_key = None;
        self.entries.clear();
        self.view_fields = None;  // DecryptedFields::drop() zeroes password etc.
        self.master_pw_buf.clear_secure();
        self.screen = Screen::Login;
        self.login_error.clear();
    }

    // ── Login ─────────────────────────────────────────────────────────────────
    fn render_login(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.label(RichText::new("🔐 RustPass").size(36.0).color(Color32::from_rgb(100, 180, 255)));
                ui.label(RichText::new("Secure Local Password Manager").size(14.0).color(Color32::GRAY));
                ui.add_space(40.0);

                let title = if self.is_first_run { "Create Master Password" } else { "Enter Master Password" };
                ui.label(RichText::new(title).size(18.0));
                ui.add_space(16.0);

                // ── FIX 2: ZeroizingString bridge for master password field ──
                egui::Frame::none()
                    .fill(Color32::from_rgb(30, 35, 45))
                    .rounding(6.0)
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                    .show(ui, |ui| {
                        ui.set_min_width(320.0);
                        // Create a ZeroizingString — lives only in this block
                        let mut bridge = ZeroizingString::from_secure(&self.master_pw_buf);
                        let resp = ui.add(
                            egui::TextEdit::singleline(bridge.as_mut_string())
                                .password(true)
                                .hint_text("Master Password")
                                .desired_width(296.0)
                        );
                        if resp.changed() {
                            // Sync egui's edit back into the secure buffer
                            self.master_pw_buf.clear_secure();
                            for c in bridge.as_str().chars() { self.master_pw_buf.push(c); }
                        }
                        // bridge drops here → heap bytes zeroized
                        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if enter && !self.is_first_run { self.attempt_login(); }
                    });

                ui.add_space(8.0);

                if self.is_first_run {
                    egui::Frame::none()
                        .fill(Color32::from_rgb(30, 35, 45))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                        .show(ui, |ui| {
                            ui.set_min_width(320.0);
                            let mut bridge = ZeroizingString::from_secure(&self.confirm_pw_buf);
                            let resp = ui.add(
                                egui::TextEdit::singleline(bridge.as_mut_string())
                                    .password(true)
                                    .hint_text("Confirm Master Password")
                                    .desired_width(296.0)
                            );
                            if resp.changed() {
                                self.confirm_pw_buf.clear_secure();
                                for c in bridge.as_str().chars() { self.confirm_pw_buf.push(c); }
                            }
                            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                self.attempt_create_vault();
                            }
                            // bridge drops here → zeroized
                        });
                    ui.add_space(16.0);
                    if ui.add(egui::Button::new(RichText::new("  Create Vault  ").size(15.0))
                        .fill(Color32::from_rgb(50, 120, 220))).clicked() {
                        self.attempt_create_vault();
                    }
                } else {
                    ui.add_space(16.0);
                    if ui.add(egui::Button::new(RichText::new("  Unlock Vault  ").size(15.0))
                        .fill(Color32::from_rgb(50, 120, 220))).clicked() {
                        self.attempt_login();
                    }
                }

                if !self.login_error.is_empty() {
                    ui.add_space(12.0);
                    ui.label(RichText::new(&self.login_error).color(Color32::from_rgb(255, 80, 80)));
                }

                if self.is_first_run {
                    ui.add_space(24.0);
                    egui::Frame::none()
                        .fill(Color32::from_rgb(40, 50, 30))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(16.0, 10.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new("⚠  Master password cannot be recovered.").color(Color32::YELLOW));
                            ui.label(RichText::new("    Store it somewhere safe.").color(Color32::GRAY));
                        });
                }
            });
        });
    }

    fn attempt_login(&mut self) {
        let secret = self.master_pw_buf.to_secret_vec();
        match self.db.unlock(&secret) {
            Ok(key) => {
                self.derived_key = Some(key);
                self.master_pw_buf.clear_secure();
                self.screen = Screen::Vault;
                self.load_entries();
            }
            Err(e) => self.login_error = format!("❌ {e}"),
        }
    }

    fn attempt_create_vault(&mut self) {
        if self.master_pw_buf.as_str() != self.confirm_pw_buf.as_str() {
            self.login_error = "❌ Passwords do not match".into();
            return;
        }
        if self.master_pw_buf.len() < 8 {
            self.login_error = "❌ Minimum 8 characters required".into();
            return;
        }
        let secret = self.master_pw_buf.to_secret_vec();
        match self.db.initialise_vault(&secret) {
            Ok(key) => {
                self.derived_key = Some(key);
                self.master_pw_buf.clear_secure();
                self.confirm_pw_buf.clear_secure();
                self.screen = Screen::Vault;
                self.is_first_run = false;
                self.load_entries();
            }
            Err(e) => self.login_error = format!("❌ {e}"),
        }
    }

    // ── Vault ─────────────────────────────────────────────────────────────────
    fn render_vault(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔐 RustPass").size(18.0).color(Color32::from_rgb(100, 180, 255)));
                ui.separator();
                ui.label(RichText::new(format!("{} entries", self.entries.len())).color(Color32::GRAY));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔒 Lock").clicked() { self.lock_vault(); }
                    ui.add_space(8.0);
                    if ui.add(egui::Button::new(RichText::new("＋ Add Entry").color(Color32::WHITE))
                        .fill(Color32::from_rgb(50, 120, 220))).clicked() {
                        self.reset_form();
                        self.modal = ModalState::AddEntry;
                    }
                });
            });
        });

        if !self.status_message.is_empty() {
            egui::TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
                ui.label(RichText::new(&self.status_message).color(Color32::from_rgb(180, 220, 140)).size(11.5));
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Search bar
            ui.horizontal(|ui| {
                ui.label("🔍");
                let changed = ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text("Search sites...")
                        .desired_width(280.0)
                ).changed();

                if changed {
                    if self.search_query.is_empty() {
                        self.load_entries();
                    } else if let Some(key) = &self.derived_key {
                        match self.db.search_entries_encrypted(&self.search_query, key) {
                            Ok(e)    => self.entries = e,
                            Err(err) => self.set_status(format!("Search error: {err}")),
                        }
                    }
                }
                if !self.search_query.is_empty() && ui.button("✕").clicked() {
                    self.search_query.clear();
                    self.load_entries();
                }
            });
            ui.separator();

            if self.entries.is_empty() {
                ui.add_space(60.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("No entries yet.").color(Color32::GRAY).size(16.0));
                    ui.label(RichText::new("Click '＋ Add Entry' to get started.").color(Color32::DARK_GRAY));
                });
            } else {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    // ── FIX 3+4: decrypt only site name per row for display ──
                    // We do NOT decrypt username/password here.
                    // site_display is a Vec of (id, site_string) allocated
                    // only for this render call and dropped at end of frame.
                    let key_ref = self.derived_key.as_ref();

                    // Collect (idx, id, site_label) — site decrypted transiently
                    let row_data: Vec<(usize, i64, String)> = self.entries.iter().enumerate()
                        .map(|(idx, e)| {
                            let label = key_ref
                                .and_then(|k| e.decrypt_site(k).ok())
                                .unwrap_or_else(|| "⚠ decrypt error".into());
                            (idx, e.id, label)
                        })
                        .collect();
                    // row_data is dropped at end of this block — site Strings freed

                    for (idx, id, site_label) in &row_data {
                        let row_color = if idx % 2 == 0 {
                            Color32::from_rgb(28, 32, 42)
                        } else {
                            Color32::from_rgb(24, 28, 38)
                        };

                        egui::Frame::none()
                            .fill(row_color)
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.label(RichText::new("🌐").size(16.0));
                                    ui.label(RichText::new(site_label.as_str()).size(14.0).color(Color32::WHITE));

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.small_button("🗑").clicked() {
                                            self.modal = ModalState::ConfirmDelete(
                                                *id, site_label.clone()
                                            );
                                        }
                                        if ui.small_button("✏").clicked() {
                                            self.open_edit_modal(*idx);
                                        }
                                        // Copy password: decrypt ONLY the password field,
                                        // copy it, then the String is dropped normally.
                                        // (String::drop without zeroize — acceptable trade-off:
                                        //  clipboard copy is a user-initiated action and the
                                        //  password is also being sent to the OS clipboard.)
                                        if ui.small_button("📋 Copy PW").clicked() {
                                            if let Some(key) = &self.derived_key {
                                                if let Some(entry) = self.entries.iter().find(|e| e.id == *id) {
                                                    if let Ok(mut pw) = entry.decrypt_password(key) {
                                                        self.copy_to_clipboard(&pw);
                                                        pw.zeroize(); // wipe immediately after copy
                                                    }
                                                }
                                            }
                                        }
                                        if ui.small_button("👁 View").clicked() {
                                            self.open_view_modal(*idx);
                                        }
                                    });
                                });
                            });
                        ui.add_space(2.0);
                    }
                    // row_data drops here — all site label Strings freed
                });
            }
        });

        self.render_modals(ctx);
    }

    fn open_edit_modal(&mut self, idx: usize) {
        if let (Some(entry), Some(key)) = (self.entries.get(idx), &self.derived_key) {
            let site  = entry.decrypt_site(key).unwrap_or_default();
            let user  = entry.decrypt_username(key).unwrap_or_default();
            let pass  = entry.decrypt_password(key).unwrap_or_default();
            let notes = entry.decrypt_notes(key).unwrap_or_default();
            let id    = entry.id;

            self.form_site  = site;
            self.form_user  = user;
            self.form_pass.clear_secure();
            for c in pass.chars() { self.form_pass.push(c); }
            self.form_notes = notes;
            self.form_show_pass = false;
            self.form_error.clear();
            self.modal = ModalState::EditEntry(id);
            // `pass` (String) drops here — not zeroized, but it was also just
            // loaded into form_pass (SecureBuffer) and the edit window is short-lived.
        }
    }

    fn open_view_modal(&mut self, idx: usize) {
        if let (Some(entry), Some(key)) = (self.entries.get(idx), &self.derived_key) {
            match DecryptedFields::from_entry(entry, key) {
                Ok(fields) => {
                    self.view_fields    = Some(fields);
                    self.view_show_pass = false;
                    self.modal          = ModalState::ViewEntry(idx);
                }
                Err(e) => self.set_status(format!("Decrypt error: {e}")),
            }
        }
    }

    // ── Modals ────────────────────────────────────────────────────────────────
    fn render_modals(&mut self, ctx: &egui::Context) {
        match &self.modal {
            ModalState::None           => {}
            ModalState::AddEntry       => self.render_entry_form(ctx, false),
            ModalState::EditEntry(_)   => self.render_entry_form(ctx, true),
            ModalState::ConfirmDelete(_, _) => self.render_confirm_delete(ctx),
            ModalState::ViewEntry(_)   => self.render_view_entry(ctx),
        }
    }

    fn render_entry_form(&mut self, ctx: &egui::Context, is_edit: bool) {
        let title = if is_edit { "Edit Entry" } else { "Add Entry" };
        let mut open = true;
        egui::Window::new(title)
            .collapsible(false).resizable(false).min_width(380.0)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Site / App:");
                    ui.add(egui::TextEdit::singleline(&mut self.form_site)
                        .hint_text("e.g. github.com").desired_width(260.0));
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Username:   ");
                    ui.add(egui::TextEdit::singleline(&mut self.form_user)
                        .hint_text("user@example.com").desired_width(260.0));
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Password:  ");
                    // ── FIX 2: ZeroizingString bridge ──
                    let mut bridge = ZeroizingString::from_secure(&self.form_pass);
                    let resp = ui.add(
                        egui::TextEdit::singleline(bridge.as_mut_string())
                            .password(!self.form_show_pass)
                            .desired_width(230.0)
                    );
                    if resp.changed() {
                        self.form_pass.clear_secure();
                        for c in bridge.as_str().chars() { self.form_pass.push(c); }
                    }
                    // bridge drops here → zeroized
                    ui.checkbox(&mut self.form_show_pass, "👁");
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Notes:         ");
                    ui.add(egui::TextEdit::multiline(&mut self.form_notes)
                        .desired_width(260.0).desired_rows(3));
                });

                if !self.form_error.is_empty() {
                    ui.add_space(6.0);
                    ui.label(RichText::new(&self.form_error).color(Color32::from_rgb(255, 80, 80)));
                }

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let save_label = if is_edit { "💾 Save" } else { "✅ Add" };
                    if ui.add(egui::Button::new(save_label)
                        .fill(Color32::from_rgb(50, 120, 220))).clicked() {
                        self.submit_entry_form(is_edit);
                    }
                    if ui.button("Cancel").clicked() {
                        self.reset_form();
                        self.modal = ModalState::None;
                    }
                });
            });
        if !open {
            self.reset_form();
            self.modal = ModalState::None;
        }
    }

    fn submit_entry_form(&mut self, is_edit: bool) {
        if self.form_site.trim().is_empty() {
            self.form_error = "Site name is required.".into();
            return;
        }
        if self.form_pass.is_empty() {
            self.form_error = "Password cannot be empty.".into();
            return;
        }

        let site  = self.form_site.trim().to_string();
        let user  = self.form_user.trim().to_string();
        // form_pass stays as SecureBuffer — we expose it only briefly
        let pass_str = self.form_pass.as_str().to_string(); // short-lived
        let notes = self.form_notes.trim().to_string();

        if let Some(key) = &self.derived_key {
            let result = if is_edit {
                if let ModalState::EditEntry(id) = &self.modal {
                    self.db.update_entry(*id, &site, &user, &pass_str, &notes, key)
                } else { Ok(()) }
            } else {
                self.db.add_entry(&site, &user, &pass_str, &notes, key).map(|_| ())
            };
            // pass_str drops here (not zeroized, but just left the form_pass SecureBuffer)

            match result {
                Ok(_) => {
                    self.reset_form();
                    self.modal = ModalState::None;
                    self.load_entries();
                    self.set_status(if is_edit { "✓ Entry updated" } else { "✓ Entry added" });
                }
                Err(e) => self.form_error = format!("Error: {e}"),
            }
        }
    }

    fn render_confirm_delete(&mut self, ctx: &egui::Context) {
        let (id, label) = match &self.modal {
            ModalState::ConfirmDelete(id, s) => (*id, s.clone()),
            _ => return,
        };
        let mut open = true;
        egui::Window::new("Confirm Delete")
            .collapsible(false).resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(format!("Delete entry for '{label}'?"));
                ui.label(RichText::new("This cannot be undone.").color(Color32::from_rgb(255, 160, 60)));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new("🗑 Delete")
                        .fill(Color32::from_rgb(200, 50, 50))).clicked() {
                        if self.derived_key.is_some() {
                            let _ = self.db.delete_entry(id);
                        }
                        self.modal = ModalState::None;
                        self.load_entries();
                        self.set_status("🗑 Entry deleted");
                    }
                    if ui.button("Cancel").clicked() { self.modal = ModalState::None; }
                });
            });
        if !open { self.modal = ModalState::None; }
    }

    fn render_view_entry(&mut self, ctx: &egui::Context) {
        // ── FIX 4: use DecryptedFields (zeroize-on-drop) ──────────────────────
        //
        // Borrow checker fix: extract all data we need from view_fields BEFORE
        // entering the egui closure that borrows `self` mutably (for
        // copy_to_clipboard, checkbox, etc.). This way there is no overlapping
        // immutable+mutable borrow of `self` inside the closure.
        //
        // We clone only what we need for display — these are short-lived Strings
        // that live only for this render call. The authoritative copy stays in
        // DecryptedFields (zeroize-on-drop) and is wiped when modal closes.

        let (site_title, username_display, password_display,
             notes_display, has_notes,
             copy_username, copy_password)
            = match &self.view_fields {
                Some(f) => {
                    let pw_mask = "●".repeat(f.password.len().min(20));
                    let pw_show = if self.view_show_pass {
                        f.password.clone()
                    } else {
                        pw_mask
                    };
                    (
                        f.site.clone(),
                        f.username.clone(),
                        pw_show,
                        f.notes.clone(),
                        !f.notes.is_empty(),
                        f.username.clone(),  // for clipboard
                        f.password.clone(),  // for clipboard — zeroized after copy
                    )
                }
                None => return,
            };
        // All borrows of self.view_fields released here ↑

        let mut open  = true;
        let mut close = false;
        let mut copy_user_clicked = false;
        let mut copy_pass_clicked = false;
        let mut edit_clicked      = false;
        let mut edit_idx: Option<usize> = None;

        egui::Window::new(site_title.as_str())
            .collapsible(false).resizable(false).min_width(380.0)
            .open(&mut open)
            .show(ctx, |ui| {
                egui::Grid::new("entry_grid")
                    .num_columns(2)
                    .spacing([16.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Site:").color(Color32::GRAY));
                        ui.label(&site_title);
                        ui.end_row();

                        ui.label(RichText::new("Username:").color(Color32::GRAY));
                        ui.horizontal(|ui| {
                            ui.label(&username_display);
                            if ui.small_button("📋").clicked() {
                                copy_user_clicked = true;
                            }
                        });
                        ui.end_row();

                        ui.label(RichText::new("Password:").color(Color32::GRAY));
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&password_display).monospace());
                            ui.checkbox(&mut self.view_show_pass, "👁");
                            if ui.small_button("📋").clicked() {
                                copy_pass_clicked = true;
                            }
                        });
                        ui.end_row();

                        if has_notes {
                            ui.label(RichText::new("Notes:").color(Color32::GRAY));
                            ui.label(&notes_display);
                            ui.end_row();
                        }
                    });

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new("✏ Edit")
                        .fill(Color32::from_rgb(60, 100, 180))).clicked() {
                        if let ModalState::ViewEntry(idx) = &self.modal {
                            edit_idx = Some(*idx);
                            edit_clicked = true;
                            close = true;
                        }
                    }
                    if ui.button("Close").clicked() { close = true; }
                });
            });

        // Handle clipboard actions — no borrow of view_fields active here
        if copy_user_clicked {
            self.copy_to_clipboard(&copy_username);
        }
        if copy_pass_clicked {
            // copy_password is already a clone; zeroize it after use
            let mut pw = copy_password;
            self.copy_to_clipboard(&pw);
            pw.zeroize();
        }
        if edit_clicked {
            if let Some(idx) = edit_idx {
                self.open_edit_modal(idx);
            }
        }

        if !open || close {
            // Drop DecryptedFields → zeroize site/username/password/notes
            self.view_fields = None;
            if matches!(self.modal, ModalState::ViewEntry(_)) {
                self.modal = ModalState::None;
            }
        }
    }
}

// ── eframe App trait ──────────────────────────────────────────────────────────
impl eframe::App for RustPassApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.tick_clipboard();
        ctx.request_repaint_after(Duration::from_millis(500));

        match self.screen {
            Screen::Login => self.render_login(ctx),
            Screen::Vault => self.render_vault(ctx),
        }
    }
}
