// src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod database;
mod ui;

use eframe::{egui, NativeOptions};
use database::Database;
use ui::RustPassApp;

fn main() -> eframe::Result<()> {
    let db_path = Database::default_path();

    let db = Database::open(&db_path)
        .unwrap_or_else(|e| {
            eprintln!("Fatal: cannot open database at {}: {e}", db_path.display());
            std::process::exit(1);
        });

    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RustPass — Secure Password Manager")
            .with_inner_size([780.0, 560.0])
            .with_min_inner_size([600.0, 400.0])
            .with_icon(load_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "RustPass",
        options,
        Box::new(|cc| {
            configure_visuals(&cc.egui_ctx);
            Box::new(RustPassApp::new(db))
        }),
    )
}

fn configure_visuals(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    visuals.window_rounding = egui::Rounding::same(8.0);
    // egui 0.27: no `extrusion` field — use Shadow::default() and override color
    visuals.window_shadow.color = egui::Color32::from_black_alpha(80);

    visuals.panel_fill                     = egui::Color32::from_rgb(20, 24, 34);
    visuals.faint_bg_color                 = egui::Color32::from_rgb(26, 30, 42);
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(30, 35, 48);
    visuals.widgets.inactive.bg_fill       = egui::Color32::from_rgb(38, 44, 58);
    visuals.widgets.hovered.bg_fill        = egui::Color32::from_rgb(50, 58, 76);
    visuals.widgets.active.bg_fill         = egui::Color32::from_rgb(60, 100, 200);
    visuals.selection.bg_fill              = egui::Color32::from_rgb(50, 100, 200);
    visuals.hyperlink_color                = egui::Color32::from_rgb(100, 180, 255);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(13.5, egui::FontFamily::Proportional),
    );
    ctx.set_style(style);
}

fn load_icon() -> egui::IconData {
    egui::IconData {
        rgba: vec![0, 0, 0, 0],
        width: 1,
        height: 1,
    }
}
