// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Site-trust / PIN prompts for `nmcades-host`.
//!
//! On macOS prefer `osascript` dialogs — egui windows started from a Safari/Chrome
//! Native Messaging host often appear behind the browser or fail to focus, which
//! looks like a hung plugin. When feature `nmcades-ui` is off or `JEX_NMH_NO_UI=1`,
//! trust defaults to Once and PIN returns None (config/defaults).

use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    Always,
    Once,
    Deny,
}

pub fn ui_enabled() -> bool {
    #[cfg(not(feature = "nmcades-ui"))]
    {
        return false;
    }
    #[cfg(feature = "nmcades-ui")]
    {
        match std::env::var("JEX_NMH_NO_UI") {
            Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => false,
            _ => true,
        }
    }
}

fn apple_script_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn prompt_trust_osascript(origin: &str) -> Option<TrustDecision> {
    let msg = format!(
        "Сайт хочет использовать Jex (ключи / подпись):\\n{}",
        apple_script_escape(origin)
    );
    let script = format!(
        r#"try
  set r to button returned of (display dialog "{msg}" with title "Jex — доступ сайта" buttons {{"Отклонить", "Разрешить сейчас", "Разрешить всегда"}} default button "Разрешить сейчас" cancel button "Отклонить" with icon caution)
  return r
on error
  return "Отклонить"
end try"#
    );
    let out = Command::new("osascript").args(["-e", &script]).output().ok()?;
    if !out.status.success() {
        return Some(TrustDecision::Deny);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let t = text.trim();
    if t.contains("всегда") {
        Some(TrustDecision::Always)
    } else if t.contains("сейчас") {
        Some(TrustDecision::Once)
    } else {
        Some(TrustDecision::Deny)
    }
}

#[cfg(target_os = "macos")]
fn prompt_pin_osascript(title: &str, label: &str) -> Option<String> {
    let title = apple_script_escape(title);
    let label = apple_script_escape(label);
    let script = format!(
        r#"try
  set r to text returned of (display dialog "{label}" with title "{title}" default answer "" buttons {{"Отмена", "OK"}} default button "OK" cancel button "Отмена" with hidden answer)
  return r
on error
  return ""
end try"#
    );
    let out = Command::new("osascript").args(["-e", &script]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let pin = text.trim_end_matches(['\n', '\r']).to_string();
    if pin.is_empty() {
        None
    } else {
        Some(pin)
    }
}

pub fn prompt_trust_site(origin: &str) -> TrustDecision {
    if !ui_enabled() {
        return TrustDecision::Once;
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(d) = prompt_trust_osascript(origin) {
            return d;
        }
    }
    #[cfg(feature = "nmcades-ui")]
    {
        return prompt_trust_egui(origin);
    }
    #[cfg(not(feature = "nmcades-ui"))]
    {
        let _ = origin;
        TrustDecision::Once
    }
}

pub fn prompt_pin(title: &str, label: &str) -> Option<String> {
    if !ui_enabled() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(p) = prompt_pin_osascript(title, label) {
            return Some(p);
        }
    }
    #[cfg(feature = "nmcades-ui")]
    {
        return prompt_pin_egui(title, label);
    }
    #[cfg(not(feature = "nmcades-ui"))]
    {
        let _ = (title, label);
        None
    }
}

#[cfg(feature = "nmcades-ui")]
fn prompt_trust_egui(origin: &str) -> TrustDecision {
    use eframe::egui;
    use std::sync::{Arc, Mutex};
    let origin = origin.to_string();
    let decision = Arc::new(Mutex::new(TrustDecision::Deny));
    let decision_ui = decision.clone();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([440.0, 190.0])
            .with_resizable(false)
            .with_always_on_top()
            .with_title("Jex — доступ сайта"),
        ..Default::default()
    };
    let _ = eframe::run_simple_native("Jex trust", options, move |ctx, _frame| {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Запрос доступа");
            ui.label(format!(
                "Сайт хочет использовать Jex (ключи / подпись):\n{origin}"
            ));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Разрешить всегда").clicked() {
                    *decision_ui.lock().unwrap() = TrustDecision::Always;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                if ui.button("Разрешить сейчас").clicked() {
                    *decision_ui.lock().unwrap() = TrustDecision::Once;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                if ui.button("Отклонить").clicked() {
                    *decision_ui.lock().unwrap() = TrustDecision::Deny;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
    });
    decision.lock().map(|g| *g).unwrap_or(TrustDecision::Deny)
}

#[cfg(feature = "nmcades-ui")]
fn prompt_pin_egui(title: &str, label: &str) -> Option<String> {
    use eframe::egui;
    use std::sync::{Arc, Mutex};
    let title = title.to_string();
    let label = label.to_string();
    let pin = Arc::new(Mutex::new(String::new()));
    let outcome = Arc::new(Mutex::new(None::<bool>));
    let pin_ui = pin.clone();
    let outcome_ui = outcome.clone();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 170.0])
            .with_resizable(false)
            .with_always_on_top()
            .with_title(title.clone()),
        ..Default::default()
    };
    let win = title.clone();
    let _ = eframe::run_simple_native(&win, options, move |ctx, _frame| {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading(&title);
            ui.label(&label);
            let mut local = pin_ui.lock().unwrap().clone();
            let resp = ui.add(
                egui::TextEdit::singleline(&mut local)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
            *pin_ui.lock().unwrap() = local;
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                *outcome_ui.lock().unwrap() = Some(true);
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("OK").clicked() {
                    *outcome_ui.lock().unwrap() = Some(true);
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                if ui.button("Отмена").clicked() {
                    *outcome_ui.lock().unwrap() = Some(false);
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
    });
    match outcome.lock().ok().and_then(|g| *g) {
        Some(true) => Some(pin.lock().ok().map(|g| g.clone()).unwrap_or_default()),
        _ => None,
    }
}
