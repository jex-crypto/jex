// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Interactive Ratatui screens for `rutoken containers` / `rutoken inspect`.
//!
//! When stdin/stdout are not both a terminal (piped output, CI, scripts),
//! these functions fall back to a plain, uncolored text dump instead of
//! entering the alternate screen — Ratatui's crossterm backend assumes an
//! interactive terminal.

use crate::{container::ClassicContainer, x509};
use anyhow::Result;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use std::io::IsTerminal;

pub fn is_interactive() -> bool {
    std::io::stdout().is_terminal() && std::io::stdin().is_terminal()
}

/// Card-derived data for one `rutoken containers` row.
pub struct ContainerRow {
    pub index: usize,
    pub uuid: Option<String>,
    pub subject_cn: Option<String>,
    pub check: Option<Result<x509::CertCheck>>,
}

/// One colored line of a details view (`rutoken inspect`).
struct DetailLine {
    text: String,
    color: Option<Color>,
}

fn detail(text: impl Into<String>) -> DetailLine {
    DetailLine {
        text: text.into(),
        color: None,
    }
}

fn detail_colored(text: impl Into<String>, color: Color) -> DetailLine {
    DetailLine {
        text: text.into(),
        color: Some(color),
    }
}

fn validity_display(v: &x509::CertValidity, now: i64) -> (String, Color) {
    let ok = v.is_valid_at(now);
    (
        format!("{} .. {}", v.not_before, v.not_after),
        if ok { Color::Green } else { Color::Red },
    )
}

/// Revocation-status text/color. Certificates already invalid by date are
/// never revocation-checked (see `validation::check_certificate`), so this
/// always reports "N/A" for them rather than a misleading "not checked".
fn revocation_display(
    status: Option<&x509::RevocationCheckResult>,
    date_ok: bool,
) -> (String, Color) {
    if !date_ok {
        return ("N/A (expired)".into(), Color::DarkGray);
    }
    match status {
        Some(s @ x509::RevocationCheckResult::Good) => (s.label(), Color::Green),
        Some(s @ x509::RevocationCheckResult::Revoked { .. }) => (s.label(), Color::Red),
        Some(s @ x509::RevocationCheckResult::Unknown) => (s.label(), Color::Yellow),
        None => ("not checked".into(), Color::DarkGray),
    }
}

struct RowText {
    index: String,
    uuid: String,
    subject_cn: String,
    validity: (String, Color),
    revocation: (String, Color),
}

fn row_text(row: &ContainerRow, now: i64) -> RowText {
    let (validity, revocation) = match &row.check {
        Some(Ok(check)) => {
            let date_ok = check.validity.is_valid_at(now);
            (
                validity_display(&check.validity, now),
                revocation_display(check.revocation_status.as_ref(), date_ok),
            )
        }
        Some(Err(e)) => (
            (format!("parse error: {e}"), Color::Red),
            ("-".to_string(), Color::DarkGray),
        ),
        None => (
            ("-".to_string(), Color::DarkGray),
            ("-".to_string(), Color::DarkGray),
        ),
    };
    RowText {
        index: row.index.to_string(),
        uuid: row.uuid.clone().unwrap_or_else(|| "-".into()),
        subject_cn: row.subject_cn.clone().unwrap_or_else(|| "-".into()),
        validity,
        revocation,
    }
}

const CONTAINERS_HELP: &str = "↑/↓ (j/k) navigate · g/G first/last · q/Esc quit";

/// Render `rutoken containers` output: an interactive, scrollable table in
/// a real terminal, or a plain aligned text dump otherwise.
pub fn run_containers_table(rows: &[ContainerRow], now: i64) -> Result<()> {
    println!("classic containers: {}", rows.len());
    if rows.is_empty() {
        return Ok(());
    }
    if !is_interactive() {
        print_plain_containers(rows, now);
        return Ok(());
    }

    let texts: Vec<RowText> = rows.iter().map(|r| row_text(r, now)).collect();
    let mut state = TableState::default();
    state.select(Some(0));

    let mut terminal = ratatui::try_init()?;
    let result = (|| -> Result<()> {
        loop {
            terminal.draw(|f| draw_containers(f, &texts, &mut state))?;
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                let len = texts.len();
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Down | KeyCode::Char('j') => select_move(&mut state, len, 1),
                    KeyCode::Up | KeyCode::Char('k') => select_move(&mut state, len, -1),
                    KeyCode::Home | KeyCode::Char('g') => state.select(Some(0)),
                    KeyCode::End | KeyCode::Char('G') => state.select(Some(len - 1)),
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

fn select_move(state: &mut TableState, len: usize, delta: i64) {
    if len == 0 {
        return;
    }
    let current = state.selected().unwrap_or(0) as i64;
    let next = (current + delta).clamp(0, len as i64 - 1);
    state.select(Some(next as usize));
}

fn draw_containers(f: &mut Frame, texts: &[RowText], state: &mut TableState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(f.area());

    let header = Row::new(vec!["#", "UUID", "Subject CN", "Validity", "Revocation"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let rows = texts.iter().map(|t| {
        Row::new(vec![
            Cell::new(t.index.clone()),
            Cell::new(t.uuid.clone()),
            Cell::new(t.subject_cn.clone()),
            Cell::new(t.validity.0.clone()).style(Style::default().fg(t.validity.1)),
            Cell::new(t.revocation.0.clone()).style(Style::default().fg(t.revocation.1)),
        ])
    });
    let widths = [
        Constraint::Length(4),
        Constraint::Length(36),
        Constraint::Percentage(30),
        Constraint::Length(21),
        Constraint::Min(14),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" classic containers "),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    f.render_stateful_widget(table, chunks[0], state);

    let footer = Paragraph::new(CONTAINERS_HELP).style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[1]);
}

fn print_plain_containers(rows: &[ContainerRow], now: i64) {
    let texts: Vec<RowText> = rows.iter().map(|r| row_text(r, now)).collect();
    let headers = ["#", "UUID", "Subject CN", "Validity", "Revocation"];
    let mut widths = headers.map(str::len);
    let as_cells = |t: &RowText| {
        [
            t.index.clone(),
            t.uuid.clone(),
            t.subject_cn.clone(),
            t.validity.0.clone(),
            t.revocation.0.clone(),
        ]
    };
    let plain_rows: Vec<[String; 5]> = texts.iter().map(as_cells).collect();
    for row in &plain_rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let print_row = |cells: &[String]| {
        let line = cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<width$}", width = widths[i]))
            .collect::<Vec<_>>()
            .join("  ");
        println!("{}", line.trim_end());
    };
    print_row(&headers.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    for row in &plain_rows {
        print_row(row);
    }
}

/// Render `rutoken inspect` output: an interactive scrollable details view
/// in a real terminal, or a plain text dump otherwise.
pub fn run_container_details(
    c: &ClassicContainer,
    source: &str,
    check: Option<&Result<x509::CertCheck>>,
    now: i64,
) -> Result<()> {
    let lines = build_detail_lines(c, source, check, now);
    if !is_interactive() {
        for line in &lines {
            println!("{}", line.text);
        }
        return Ok(());
    }

    let mut scroll: u16 = 0;
    let mut terminal = ratatui::try_init()?;
    let result = (|| -> Result<()> {
        loop {
            terminal.draw(|f| draw_details(f, &lines, scroll))?;
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Down | KeyCode::Char('j') => scroll = scroll.saturating_add(1),
                    KeyCode::Up | KeyCode::Char('k') => scroll = scroll.saturating_sub(1),
                    KeyCode::Home | KeyCode::Char('g') => scroll = 0,
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

fn build_detail_lines(
    c: &ClassicContainer,
    source: &str,
    check: Option<&Result<x509::CertCheck>>,
    now: i64,
) -> Vec<DetailLine> {
    let mut lines = Vec::new();
    lines.push(detail(format!("source: {source}")));
    lines.push(detail(format!("name: {}", crate::format_container_name(c))));
    if let Some(uuid) = &c.uuid {
        lines.push(detail(format!("uuid: {uuid}")));
    }
    lines.push(detail(format!("curve: {} ({})", c.curve.name, c.curve.oid)));
    lines.push(detail(format!("private size: {} bits", c.curve.bytes * 8)));

    match c.certificate.as_deref() {
        Some(cert) => {
            lines.push(detail(format!("certificate: {} bytes", cert.len())));
            if let Ok(Some(cn)) = x509::extract_subject_cn(cert) {
                lines.push(detail(format!("subject CN: {cn}")));
            }
            match check {
                Some(Ok(check)) => {
                    let (validity_text, validity_color) = validity_display(&check.validity, now);
                    lines.push(detail_colored(
                        format!("validity: {validity_text}"),
                        validity_color,
                    ));
                    let date_ok = check.validity.is_valid_at(now);
                    let (revocation_text, revocation_color) =
                        revocation_display(check.revocation_status.as_ref(), date_ok);
                    lines.push(detail_colored(
                        format!("revocation: {revocation_text}"),
                        revocation_color,
                    ));
                }
                Some(Err(e)) => {
                    lines.push(detail_colored(
                        format!("validity: parse error: {e}"),
                        Color::Red,
                    ));
                }
                None => {
                    if let Ok(validity) = x509::validity(cert) {
                        let (validity_text, validity_color) = validity_display(&validity, now);
                        lines.push(detail_colored(
                            format!("validity: {validity_text}"),
                            validity_color,
                        ));
                    }
                }
            }
        }
        None => {
            lines.push(detail_colored("certificate: <not found>", Color::Yellow));
        }
    }

    match c.primary_fp {
        Some(fp) => lines.push(detail(format!("primaryFP: {}", hex::encode(fp)))),
        None => lines.push(detail("primaryFP: <not found>")),
    }

    if c.oids.is_empty() {
        lines.push(detail("OIDs: -"));
    } else {
        lines.push(detail("OIDs:"));
        for oid in &c.oids {
            let described = match crate::oids::describe(oid) {
                Some(label) => format!("  {oid}  {label}"),
                None => format!("  {oid}"),
            };
            lines.push(detail(described));
        }
    }
    lines
}

fn draw_details(f: &mut Frame, lines: &[DetailLine], scroll: u16) {
    let text: Vec<Line> = lines
        .iter()
        .map(|l| {
            let span = match l.color {
                Some(color) => Span::styled(l.text.clone(), Style::default().fg(color)),
                None => Span::raw(l.text.clone()),
            };
            Line::from(span)
        })
        .collect();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(f.area());

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" container details "),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(paragraph, chunks[0]);

    let footer = Paragraph::new("↑/↓ (j/k) scroll · g top · q/Esc quit")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[1]);
}
