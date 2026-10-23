#![warn(clippy::all)]

use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Tabs};
use ratatui::{DefaultTerminal, Frame};
use serde::{Deserialize, Serialize};

const DAEMON_UDP_ADDR: &str = "127.0.0.1:18818";

/// Repeat / scroll mode for custom messages and triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScrollMode {
    Static,
    Once,
    Twice,
    ThreeTimes,
    FiveTimes,
    Continuous,
}

impl ScrollMode {
    pub const ALL: [ScrollMode; 6] = [
        ScrollMode::Static,
        ScrollMode::Once,
        ScrollMode::Twice,
        ScrollMode::ThreeTimes,
        ScrollMode::FiveTimes,
        ScrollMode::Continuous,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ScrollMode::Static => "Static (9 Digits)",
            ScrollMode::Once => "Scroll 1x",
            ScrollMode::Twice => "Scroll 2x",
            ScrollMode::ThreeTimes => "Scroll 3x",
            ScrollMode::FiveTimes => "Scroll 5x",
            ScrollMode::Continuous => "Continuous Loop",
        }
    }

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|&m| m == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let idx = Self::ALL.iter().position(|&m| m == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// A saved custom text trigger that can be fired on demand (hotkey F1..F9 or Enter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextTrigger {
    pub name: String,
    pub text: String,
    pub mode: ScrollMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusPane {
    Input,
    ScrollSelector,
    Triggers,
    Modes,
}

/// Map an ASCII character to the exact 8BitDo Retro 18 Numpad 7-segment byte (`0x00844644`).
pub fn char_to_seg7(ch: char) -> u8 {
    match ch {
        ' ' => 0x00,
        '0' | 'O' => 0x3F,
        '1' | 'I' => 0x06,
        '2' | 'Z' => 0x5B,
        '3' => 0x4F,
        '4' => 0x66,
        '5' | 'S' => 0x6D,
        '6' => 0x7D,
        '7' => 0x07,
        '8' => 0x7F,
        '9' => 0x6F,
        '-' => 0x40,
        '_' => 0x08,
        '=' | ':' => 0x48,
        '/' => 0x52,
        '!' => 0x86,
        '?' => 0x53,
        'A' | 'a' => 0x77,
        'B' | 'b' => 0x7C,
        'C' => 0x39,
        'c' => 0x58,
        'D' | 'd' => 0x5E,
        'E' | 'e' => 0x79,
        'F' | 'f' => 0x71,
        'G' => 0x3D,
        'g' => 0x6F,
        'H' | 'X' | 'x' => 0x76,
        'h' => 0x74,
        'i' => 0x04,
        'J' | 'j' => 0x1E,
        'K' | 'k' => 0x75,
        'L' => 0x38,
        'l' => 0x30,
        'M' => 0x37,
        'm' | 'N' | 'n' => 0x54,
        'o' => 0x5C,
        'P' | 'p' => 0x73,
        'Q' | 'q' => 0x67,
        'R' | 'r' => 0x50,
        's' => 0x6D,
        'T' | 't' => 0x78,
        'U' | 'V' | 'W' => 0x3E,
        'u' | 'v' | 'w' => 0x1C,
        'Y' | 'y' => 0x6E,
        'z' => 0x5B,
        _ => 0x00,
    }
}

/// Encode arbitrary text into a sequence of 7-segment bytes (with `.` merging into bit 7).
pub fn encode_7seg_sequence(text: &str) -> Vec<u8> {
    let mut digits = Vec::new();
    for ch in text.chars() {
        if ch == '.' {
            if let Some(last) = digits.last_mut()
                && (*last & 0x80) == 0
            {
                *last |= 0x80;
                continue;
            }
            digits.push(0x80);
        } else {
            digits.push(char_to_seg7(ch));
        }
    }
    digits
}

/// Encode text into a right-aligned 9-byte framebuffer.
pub fn encode_7seg_fixed(text: &str) -> [u8; 9] {
    let seq = encode_7seg_sequence(text);
    let mut out = [0u8; 9];
    if seq.len() >= 9 {
        out.copy_from_slice(&seq[..9]);
    } else {
        let pad = 9 - seq.len();
        out[pad..].copy_from_slice(&seq);
    }
    out
}

/// Render a single 7-segment byte as a 3-line-tall, 5-char-wide retro LED digit.
pub fn render_digit_lines(seg: u8) -> [String; 3] {
    let a = (seg & 0x01) != 0;
    let b = (seg & 0x02) != 0;
    let c = (seg & 0x04) != 0;
    let d = (seg & 0x08) != 0;
    let e = (seg & 0x10) != 0;
    let f = (seg & 0x20) != 0;
    let g = (seg & 0x40) != 0;
    let dp = (seg & 0x80) != 0;

    let top = format!(" {}  ", if a { "━━" } else { "  " });
    let mid = format!(
        "{}{}{}{} ",
        if f { "┃" } else { " " },
        if g { "━━" } else { "  " },
        if b { "┃" } else { " " },
        ""
    );
    let bot = format!(
        "{}{}{}{}",
        if e { "┃" } else { " " },
        if d { "━━" } else { "  " },
        if c { "┃" } else { " " },
        if dp { "•" } else { " " }
    );
    [top, mid, bot]
}

pub struct App {
    input_text: String,
    scroll_mode: ScrollMode,
    triggers: Vec<TextTrigger>,
    trigger_state: ListState,
    focus: FocusPane,
    daemon_mode_idx: usize,
    status_msg: String,
    preview_offset: usize,
    last_tick: Instant,
    triggers_path: PathBuf,
}

impl App {
    const DAEMON_MODES: [(&'static str, &'static str); 6] = [
        ("clock", "24h Clock"),
        ("date", "Date (MM-DD-YY)"),
        ("sys", "CPU & RAM %"),
        ("stocks", "Stock Ticker"),
        ("lyrics", "YouTube Music Lyrics"),
        ("off", "Display Off"),
    ];

    pub fn new(triggers_path: PathBuf) -> Self {
        let triggers = Self::load_triggers(&triggers_path);
        let mut trigger_state = ListState::default();
        if !triggers.is_empty() {
            trigger_state.select(Some(0));
        }
        Self {
            input_text: String::from("HELLO WORLD"),
            scroll_mode: ScrollMode::Once,
            triggers,
            trigger_state,
            focus: FocusPane::Input,
            daemon_mode_idx: 0,
            status_msg: String::from("Ready — Type text and press [Enter] to send to your 8BitDo Numpad!"),
            preview_offset: 0,
            last_tick: Instant::now(),
            triggers_path,
        }
    }

    fn load_triggers(path: &PathBuf) -> Vec<TextTrigger> {
        if let Ok(raw) = fs::read_to_string(path)
            && let Ok(list) = serde_json::from_str::<Vec<TextTrigger>>(&raw)
            && !list.is_empty()
        {
            return list;
        }
        vec![
            TextTrigger {
                name: "Greeting".into(),
                text: "HELLO WORLD".into(),
                mode: ScrollMode::Once,
            },
            TextTrigger {
                name: "Focus Mode".into(),
                text: "DEEP WORK DO NOT DISTURB".into(),
                mode: ScrollMode::Twice,
            },
            TextTrigger {
                name: "Market Open".into(),
                text: "MARKET OPEN - CHECK SPY NVDA DIS".into(),
                mode: ScrollMode::ThreeTimes,
            },
            TextTrigger {
                name: "Coffee Break".into(),
                text: "COFFEE".into(),
                mode: ScrollMode::Static,
            },
            TextTrigger {
                name: "Alert Loop".into(),
                text: "BUILD COMPLETE".into(),
                mode: ScrollMode::Continuous,
            },
        ]
    }

    fn save_triggers(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.triggers) {
            let _ = fs::write(&self.triggers_path, json);
        }
    }

    fn send_udp_json(&mut self, payload: &serde_json::Value) -> Result<()> {
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        let data = serde_json::to_vec(payload)?;
        sock.send_to(&data, DAEMON_UDP_ADDR)?;
        Ok(())
    }

    pub fn send_text(&mut self, text: &str, mode: ScrollMode) {
        let payload = match mode {
            ScrollMode::Static => serde_json::json!({
                "cmd": "static",
                "text": text,
                "align": "right"
            }),
            ScrollMode::Once => serde_json::json!({
                "cmd": "scroll",
                "text": text,
                "loops": 1
            }),
            ScrollMode::Twice => serde_json::json!({
                "cmd": "scroll",
                "text": text,
                "loops": 2
            }),
            ScrollMode::ThreeTimes => serde_json::json!({
                "cmd": "scroll",
                "text": text,
                "loops": 3
            }),
            ScrollMode::FiveTimes => serde_json::json!({
                "cmd": "scroll",
                "text": text,
                "loops": 5
            }),
            ScrollMode::Continuous => serde_json::json!({
                "cmd": "scroll",
                "text": text,
                "loops": 0
            }),
        };

        match self.send_udp_json(&payload) {
            Ok(()) => {
                self.status_msg = format!("Sent {:?} ({}) -> Numpad!", text, mode.label());
            }
            Err(e) => {
                self.status_msg = format!("UDP send error: {e}");
            }
        }
    }

    pub fn stop_active(&mut self) {
        let payload = serde_json::json!({ "cmd": "stop" });
        let _ = self.send_udp_json(&payload);
        self.status_msg = "Stopped active scroll / override — returned to normal display mode.".into();
    }

    pub fn set_daemon_mode(&mut self, idx: usize) {
        self.daemon_mode_idx = idx % Self::DAEMON_MODES.len();
        let (mode_id, mode_label) = Self::DAEMON_MODES[self.daemon_mode_idx];
        let payload = serde_json::json!({
            "cmd": "mode",
            "mode": mode_id
        });
        let _ = self.send_udp_json(&payload);
        self.status_msg = format!("Switched Numpad base mode to: {mode_label}");
    }

    pub fn add_current_as_trigger(&mut self) {
        let trimmed = self.input_text.trim().to_string();
        if trimmed.is_empty() {
            self.status_msg = "Cannot save an empty message as a trigger.".into();
            return;
        }
        let name = format!("Trigger #{}", self.triggers.len() + 1);
        self.triggers.push(TextTrigger {
            name,
            text: trimmed.clone(),
            mode: self.scroll_mode,
        });
        self.trigger_state.select(Some(self.triggers.len() - 1));
        self.save_triggers();
        self.status_msg = format!("Saved {:?} ({}) to Triggers!", trimmed, self.scroll_mode.label());
    }

    pub fn delete_selected_trigger(&mut self) {
        if let Some(i) = self.trigger_state.selected()
            && i < self.triggers.len()
        {
            let removed = self.triggers.remove(i);
            if self.triggers.is_empty() {
                self.trigger_state.select(None);
            } else {
                self.trigger_state.select(Some(i.min(self.triggers.len() - 1)));
            }
            self.save_triggers();
            self.status_msg = format!("Deleted trigger {:?}.", removed.text);
        }
    }

    pub fn current_preview_9(&self) -> [u8; 9] {
        let upper = self.input_text.to_uppercase();
        if self.scroll_mode == ScrollMode::Static {
            encode_7seg_fixed(&upper)
        } else {
            let mut padded = vec![0u8; 9];
            padded.extend(encode_7seg_sequence(&upper));
            padded.extend(vec![0u8; 4]);
            let total = padded.len().saturating_sub(8).max(1);
            let start = self.preview_offset % total;
            let mut out = [0u8; 9];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = *padded.get(start + i).unwrap_or(&0);
            }
            out
        }
    }

    pub fn on_tick(&mut self) {
        if self.last_tick.elapsed() >= Duration::from_millis(160) {
            self.preview_offset = self.preview_offset.wrapping_add(1);
            self.last_tick = Instant::now();
        }
    }
}

fn render(frame: &mut Frame, app: &mut App) {
    let [header_area, preview_area, input_area, body_area, mode_area, footer_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(5),
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(2),
    ])
    .areas(frame.area());

    // 1. Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" 8BitDo Retro 18 Mechanical Numpad ", Style::new().fg(Color::Black).bg(Color::Red).bold()),
        Span::raw("  "),
        Span::styled("Ratatui Custom Display & Trigger Studio", Style::new().fg(Color::Yellow).bold()),
    ]))
    .block(Block::bordered());
    frame.render_widget(header, header_area);

    // 2. Live 9-Digit 7-Segment LED Preview
    render_led_preview(frame, preview_area, app);

    // 3. Custom Text Input + Scroll Duration Selector
    let [text_box_area, duration_box_area] = Layout::horizontal([
        Constraint::Percentage(62),
        Constraint::Percentage(38),
    ])
    .areas(input_area);

    let input_border = if app.focus == FocusPane::Input {
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let input_widget = Paragraph::new(format!("{}_", app.input_text))
        .style(Style::new().fg(Color::White).bold())
        .block(
            Block::bordered()
                .title(" 1. Custom Text Input [Enter = Send | Ctrl+S = Save Trigger] ")
                .border_style(input_border),
        );
    frame.render_widget(input_widget, text_box_area);

    let scroll_border = if app.focus == FocusPane::ScrollSelector {
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let scroll_widget = Paragraph::new(format!("◄  {}  ►", app.scroll_mode.label()))
        .style(Style::new().fg(Color::LightGreen).bold())
        .block(
            Block::bordered()
                .title(" 2. Scroll Duration [Left/Right or Tab] ")
                .border_style(scroll_border),
        );
    frame.render_widget(scroll_widget, duration_box_area);

    // 4. Saved Text Triggers List (F1..F9 or Enter to fire)
    let trig_border = if app.focus == FocusPane::Triggers {
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let items: Vec<ListItem> = app
        .triggers
        .iter()
        .enumerate()
        .map(|(idx, t)| {
            let hotkey = if idx < 9 {
                format!("[F{}]", idx + 1)
            } else {
                "[--]".into()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{hotkey:<5} "), Style::new().fg(Color::Yellow).bold()),
                Span::styled(format!("{:<16} ", t.name), Style::new().fg(Color::Cyan)),
                Span::styled(format!("{:<34} ", format!("{:?}", t.text)), Style::new().fg(Color::White).bold()),
                Span::styled(format!("({})", t.mode.label()), Style::new().fg(Color::LightGreen)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::bordered()
                .title(" 3. Saved Text Triggers [F1-F9 = Instant Fire | Up/Down + Enter = Fire | Del = Remove] ")
                .border_style(trig_border),
        )
        .highlight_style(Style::new().bg(Color::DarkGray).fg(Color::White).bold())
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, body_area, &mut app.trigger_state);

    // 5. Base Numpad Mode Switcher
    let mode_border = if app.focus == FocusPane::Modes {
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let titles: Vec<Line> = App::DAEMON_MODES
        .iter()
        .map(|(_, label)| Line::from(*label))
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.daemon_mode_idx)
        .block(
            Block::bordered()
                .title(" 4. Base Numpad Display Mode [Left/Right + Enter] ")
                .border_style(mode_border),
        )
        .highlight_style(Style::new().fg(Color::Black).bg(Color::Yellow).bold());
    frame.render_widget(tabs, mode_area);

    // 6. Status & Help Footer
    let footer = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" Status: ", Style::new().fg(Color::Yellow).bold()),
            Span::raw(&app.status_msg),
        ]),
        Line::from(vec![
            Span::styled(" Keys: ", Style::new().fg(Color::Cyan).bold()),
            Span::raw("[Tab] Switch Pane  [Enter] Send/Fire  [Ctrl+S] Save Trigger  [F1-F9] Fire Trigger  [Esc] Stop Scroll  [Ctrl+Q] Quit"),
        ]),
    ]);
    frame.render_widget(footer, footer_area);
}

fn render_led_preview(frame: &mut Frame, area: Rect, app: &App) {
    let segs = app.current_preview_9();
    let mut row0 = String::from("   ");
    let mut row1 = String::from("   ");
    let mut row2 = String::from("   ");

    for &b in &segs {
        let [t, m, bo] = render_digit_lines(b);
        row0.push_str(&t);
        row0.push_str("  ");
        row1.push_str(&m);
        row1.push_str("  ");
        row2.push_str(&bo);
        row2.push_str("  ");
    }

    let led_style = Style::new().fg(Color::LightRed).bold();
    let preview = Paragraph::new(vec![
        Line::from(Span::styled(row0, led_style)),
        Line::from(Span::styled(row1, led_style)),
        Line::from(Span::styled(row2, led_style)),
    ])
    .block(
        Block::bordered()
            .title(format!(
                " Live 9-Digit 7-Segment LED Preview ({}) ",
                app.scroll_mode.label()
            ))
            .border_style(Style::new().fg(Color::Red)),
    );
    frame.render_widget(preview, area);
}

fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('q') {
        return true;
    }

    // Global function key triggers F1..F9
    if let KeyCode::F(n) = key.code {
        let idx = (n as usize).saturating_sub(1);
        if let Some(trig) = app.triggers.get(idx).cloned() {
            app.send_text(&trig.text, trig.mode);
        }
        return false;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
        app.add_current_as_trigger();
        return false;
    }

    match key.code {
        KeyCode::Esc => {
            app.stop_active();
            return false;
        }
        KeyCode::Tab => {
            app.focus = match app.focus {
                FocusPane::Input => FocusPane::ScrollSelector,
                FocusPane::ScrollSelector => FocusPane::Triggers,
                FocusPane::Triggers => FocusPane::Modes,
                FocusPane::Modes => FocusPane::Input,
            };
            return false;
        }
        KeyCode::BackTab => {
            app.focus = match app.focus {
                FocusPane::Input => FocusPane::Modes,
                FocusPane::ScrollSelector => FocusPane::Input,
                FocusPane::Triggers => FocusPane::ScrollSelector,
                FocusPane::Modes => FocusPane::Triggers,
            };
            return false;
        }
        _ => {}
    }

    match app.focus {
        FocusPane::Input => match key.code {
            KeyCode::Enter => {
                let text = app.input_text.clone();
                let mode = app.scroll_mode;
                app.send_text(&text, mode);
            }
            KeyCode::Backspace => {
                app.input_text.pop();
                app.preview_offset = 0;
            }
            KeyCode::Left if key.modifiers.contains(KeyModifiers::ALT) => {
                app.scroll_mode = app.scroll_mode.prev();
                app.preview_offset = 0;
            }
            KeyCode::Right if key.modifiers.contains(KeyModifiers::ALT) => {
                app.scroll_mode = app.scroll_mode.next();
                app.preview_offset = 0;
            }
            KeyCode::Char(c) => {
                app.input_text.push(c);
                app.preview_offset = 0;
            }
            _ => {}
        },
        FocusPane::ScrollSelector => match key.code {
            KeyCode::Left | KeyCode::Up => {
                app.scroll_mode = app.scroll_mode.prev();
                app.preview_offset = 0;
            }
            KeyCode::Right | KeyCode::Down => {
                app.scroll_mode = app.scroll_mode.next();
                app.preview_offset = 0;
            }
            KeyCode::Enter => {
                let text = app.input_text.clone();
                let mode = app.scroll_mode;
                app.send_text(&text, mode);
            }
            _ => {}
        },
        FocusPane::Triggers => match key.code {
            KeyCode::Up => {
                if let Some(sel) = app.trigger_state.selected() {
                    app.trigger_state.select(Some(sel.saturating_sub(1)));
                }
            }
            KeyCode::Down => {
                if let Some(sel) = app.trigger_state.selected()
                    && sel + 1 < app.triggers.len()
                {
                    app.trigger_state.select(Some(sel + 1));
                }
            }
            KeyCode::Enter => {
                if let Some(sel) = app.trigger_state.selected()
                    && let Some(trig) = app.triggers.get(sel).cloned()
                {
                    app.send_text(&trig.text, trig.mode);
                }
            }
            KeyCode::Delete | KeyCode::Backspace => {
                app.delete_selected_trigger();
            }
            _ => {}
        },
        FocusPane::Modes => match key.code {
            KeyCode::Left => {
                let n = App::DAEMON_MODES.len();
                app.daemon_mode_idx = (app.daemon_mode_idx + n - 1) % n;
            }
            KeyCode::Right => {
                let n = App::DAEMON_MODES.len();
                app.daemon_mode_idx = (app.daemon_mode_idx + 1) % n;
            }
            KeyCode::Enter => {
                app.set_daemon_mode(app.daemon_mode_idx);
            }
            _ => {}
        },
    }

    false
}

fn run_app(terminal: &mut DefaultTerminal, mut app: App) -> Result<()> {
    loop {
        app.on_tick();
        terminal.draw(|frame| render(frame, &mut app))?;

        if event::poll(Duration::from_millis(40))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && handle_key(&mut app, key)
        {
            break Ok(());
        }
    }
}

fn main() -> Result<()> {
    let triggers_path = PathBuf::from("triggers.json");
    let app = App::new(triggers_path);

    let mut terminal = ratatui::init();
    let res = run_app(&mut terminal, app);
    ratatui::restore();
    res
}
