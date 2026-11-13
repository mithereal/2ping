use crate::engine::State;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
    Terminal,
};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub async fn run_tui_loop(state: Arc<Mutex<State>>, active_key_id: String) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = tui_event_loop(&mut terminal, state, active_key_id).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

async fn tui_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: Arc<Mutex<State>>,
    active_key_id: String,
) -> io::Result<()> {
    loop {
        let (global, per_target) = {
            let st = state.lock().await;
            (st.global_stats.clone(), st.per_target_stats.clone())
        };

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(8),
                    Constraint::Min(8),
                    Constraint::Length(2),
                ])
                .split(f.area());

            // 1. Header Banner
            let header = Paragraph::new(Line::from(vec![
                Span::styled(
                    " 2PING ENTERPRISE TELEMETRY ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "  Active Key: [{}]  |  TX: {}  RX: {}  Invalid/Replay Drops: {}",
                    active_key_id,
                    global.pings_transmitted,
                    global.pings_received,
                    global.auth_or_decrypt_errors
                )),
            ]))
            .block(Block::default().borders(Borders::ALL).title("Status"));
            f.render_widget(header, chunks);

            // 2. RTT Sparkline (scaled to microseconds for crisp integer bars)
            let spark_data: Vec<u64> = global
                .rtts_ms
                .iter()
                .rev()
                .take(120)
                .rev()
                .map(|&ms| (ms * 100.0).round() as u64)
                .collect();

            let sparkline = Sparkline::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(
                            "Wire RTT Trend (Avg: {:.2} ms | Jitter: {:.2} ms)",
                            global.avg_rtt(),
                            global.jitter_ms
                        )),
                )
                .data(&spark_data)
                .style(Style::default().fg(Color::Green));
            f.render_widget(sparkline, chunks);

            // 3. Per-Target Table (Directional Loss + One-Way Delay)
            let header_cells = [
                "Target",
                "TX / RX",
                "Out Loss",
                "In Loss",
                "Avg RTT",
                "Out OWD",
                "In OWD",
                "Jitter",
            ]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)));

            let header_row = Row::new(header_cells).height(1);

            let mut target_names: Vec<&String> = per_target.keys().collect();
            target_names.sort();

            let rows = target_names.iter().map(|&name| {
                let s = &per_target[name];
                let out_pct = if s.pings_transmitted > 0 {
                    (s.outbound_loss as f64 / s.pings_transmitted as f64) * 100.0
                } else {
                    0.0
                };
                let in_pct = if s.pings_transmitted > 0 {
                    (s.inbound_loss as f64 / s.pings_transmitted as f64) * 100.0
                } else {
                    0.0
                };

                let out_owd = s
                    .avg_outbound_owd()
                    .map(|v| format!("{:.2} ms", v))
                    .unwrap_or_else(|| "n/a".into());
                let in_owd = s
                    .avg_inbound_owd()
                    .map(|v| format!("{:.2} ms", v))
                    .unwrap_or_else(|| "n/a".into());

                Row::new(vec![
                    Cell::from(name.clone()),
                    Cell::from(format!("{}/{}", s.pings_transmitted, s.pings_received)),
                    Cell::from(format!("{} ({:.1}%)", s.outbound_loss, out_pct))
                        .style(Style::default().fg(if out_pct > 1.0 { Color::Red } else { Color::Green })),
                    Cell::from(format!("{} ({:.1}%)", s.inbound_loss, in_pct))
                        .style(Style::default().fg(if in_pct > 1.0 { Color::Red } else { Color::Green })),
                    Cell::from(format!("{:.2} ms", s.avg_rtt())),
                    Cell::from(out_owd),
                    Cell::from(in_owd),
                    Cell::from(format!("{:.2} ms", s.jitter_ms)),
                ])
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(22),
                    Constraint::Percentage(11),
                    Constraint::Percentage(13),
                    Constraint::Percentage(13),
                    Constraint::Percentage(11),
                    Constraint::Percentage(10),
                    Constraint::Percentage(10),
                    Constraint::Percentage(10),
                ],
            )
            .header(header_row)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Per-Target Directional Loss & One-Way Delay (OWD)"),
            );
            f.render_widget(table, chunks);

            // 4. Footer Help
            let footer = Paragraph::new("Press 'q' or Ctrl+C to exit TUI and print final summary.")
                .style(Style::default().fg(Color::DarkGray));
            f.render_widget(footer, chunks);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press
                    && (key.code == KeyCode::Char('q') || key.code == KeyCode::Esc)
                {
                    break;
                }
            }
        }
    }
    Ok(())
}
