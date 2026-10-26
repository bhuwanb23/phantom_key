//! TUI Application
//!
//! Main application state and rendering logic for the Egress Court TUI.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::egress::{
    ledger::{Ledger, ChainStatus},
    canary::CanaryRegistry,
};
use crate::vault::storage::VaultStorage;
use crate::crypto::dkg::DKG;

/// Main application state for TUI
pub struct App {
    ledger: Arc<Ledger>,
    vault_storage: Arc<dyn VaultStorage>,
    dkg: Arc<DKG>,
    canary_registry: Arc<Mutex<CanaryRegistry>>,
}

impl App {
    pub fn new(
        ledger: Arc<Ledger>,
        vault_storage: Arc<dyn VaultStorage>,
        dkg: Arc<DKG>,
        canary_registry: Arc<Mutex<CanaryRegistry>>,
    ) -> Self {
        Self {
            ledger,
            vault_storage,
            dkg,
            canary_registry,
        }
    }

    /// Run the TUI
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut terminal = setup_terminal()?;

        loop {
            terminal.draw(|f| self.ui(f))?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Draw the UI
    fn ui(&self, f: &mut Frame) {
        let size = f.size();

        // Split into left and right panels
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(size);

        // Left side: Chat and Vault
        let left_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(60),
                Constraint::Percentage(40),
            ])
            .split(layout[0]);

        self.render_chat_panel(f, left_layout[0]);
        self.render_vault_panel(f, left_layout[1]);

        // Right side: Ledger and Shareholders
        let right_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(60),
                Constraint::Percentage(40),
            ])
            .split(layout[1]);

        self.render_ledger_panel(f, right_layout[0]);
        self.render_shareholder_panel(f, right_layout[1]);
    }

    fn render_chat_panel(&self, f: &mut Frame, area: Rect) {
        let chat = Paragraph::new("Chat Panel\n\n(LLM conversation will appear here)")
            .block(Block::default().title("Chat").borders(Borders::ALL));
        f.render_widget(chat, area);
    }

    fn render_vault_panel(&self, f: &mut Frame, area: Rect) {
        use ratatui::widgets::{Row, Table, Cell};

        let entries = self.vault_storage.list();
        let rows: Vec<Row> = entries.iter()
            .map(|entry| {
                Row::new([
                    Cell::new(&entry.handle),
                    Cell::new(&format!("{:?}", entry.metadata.secret_type)),
                    Cell::new(&entry.metadata.created_at.format("%H:%M:%S").to_string()),
                ])
            })
            .collect();

        let table = Table::new(rows)
            .header(Row::new(["Handle", "Type", "Created"]))
            .block(Block::default().title("Vault").borders(Borders::ALL))
            .widths(&[20, 20, 10]);

        f.render_widget(table, area);
    }

    fn render_ledger_panel(&self, f: &mut Frame, area: Rect) {
        use ratatui::widgets::{Row, Table, Cell};

        let entries = self.ledger.entries();
        let latest = &entries[entries.len().saturating_sub(10)..];

        let rows: Vec<Row> = latest.iter()
            .map(|entry| {
                Row::new([
                    Cell::new(entry.entry.timestamp.format("%H:%M:%S").to_string()),
                    Cell::new(&entry.entry.provider),
                    Cell::new(&entry.entry.method),
                    Cell::new(&entry.entry.url),
                    Cell::new(if entry.entry.hash == self.ledger.head_hash().unwrap_or([0; 32]) {
                        "✓"
                    } else {
                        "✗"
                    }),
                ])
            })
            .collect();

        let table = Table::new(rows)
            .header(Row::new(["Time", "Provider", "Method", "URL", "Status"]))
            .block(Block::default().title("Egress Ledger").borders(Borders::ALL))
            .widths(&[10, 15, 10, 30, 5]);

        f.render_widget(table, area);

        // Show chain status below the table
        let chain_status = self.ledger.chain_status();
        let status_text = match chain_status {
            ChainStatus::Valid { head_hash, entry_count } => {
                format!("✓ Chain Valid | Entries: {}", entry_count)
            }
            ChainStatus::Invalid { entry_count } => {
                format!("✗ Chain Invalid | Entries: {}", entry_count)
            }
        };

        let status = Paragraph::new(status_text)
            .block(Block::default().title("Chain Status").borders(Borders::ALL));

        // This would be rendered below the table
        // For now, we'll just render it in the same area
    }

    fn render_shareholder_panel(&self, f: &mut Frame, area: Rect) {
        let status = Paragraph::new(
            "Shareholder Status Panel\n\n(
            Party status will appear here\n\n
            Total Parties: TODO\n
            Online: TODO\n
            Valid Shares: TODO
            )"
        )
        .block(Block::default().title("Shareholders").borders(Borders::ALL));
        f.render_widget(status, area);
    }
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>, Box<dyn std::error::Error>> {
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    crossterm::terminal::enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;

    Ok(terminal)
}

/// Cleanup terminal on drop
impl Drop for App {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen
        );
    }
}
