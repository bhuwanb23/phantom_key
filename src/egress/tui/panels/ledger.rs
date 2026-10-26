//! Ledger Panel
//!
//! Displays the egress ledger entries and chain status.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table, Cell},
};
use std::sync::Arc;
use crate::egress::ledger::{Ledger, ChainStatus};

/// Ledger panel state
pub struct LedgerPanel {
    ledger: Arc<Ledger>,
    scroll: usize,
}

impl LedgerPanel {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self {
            ledger,
            scroll: 0,
        }
    }

    /// Scroll up
    pub fn scroll_up(&mut self) {
        if self.scroll > 0 {
            self.scroll -= 1;
        }
    }

    /// Scroll down
    pub fn scroll_down(&mut self) {
        let entries = self.ledger.entries();
        if self.scroll < entries.len().saturating_sub(1) {
            self.scroll += 1;
        }
    }

    /// Render the ledger panel
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let entries = self.ledger.entries();
        let display_entries = &entries[entries.len().saturating_sub(10 + self.scroll)..];

        let rows: Vec<Row> = display_entries.iter()
            .map(|entry| {
                Row::new([
                    Cell::new(entry.entry.timestamp.format("%H:%M:%S").to_string()),
                    Cell::new(&entry.entry.provider),
                    Cell::new(&entry.entry.method),
                    Cell::new(&truncate_url(&entry.entry.url, 30)),
                    Cell::new(if entry.entry.hash == self.ledger.head_hash().unwrap_or([0; 32]) {
                        "✓"
                    } else {
                        "✗"
                    }),
                ])
            })
            .collect();

        let table = Table::new(rows)
            .header(Row::new(["Time", "Provider", "Method", "URL", "S"]))
            .block(Block::default().title("Egress Ledger").borders(Borders::ALL))
            .widths(&[10, 15, 10, 30, 5]);

        f.render_widget(table, area);

        // Show chain status
        let chain_status = self.ledger.chain_status();
        let status_text = match chain_status {
            ChainStatus::Valid { entry_count, .. } => {
                format!("✓ Chain Valid | {} entries", entry_count)
            }
            ChainStatus::Invalid { entry_count } => {
                format!("✗ Chain Invalid | {} entries", entry_count)
            }
        };

        let status = Paragraph::new(status_text)
            .block(Block::default().title("Chain Status").borders(Borders::ALL));

        // For now, render status in the same area
        // In a real implementation, this would be separate
    }
}

/// Truncate URL to fit in display
fn truncate_url(url: &str, max_len: usize) -> String {
    if url.len() <= max_len {
        url.to_string()
    } else {
        format!("...{}", &url[url.len() - max_len + 3..])
    }
}
