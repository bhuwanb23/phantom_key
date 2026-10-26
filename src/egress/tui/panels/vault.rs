//! Vault Panel
//!
//! Displays vault entries and their status.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Row, Table, Cell},
};
use std::sync::Arc;
use crate::vault::storage::VaultStorage;

/// Vault panel state
pub struct VaultPanel {
    vault_storage: Arc<dyn VaultStorage>,
    scroll: usize,
}

impl VaultPanel {
    pub fn new(vault_storage: Arc<dyn VaultStorage>) -> Self {
        Self {
            vault_storage,
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
        let entries = self.vault_storage.list();
        if self.scroll < entries.len().saturating_sub(1) {
            self.scroll += 1;
        }
    }

    /// Render the vault panel
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let entries = self.vault_storage.list();
        let display_entries = &entries[entries.len().saturating_sub(10 + self.scroll)..];

        let rows: Vec<Row> = display_entries.iter()
            .map(|entry| {
                Row::new([
                    Cell::new(&truncate_handle(&entry.handle, 15)),
                    Cell::new(&format!("{:?}", entry.metadata.secret_type)),
                    Cell::new(&entry.metadata.created_at.format("%H:%M:%S").to_string()),
                    Cell::new(&entry.metadata.access_count.to_string()),
                ])
            })
            .collect();

        let table = Table::new(rows)
            .header(Row::new(["Handle", "Type", "Created", "Access"]))
            .block(Block::default().title("Vault").borders(Borders::ALL))
            .widths(&[15, 20, 15, 10]);

        f.render_widget(table, area);
    }
}

/// Truncate handle to fit in display
fn truncate_handle(handle: &str, max_len: usize) -> String {
    if handle.len() <= max_len {
        handle.to_string()
    } else {
        format!("...{}", &handle[handle.len() - max_len + 3..])
    }
}
