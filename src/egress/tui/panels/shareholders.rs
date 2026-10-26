//! Shareholder Panel
//!
//! Displays the status of DKG parties/shareholders.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table, Cell},
};
use std::sync::Arc;
use crate::crypto::dkg::DKG;

/// Shareholder panel state
pub struct ShareholderPanel {
    dkg: Arc<DKG>,
}

impl ShareholderPanel {
    pub fn new(dkg: Arc<DKG>) -> Self {
        Self { dkg }
    }

    /// Render the shareholder panel
    pub fn render(&self, f: &mut Frame, area: Rect) {
        // Create a simple status display
        // In a real implementation, this would show actual party status

        let info = vec![
            format!("Total Parties: {}", self.dkg.parties),
            format!("Threshold: {}", self.dkg.threshold),
            "Online: TODO".to_string(),
            "Valid Shares: TODO".to_string(),
        ];

        let text: Vec<Line> = info.iter()
            .map(|line| Line::from(line.as_str()))
            .collect();

        let paragraph = Paragraph::new(text)
            .block(Block::default().title("Shareholders").borders(Borders::ALL));

        f.render_widget(paragraph, area);
    }
}
