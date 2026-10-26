//! Chat Panel
//!
//! Displays the LLM conversation in real-time.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation},
};

/// Chat panel state
pub struct ChatPanel {
    messages: Vec<String>,
    scroll: usize,
}

impl ChatPanel {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            scroll: 0,
        }
    }

    /// Add a message to the chat
    pub fn add_message(&mut self, message: String) {
        self.messages.push(message);
    }

    /// Scroll up
    pub fn scroll_up(&mut self) {
        if self.scroll > 0 {
            self.scroll -= 1;
        }
    }

    /// Scroll down
    pub fn scroll_down(&mut self) {
        if self.scroll < self.messages.len().saturating_sub(1) {
            self.scroll += 1;
        }
    }

    /// Render the chat panel
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let text: Vec<Line> = self.messages
            .iter()
            .skip(self.scroll)
            .map(|msg| Line::from(msg.as_str()))
            .collect();

        let paragraph = Paragraph::new(text)
            .block(Block::default().title("Chat").borders(Borders::ALL))
            .scroll((self.scroll as u16, 0));

        f.render_widget(paragraph, area);
        f.render_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            area,
        );
    }
}

impl Default for ChatPanel {
    fn default() -> Self {
        Self::new()
    }
}
