//! Mission Control Color Palettes (Arasaka Cyber-Red and Cyber Circuit).

use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeMode {
    Arasaka,
    Circuit,
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub mode: ThemeMode,
    pub bg: Color,
    pub border: Color,
    pub logo: Color,
    pub text: Color,
    pub muted: Color,
    pub accent: Color,
    pub tab_active_bg: Color,
    pub tab_active_fg: Color,
    pub success: Color,
    pub danger: Color,
    pub info: Color,
    pub warning: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,
}

impl Theme {
    pub fn arasaka() -> Self {
        Self {
            mode: ThemeMode::Arasaka,
            bg: Color::Rgb(10, 5, 6),
            border: Color::Rgb(61, 18, 23),
            logo: Color::Rgb(255, 23, 68),
            text: Color::Rgb(244, 232, 234),
            muted: Color::Rgb(138, 100, 105),
            accent: Color::Rgb(255, 82, 82),
            tab_active_bg: Color::Rgb(255, 23, 68),
            tab_active_fg: Color::White,
            success: Color::Rgb(0, 230, 118),
            danger: Color::Rgb(255, 23, 68),
            info: Color::Rgb(255, 138, 128),
            warning: Color::Rgb(255, 214, 0),
            selection_bg: Color::Rgb(51, 15, 20),
            selection_fg: Color::Rgb(255, 255, 255),
        }
    }

    pub fn circuit() -> Self {
        Self {
            mode: ThemeMode::Circuit,
            bg: Color::Rgb(12, 13, 14),
            border: Color::Rgb(38, 41, 45),
            logo: Color::Rgb(212, 207, 150),
            text: Color::Rgb(225, 227, 230),
            muted: Color::Rgb(114, 121, 130),
            accent: Color::Rgb(229, 224, 163),
            tab_active_bg: Color::Rgb(212, 207, 150),
            tab_active_fg: Color::Rgb(12, 13, 14),
            success: Color::Rgb(0, 230, 118),
            danger: Color::Rgb(255, 82, 82),
            info: Color::Rgb(56, 189, 248),
            warning: Color::Rgb(250, 204, 21),
            selection_bg: Color::Rgb(30, 33, 38),
            selection_fg: Color::Rgb(255, 255, 255),
        }
    }

    pub fn name(&self) -> &'static str {
        match self.mode {
            ThemeMode::Arasaka => "Arasaka Cyber-Red",
            ThemeMode::Circuit => "Cyber Circuit",
        }
    }

    pub fn toggle(&mut self) {
        *self = match self.mode {
            ThemeMode::Arasaka => Self::circuit(),
            ThemeMode::Circuit => Self::arasaka(),
        };
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::arasaka()
    }
}
