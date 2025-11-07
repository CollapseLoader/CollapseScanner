use iced::{Color, Theme};
use iced::widget::{button, container};

pub const BG_COLOR: Color = Color::from_rgb(0.10, 0.10, 0.12);
pub const SURFACE_COLOR: Color = Color::from_rgb(0.15, 0.15, 0.2);
pub const BORDER_COLOR: Color = Color::from_rgb(0.3, 0.3, 0.35);
pub const ACCENT_COLOR: Color = Color::from_rgb(0.2, 0.6, 1.0);
pub const ACCENT_MUTED: Color = Color::from_rgb(0.2, 0.4, 0.7);
pub const TEXT_PRIMARY: Color = Color::WHITE;

pub const DANGER_CRITICAL: Color = Color::from_rgb(1.0, 0.2, 0.2);
pub const DANGER_HIGH: Color = Color::from_rgb(1.0, 0.7, 0.0);
pub const DANGER_MEDIUM: Color = Color::from_rgb(1.0, 1.0, 0.3);
pub const DANGER_LOW: Color = Color::from_rgb(0.3, 1.0, 0.3);

pub fn container_style() -> container::Style {
    container::Style {
        background: Some(BG_COLOR.into()),
        text_color: Some(TEXT_PRIMARY),
        ..container::Style::default()
    }
}

pub fn button_style(theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(SURFACE_COLOR.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: BORDER_COLOR,
            width: 1.0,
            radius: 5.0.into(),
        },
        ..button::secondary(theme, _status)
    }
}

pub fn primary_button_style(theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(ACCENT_COLOR.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: ACCENT_MUTED,
            width: 2.0,
            radius: 6.0.into(),
        },
        ..button::primary(theme, _status)
    }
}

pub fn cancel_button_style(theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(DANGER_CRITICAL.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: Color::from_rgb(1.0, 0.3, 0.3),
            width: 2.0,
            radius: 6.0.into(),
        },
        ..button::primary(theme, _status)
    }
}

pub fn result_button_style(theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(SURFACE_COLOR.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: Color::from_rgb(0.3, 0.3, 0.4),
            width: 1.0,
            radius: 5.0.into(),
        },
        ..button::secondary(theme, _status)
    }
}

/// map danger score (0..=10) to a color for badges/labels
pub fn danger_color(score: u8) -> Color {
    match score {
        8..=10 => DANGER_CRITICAL,
        5..=7 => DANGER_HIGH,
        3..=4 => DANGER_MEDIUM,
        _ => DANGER_LOW,
    }
}