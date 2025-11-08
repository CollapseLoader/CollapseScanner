use iced::widget::{button, container};
use iced::{Background, Border, Color, Theme};

pub const BG_COLOR: Color = Color::from_rgb(0.08, 0.08, 0.10);
pub const SURFACE_COLOR: Color = Color::from_rgb(0.10, 0.10, 0.16);
pub const CARD_COLOR: Color = Color::from_rgb(0.15, 0.15, 0.22);
pub const BORDER_COLOR: Color = Color::from_rgb(0.25, 0.25, 0.30);
pub const ACCENT_COLOR: Color = Color::from_rgb(0.3, 0.7, 1.0);
pub const ACCENT_COLOR_MUTED: Color = Color::from_rgb(0.15, 0.35, 0.5);
pub const ACCENT_MUTED: Color = Color::from_rgb(0.2, 0.5, 0.8);
pub const SUCCESS_COLOR: Color = Color::from_rgb(0.2, 0.8, 0.4);
pub const WARNING_COLOR: Color = Color::from_rgb(1.0, 0.8, 0.2);
pub const ERROR_COLOR: Color = Color::from_rgb(1.0, 0.3, 0.3);
pub const ERROR_COLOR_MUTED: Color = Color::from_rgb(0.8, 0.4, 0.4);
pub const TEXT_PRIMARY: Color = Color::from_rgb(0.95, 0.95, 0.95);
pub const TEXT_SECONDARY: Color = Color::from_rgb(0.7, 0.7, 0.7);

pub const DANGER_CRITICAL: Color = ERROR_COLOR;
pub const DANGER_CRITICAL_MUTED: Color = ERROR_COLOR_MUTED;
pub const DANGER_HIGH: Color = WARNING_COLOR;
pub const DANGER_MEDIUM: Color = Color::from_rgb(1.0, 1.0, 0.3);
pub const DANGER_LOW: Color = SUCCESS_COLOR;

pub fn container_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(BG_COLOR.into()),
        text_color: Some(TEXT_PRIMARY),
        ..Default::default()
    }
}

pub fn card_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(CARD_COLOR.into()),
        border: iced::Border {
            color: BORDER_COLOR,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    }
}

pub fn button_style(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(SURFACE_COLOR.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: BORDER_COLOR,
            width: 1.0,
            radius: 5.0.into(),
        },
        ..button::secondary(_theme, _status)
    }
}

pub fn primary_button_style(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(ACCENT_COLOR_MUTED.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: ACCENT_MUTED,
            width: 2.0,
            radius: 6.0.into(),
        },
        ..button::primary(_theme, _status)
    }
}

pub fn cancel_button_style(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(DANGER_CRITICAL_MUTED.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: Color::from_rgb(1.0, 0.3, 0.3),
            width: 2.0,
            radius: 6.0.into(),
        },
        ..button::primary(_theme, _status)
    }
}

pub fn result_button_style(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(SURFACE_COLOR.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: Color::from_rgb(0.3, 0.3, 0.4),
            width: 1.0,
            radius: 5.0.into(),
        },
        ..button::secondary(_theme, _status)
    }
}

pub fn pick_list_style(
    _theme: &Theme,
    _status: iced::widget::pick_list::Status,
) -> iced::widget::pick_list::Style {
    iced::widget::pick_list::Style {
        text_color: TEXT_SECONDARY,
        placeholder_color: TEXT_SECONDARY,
        handle_color: ACCENT_COLOR,
        background: Background::Color(SURFACE_COLOR),
        border: Border {
            radius: 6.0.into(),
            width: 1.0,
            color: BORDER_COLOR,
        },
    }
}

pub fn pick_list_menu_style(_theme: &Theme) -> iced::overlay::menu::Style {
    iced::overlay::menu::Style {
        text_color: TEXT_PRIMARY,
        background: Background::Color(CARD_COLOR),
        border: Border {
            radius: 6.0.into(),
            width: 1.0,
            color: BORDER_COLOR,
        },
        selected_text_color: Color::WHITE,
        selected_background: Background::Color(Color {
            r: ACCENT_COLOR.r * 0.6,
            g: ACCENT_COLOR.g * 0.6,
            b: ACCENT_COLOR.b * 0.6,
            a: ACCENT_COLOR.a,
        }),
    }
}

pub fn danger_color(score: u8) -> Color {
    match score {
        8..=10 => DANGER_CRITICAL,
        5..=7 => DANGER_HIGH,
        3..=4 => DANGER_MEDIUM,
        _ => DANGER_LOW,
    }
}
