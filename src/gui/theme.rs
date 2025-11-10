use iced::widget::{button, container};
use iced::{Background, Border, Color, Theme};

pub const BG_COLOR: Color = Color::from_rgb(0.06, 0.06, 0.08);
pub const SURFACE_COLOR: Color = Color::from_rgb(0.09, 0.10, 0.14);
pub const CARD_COLOR: Color = Color::from_rgb(0.12, 0.13, 0.18);
pub const BORDER_COLOR: Color = Color::from_rgb(0.20, 0.22, 0.28);
pub const BORDER_HIGHLIGHT: Color = Color::from_rgb(0.30, 0.35, 0.45);

pub const ACCENT_COLOR: Color = Color::from_rgb(0.25, 0.75, 1.0);
pub const ACCENT_COLOR_MUTED: Color = Color::from_rgb(0.18, 0.40, 0.58);
pub const ACCENT_HOVER: Color = Color::from_rgb(0.30, 0.82, 1.0);

pub const WARNING_COLOR: Color = Color::from_rgb(1.0, 0.75, 0.15);
pub const ERROR_COLOR: Color = Color::from_rgb(1.0, 0.35, 0.40);
pub const ERROR_COLOR_MUTED: Color = Color::from_rgb(0.65, 0.25, 0.30);

pub const TEXT_PRIMARY: Color = Color::from_rgb(0.96, 0.97, 0.98);
pub const TEXT_SECONDARY: Color = Color::from_rgb(0.65, 0.68, 0.72);

pub const DANGER_CRITICAL: Color = ERROR_COLOR;
pub const DANGER_CRITICAL_MUTED: Color = ERROR_COLOR_MUTED;
pub const DANGER_HIGH: Color = Color::from_rgb(1.0, 0.60, 0.20);
pub const DANGER_MEDIUM: Color = WARNING_COLOR;
pub const DANGER_LOW: Color = Color::from_rgb(0.40, 0.90, 0.60);

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
            width: 1.5,
            radius: 12.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.3),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 12.0,
        },
        ..Default::default()
    }
}

pub fn button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg_color, border_color) = match status {
        button::Status::Hovered => (Color::from_rgb(0.12, 0.14, 0.20), BORDER_HIGHLIGHT),
        button::Status::Pressed => (Color::from_rgb(0.08, 0.09, 0.13), ACCENT_COLOR),
        _ => (SURFACE_COLOR, BORDER_COLOR),
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: border_color,
            width: 1.5,
            radius: 8.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.2),
            offset: iced::Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
    }
}

pub fn primary_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg_color, shadow_offset) = match status {
        button::Status::Hovered => (ACCENT_HOVER, 3.0),
        button::Status::Pressed => (ACCENT_COLOR_MUTED, 1.0),
        _ => (ACCENT_COLOR, 2.0),
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color: Color::WHITE,
        border: iced::Border {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.0),
            width: 0.0,
            radius: 10.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.1, 0.4, 0.7, 0.4),
            offset: iced::Vector::new(0.0, shadow_offset),
            blur_radius: 8.0,
        },
    }
}

pub fn cancel_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg_color, shadow_offset) = match status {
        button::Status::Hovered => (Color::from_rgb(1.0, 0.40, 0.45), 3.0),
        button::Status::Pressed => (DANGER_CRITICAL_MUTED, 1.0),
        _ => (ERROR_COLOR, 2.0),
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color: Color::WHITE,
        border: iced::Border {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.0),
            width: 0.0,
            radius: 10.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.8, 0.2, 0.2, 0.4),
            offset: iced::Vector::new(0.0, shadow_offset),
            blur_radius: 8.0,
        },
    }
}

pub fn result_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg_color, border_width) = match status {
        button::Status::Hovered => (Color::from_rgb(0.14, 0.15, 0.21), 1.5),
        button::Status::Pressed => (Color::from_rgb(0.10, 0.11, 0.16), 1.5),
        _ => (SURFACE_COLOR, 1.0),
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color: TEXT_PRIMARY,
        border: iced::Border {
            color: BORDER_COLOR,
            width: border_width,
            radius: 8.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.15),
            offset: iced::Vector::new(0.0, 2.0),
            blur_radius: 6.0,
        },
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

pub fn progress_bar_style(_theme: &Theme) -> iced::widget::progress_bar::Style {
    iced::widget::progress_bar::Style {
        background: Background::Color(SURFACE_COLOR),
        bar: Background::Color(ACCENT_COLOR),
        border: Border {
            radius: 8.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
    }
}
