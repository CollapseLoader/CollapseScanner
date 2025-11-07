use std::collections::HashMap;
use std::path::PathBuf;

use iced::time;
use iced::widget::{
    button, checkbox, column, container, horizontal_space, pick_list, progress_bar, row,
    scrollable, text, text_input, vertical_space, Column,
};
use iced::{Alignment, Color, Element, Length, Subscription, Task, Theme};
use std::time::Duration;

use crate::scanner::CollapseScanner;
use crate::types::{
    DetectionMode, FindingType, Progress as TypesProgress, ScanResult, ScannerOptions,
};
use std::sync::{Arc, Mutex};

use super::message::Message;
use super::state::{AppState, ResultsUi, ScanProgress, ScanSettings};
use super::theme;

const SEVERITY_OPTIONS: [&str; 5] = ["All", "Low", "Medium", "High", "Critical"];

pub struct CollapseApp {
    state: AppState,
    settings: ScanSettings,
    progress: ScanProgress,
    results: Vec<ScanResult>,
    active_tab: usize,
    expanded_findings: Vec<usize>,
    results_ui: ResultsUi,
}

impl CollapseApp {
    pub fn new() -> (Self, Task<Message>) {
        (
            Self {
                state: AppState::Idle,
                settings: ScanSettings::default(),
                progress: Arc::new(Mutex::new(TypesProgress::new())),
                results: Vec::new(),
                active_tab: 0,
                expanded_findings: Vec::new(),
                results_ui: ResultsUi::default(),
            },
            Task::none(),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PathInputChanged(path) => {
                self.settings.path = path;
                Task::none()
            }
            Message::SelectPath => Task::future(async {
                let result = rfd::AsyncFileDialog::new()
                    .set_title("Select JAR or class file")
                    .add_filter("JAR", &["jar"])
                    .add_filter("Class", &["class"])
                    .pick_file()
                    .await
                    .map(|handle| handle.path().to_path_buf());
                Message::PathSelected(result)
            }),
            Message::PathSelected(path) => {
                if let Some(p) = path {
                    self.settings.path = p.to_string_lossy().to_string();
                }
                Task::none()
            }
            Message::ModeChanged(mode) => {
                self.settings.mode = mode;
                Task::none()
            }
            Message::VerboseToggled(value) => {
                self.settings.verbose = value;
                Task::none()
            }
            Message::ExtractStringsToggled(value) => {
                self.settings.extract_strings = value;
                Task::none()
            }
            Message::ExtractResourcesToggled(value) => {
                self.settings.extract_resources = value;
                Task::none()
            }
            Message::ExportJsonToggled(value) => {
                self.settings.export_json = value;
                Task::none()
            }
            Message::ThreadsChanged(value) => {
                self.settings.threads = value;
                Task::none()
            }
            Message::ExcludePatternChanged(value) => {
                self.settings.exclude_pattern_input = value;
                Task::none()
            }
            Message::AddExcludePattern => {
                if !self.settings.exclude_pattern_input.trim().is_empty() {
                    self.settings
                        .exclude_patterns
                        .push(self.settings.exclude_pattern_input.trim().to_string());
                    self.settings.exclude_pattern_input.clear();
                }
                Task::none()
            }
            Message::RemoveExcludePattern(index) => {
                if index < self.settings.exclude_patterns.len() {
                    self.settings.exclude_patterns.remove(index);
                }
                Task::none()
            }
            Message::FindPatternChanged(value) => {
                self.settings.find_pattern_input = value;
                Task::none()
            }
            Message::AddFindPattern => {
                if !self.settings.find_pattern_input.trim().is_empty() {
                    self.settings
                        .find_patterns
                        .push(self.settings.find_pattern_input.trim().to_string());
                    self.settings.find_pattern_input.clear();
                }
                Task::none()
            }
            Message::RemoveFindPattern(index) => {
                if index < self.settings.find_patterns.len() {
                    self.settings.find_patterns.remove(index);
                }
                Task::none()
            }
            Message::StartScan => {
                if self.settings.path.is_empty() {
                    self.state = AppState::Error("Please select a path to scan".to_string());
                    return Task::none();
                }

                self.state = AppState::Scanning;
                self.progress = Arc::new(Mutex::new(TypesProgress::new()));
                self.results.clear();
                self.expanded_findings.clear();

                let settings = self.settings.clone();
                let progress_clone = self.progress.clone();
                Task::future(async move {
                    Message::ScanCompleted(Self::perform_scan(settings, progress_clone).await)
                })
            }
            Message::ResultsSearchChanged(query) => {
                self.results_ui.search = query;
                Task::none()
            }
            Message::ResultsSeverityChanged(label) => {
                self.results_ui.severity = label;
                Task::none()
            }

            Message::CancelScan => {
                self.state = AppState::Idle;
                Task::none()
            }
            Message::ScanCompleted(result) => {
                match result {
                    Ok(results) => {
                        self.results = results;
                        self.state = AppState::Completed;
                        if let Ok(mut pg) = self.progress.lock() {
                            pg.message = format!("Scan completed: {} results", self.results.len());
                            pg.current = pg.total;
                        }
                    }
                    Err(e) => {
                        self.state = AppState::Error(e);
                    }
                }
                Task::none()
            }
            Message::Tick => {
                if matches!(self.state, AppState::Scanning) {}
                Task::none()
            }
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                Task::none()
            }
            Message::ClearResults => {
                self.results.clear();
                self.expanded_findings.clear();
                self.state = AppState::Idle;
                Task::none()
            }
            Message::ExpandFinding(index) => {
                if let Some(pos) = self.expanded_findings.iter().position(|&i| i == index) {
                    self.expanded_findings.remove(pos);
                } else {
                    self.expanded_findings.push(index);
                }
                Task::none()
            }
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        if matches!(self.state, AppState::Scanning) {
            time::every(Duration::from_millis(200)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let content = match self.active_tab {
            0 => self.view_scan_tab(),
            1 => self.view_results_tab(),
            2 => self.view_settings_tab(),
            _ => self.view_scan_tab(),
        };

        let tabs = row![
            tab_button("Scan", 0, self.active_tab),
            tab_button("Results", 1, self.active_tab),
            tab_button("Settings", 2, self.active_tab),
        ]
        .spacing(5);

        let main_content = column![tabs, content]
            .spacing(10)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill);

        container(main_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_theme: &Theme| theme::container_style())
            .into()
    }

    pub fn theme(&self) -> Theme {
        Theme::Dark
    }

    fn view_scan_tab(&self) -> Element<'_, Message> {
        let title = text("CollapseScanner")
            .size(32)
            .style(|_theme: &Theme| text::Style {
                color: Some(Color::from_rgb(0.3, 0.7, 1.0)),
            });

        let subtitle = text("Advanced JAR/Class File Analysis Tool")
            .size(14)
            .style(|_theme: &Theme| text::Style {
                color: Some(Color::from_rgb(0.6, 0.6, 0.6)),
            });

        let path_row = row![
            text_input("Select path to scan...", &self.settings.path)
                .on_input(Message::PathInputChanged)
                .padding(10)
                .width(Length::FillPortion(4)),
            button("Browse...")
                .on_press(Message::SelectPath)
                .padding(10)
                .style(theme::button_style),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let mode_picker = row![
            text("Detection Mode:").width(Length::Fixed(120.0)),
            pick_list(
                &[
                    DetectionMode::All,
                    DetectionMode::Network,
                    DetectionMode::Malicious,
                    DetectionMode::Obfuscation,
                ][..],
                Some(self.settings.mode),
                Message::ModeChanged,
            )
            .padding(10)
            .width(Length::Fill),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let quick_options = column![
            checkbox("Verbose output", self.settings.verbose).on_toggle(Message::VerboseToggled),
            checkbox("Extract strings", self.settings.extract_strings)
                .on_toggle(Message::ExtractStringsToggled),
            checkbox("Extract resources", self.settings.extract_resources)
                .on_toggle(Message::ExtractResourcesToggled),
            checkbox("Export JSON", self.settings.export_json)
                .on_toggle(Message::ExportJsonToggled),
        ]
        .spacing(8);

        let scan_button = match self.state {
            AppState::Scanning => button("Cancel Scan")
                .on_press(Message::CancelScan)
                .padding(15)
                .width(Length::Fill)
                .style(theme::cancel_button_style),
            _ => button("Start Scan")
                .on_press(Message::StartScan)
                .padding(15)
                .width(Length::Fill)
                .style(theme::primary_button_style),
        };

        let progress_section = if matches!(self.state, AppState::Scanning) {
            let pg = self.progress.lock().unwrap();
            let percent_text = format!("{:.0}%", pg.percentage());
            let files_text = format!("{}/{} files", pg.current, pg.total);
            column![
                progress_bar(0.0..=100.0, pg.percentage()),
                row![
                    text(percent_text).size(14),
                    horizontal_space(),
                    text(files_text).size(12)
                ],
            ]
            .spacing(5)
        } else {
            column![]
        };

        let status_section = match &self.state {
            AppState::Idle => {
                column![text("Ready to scan")
                    .size(14)
                    .style(|_theme: &Theme| text::Style {
                        color: Some(Color::from_rgb(0.5, 0.5, 0.5)),
                    })]
            }
            AppState::Scanning => {
                column![text("Scanning in progress...")
                    .size(14)
                    .style(|_theme: &Theme| text::Style {
                        color: Some(Color::from_rgb(0.3, 0.7, 1.0)),
                    })]
            }
            AppState::Completed => {
                let findings_count = self
                    .results
                    .iter()
                    .filter(|r| !r.matches.is_empty())
                    .count();
                column![text(format!(
                    "Scan completed: {} files scanned, {} with findings",
                    self.results.len(),
                    findings_count
                ))
                .size(14)
                .style(|_theme: &Theme| text::Style {
                    color: Some(Color::from_rgb(0.3, 1.0, 0.3)),
                })]
            }
            AppState::Error(e) => {
                column![text(format!("Error: {}", e))
                    .size(14)
                    .style(|_theme: &Theme| text::Style {
                        color: Some(Color::from_rgb(1.0, 0.3, 0.3)),
                    })]
            }
        };

        column![
            title,
            subtitle,
            vertical_space().height(20),
            path_row,
            vertical_space().height(15),
            mode_picker,
            vertical_space().height(15),
            quick_options,
            vertical_space().height(20),
            scan_button,
            vertical_space().height(10),
            progress_section,
            vertical_space().height(10),
            status_section,
        ]
        .spacing(5)
        .width(Length::Fill)
        .into()
    }

    fn view_results_tab(&self) -> Element<'_, Message> {
        let title = row![text("Scan Results").size(24)].align_y(Alignment::Center);

        let toolbar = row![
            text_input("Search results...", &self.results_ui.search)
                .on_input(Message::ResultsSearchChanged)
                .padding(8)
                .width(Length::FillPortion(3)),
            pick_list(
                &SEVERITY_OPTIONS[..],
                Some(self.results_ui.severity),
                Message::ResultsSeverityChanged
            )
            .padding(8)
            .width(Length::Fixed(140.0)),
            horizontal_space(),
            button("Clear")
                .on_press(Message::ClearResults)
                .style(theme::button_style)
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        if self.results.is_empty() {
            return column![
                title,
                vertical_space().height(10),
                toolbar,
                vertical_space().height(30),
                text("No results yet. Run a scan to see results here.")
                    .size(16)
                    .style(|_theme: &Theme| text::Style {
                        color: Some(Color::from_rgb(0.5, 0.5, 0.5)),
                    }),
            ]
            .spacing(10)
            .into();
        }

        let base_results: Vec<&ScanResult> = self
            .results
            .iter()
            .filter(|r| !r.matches.is_empty())
            .collect();

        let severity_min = match self.results_ui.severity {
            "Low" => 1,
            "Medium" => 4,
            "High" => 7,
            "Critical" => 9,
            _ => 0,
        };

        let search = self.results_ui.search.to_lowercase();

        let filtered_results: Vec<&ScanResult> = base_results
            .into_iter()
            .filter(|r| {
                if r.danger_score < severity_min {
                    return false;
                }
                if search.is_empty() {
                    return true;
                }
                if r.file_path.to_lowercase().contains(&search) {
                    return true;
                }
                for (_t, v) in &r.matches {
                    if v.to_lowercase().contains(&search) {
                        return true;
                    }
                }
                false
            })
            .collect();

        let mut findings_by_type: HashMap<FindingType, Vec<(&ScanResult, &String)>> =
            HashMap::new();
        for result in &filtered_results {
            for (finding_type, value) in &result.matches {
                findings_by_type
                    .entry(finding_type.clone())
                    .or_default()
                    .push((result, value));
            }
        }

        let summary = column![
            text(format!("Total files scanned: {}", self.results.len())),
            text(format!(
                "Files with findings (after filter): {}",
                filtered_results.len()
            )),
            text(format!(
                "Total findings: {}",
                findings_by_type.values().map(|v| v.len()).sum::<usize>()
            )),
        ]
        .spacing(5);

        let mut findings_list = Column::new().spacing(10).padding(10);

        for (i, result) in filtered_results.iter().enumerate() {
            let is_expanded = self.expanded_findings.contains(&i);

            let danger_color = theme::danger_color(result.danger_score);

            let header = button(
                row![
                    text(&result.file_path).width(Length::FillPortion(3)).style(
                        |_theme: &Theme| text::Style {
                            color: Some(Color::from_rgb(0.7, 0.9, 1.0)),
                        }
                    ),
                    text(format!("Risk: {}/10", result.danger_score))
                        .width(Length::FillPortion(1))
                        .style(move |_theme: &Theme| text::Style {
                            color: Some(danger_color),
                        }),
                    text(format!("Findings: {}", result.matches.len()))
                        .width(Length::FillPortion(1)),
                ]
                .spacing(10)
                .padding(5),
            )
            .on_press(Message::ExpandFinding(i))
            .width(Length::Fill)
            .style(theme::result_button_style);

            findings_list = findings_list.push(header);

            if is_expanded {
                let mut details = Column::new().spacing(5).padding(15);

                for explanation in &result.danger_explanation {
                    details = details.push(text(explanation).size(12).style(|_theme: &Theme| {
                        text::Style {
                            color: Some(Color::from_rgb(0.9, 0.9, 0.9)),
                        }
                    }));
                }

                details = details.push(vertical_space().height(10));
                details = details.push(text("Findings:").size(14));

                for (finding_type, value) in &result.matches {
                    details = details.push(
                        row![
                            text(format!("• {}: ", finding_type)).size(12).style(
                                |_theme: &Theme| text::Style {
                                    color: Some(Color::from_rgb(0.5, 0.8, 1.0)),
                                }
                            ),
                            text(value).size(12),
                        ]
                        .spacing(5),
                    );
                }

                findings_list = findings_list.push(
                    container(details)
                        .style(|_theme: &Theme| container::Style {
                            background: Some(Color::from_rgb(0.15, 0.15, 0.2).into()),
                            border: iced::Border {
                                color: Color::from_rgb(0.3, 0.3, 0.4),
                                width: 1.0,
                                radius: 5.0.into(),
                            },
                            ..Default::default()
                        })
                        .padding(10)
                        .width(Length::Fill),
                );
            }
        }

        let results_scroll = scrollable(findings_list)
            .height(Length::Fill)
            .width(Length::Fill);

        column![
            title,
            toolbar,
            vertical_space().height(10),
            summary,
            vertical_space().height(10),
            results_scroll
        ]
        .spacing(10)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn view_settings_tab(&self) -> Element<'_, Message> {
        let title = text("Advanced Settings").size(24);

        let threads_row = row![
            text("Thread count (0 = auto):").width(Length::Fixed(180.0)),
            text_input("0", &self.settings.threads)
                .on_input(Message::ThreadsChanged)
                .padding(10)
                .width(Length::Fill),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let exclude_section = column![
            text("Exclude Patterns:").size(16),
            row![
                text_input("*.txt, test/**", &self.settings.exclude_pattern_input)
                    .on_input(Message::ExcludePatternChanged)
                    .padding(10)
                    .width(Length::FillPortion(3)),
                button("Add")
                    .on_press(Message::AddExcludePattern)
                    .padding(10)
                    .style(theme::button_style),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
        ]
        .spacing(8);

        let mut exclude_list = Column::new().spacing(5);
        for (i, pattern) in self.settings.exclude_patterns.iter().enumerate() {
            exclude_list = exclude_list.push(
                row![
                    text(pattern).width(Length::Fill),
                    button("Remove")
                        .on_press(Message::RemoveExcludePattern(i))
                        .style(theme::button_style),
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            );
        }

        let find_section = column![
            text("Find Patterns (only scan matching):").size(16),
            row![
                text_input("*.class, com/**", &self.settings.find_pattern_input)
                    .on_input(Message::FindPatternChanged)
                    .padding(10)
                    .width(Length::FillPortion(3)),
                button("Add")
                    .on_press(Message::AddFindPattern)
                    .padding(10)
                    .style(theme::button_style),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
        ]
        .spacing(8);

        let mut find_list = Column::new().spacing(5);
        for (i, pattern) in self.settings.find_patterns.iter().enumerate() {
            find_list = find_list.push(
                row![
                    text(pattern).width(Length::Fill),
                    button("Remove")
                        .on_press(Message::RemoveFindPattern(i))
                        .style(theme::button_style),
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            );
        }

        let settings_content = column![
            title,
            vertical_space().height(15),
            threads_row,
            vertical_space().height(20),
            exclude_section,
            exclude_list,
            vertical_space().height(20),
            find_section,
            find_list,
        ]
        .spacing(5);

        scrollable(settings_content)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }

    async fn perform_scan(
        settings: ScanSettings,
        progress: ScanProgress,
    ) -> Result<Vec<ScanResult>, String> {
        let path = PathBuf::from(&settings.path);

        let threads: usize = settings.threads.parse().unwrap_or(0);
        if threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global()
                .map_err(|e| format!("Failed to configure threads: {}", e))?;
        }

        let scanner_options = ScannerOptions {
            extract_strings: settings.extract_strings,
            extract_resources: settings.extract_resources,
            output_dir: PathBuf::from("./extracted"),
            export_json: settings.export_json,
            mode: settings.mode,
            verbose: settings.verbose,
            ignore_keywords_file: None,
            exclude_patterns: settings.exclude_patterns,
            find_patterns: settings.find_patterns,
            max_file_size: None,
            progress: Some(progress.clone()),
        };

        let scanner = CollapseScanner::new(scanner_options)
            .map_err(|e| format!("Failed to create scanner: {}", e))?;

        let results = scanner
            .scan_path(&path)
            .map_err(|e| format!("Scan failed: {}", e))?;

        Ok(results)
    }
}

fn tab_button(label: &str, index: usize, active: usize) -> Element<'_, Message> {
    let is_active = index == active;

    button(text(label))
        .on_press(Message::TabSelected(index))
        .padding(10)
        .style(move |theme: &Theme, status| {
            if is_active {
                button::Style {
                    background: Some(Color::from_rgb(0.2, 0.4, 0.7).into()),
                    text_color: Color::WHITE,
                    border: iced::Border {
                        color: Color::from_rgb(0.3, 0.5, 0.8),
                        width: 2.0,
                        radius: 5.0.into(),
                    },
                    ..button::primary(theme, status)
                }
            } else {
                button::Style {
                    background: Some(Color::from_rgb(0.2, 0.2, 0.25).into()),
                    text_color: Color::from_rgb(0.7, 0.7, 0.7),
                    border: iced::Border {
                        color: Color::from_rgb(0.3, 0.3, 0.35),
                        width: 1.0,
                        radius: 5.0.into(),
                    },
                    ..button::secondary(theme, status)
                }
            }
        })
        .into()
}


pub fn run_gui() -> iced::Result {
    iced::application("CollapseScanner", CollapseApp::update, CollapseApp::view)
        .theme(CollapseApp::theme)
        .subscription(CollapseApp::subscription)
        .window(iced::window::Settings {
            size: iced::Size::new(900.0, 700.0),
            min_size: Some(iced::Size::new(700.0, 500.0)),
            ..Default::default()
        })
        .run_with(CollapseApp::new)
}
