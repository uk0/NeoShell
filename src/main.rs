#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod crypto;
mod ssh;
mod sshconfig;
mod storage;
mod terminal;
mod ui;

fn main() -> iced::Result {
    env_logger::init();
    app::run()
}
