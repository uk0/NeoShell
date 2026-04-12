mod app;
mod crypto;
mod ssh;
mod storage;
mod terminal;
mod ui;

fn main() -> iced::Result {
    env_logger::init();
    app::run()
}
