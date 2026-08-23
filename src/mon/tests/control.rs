use mon::control;
use signal_hook::consts::signal::SIGTERM;

#[test]
fn run_returns_on_sigterm() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(100));
        signal_hook::low_level::raise(SIGTERM).unwrap();
    });
    // Returns only if the signal was received and handled.
    control::run().unwrap();
}
