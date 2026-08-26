use std::thread;
use std::time::{Duration, Instant};

pub fn wait_until(deadline: Instant) -> Duration {
    let now = Instant::now();
    if deadline > now {
        let remaining = deadline - now;
        if remaining > Duration::from_micros(300) {
            thread::sleep(remaining - Duration::from_micros(200));
        }
        while Instant::now() < deadline {
            std::hint::spin_loop();
        }
    }
    Instant::now().saturating_duration_since(deadline)
}
