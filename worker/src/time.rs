//! Wall-clock time from the Workers runtime.

pub fn now_ms() -> u64 {
    worker::Date::now().as_millis()
}

pub fn now_secs() -> u64 {
    now_ms() / 1000
}
