//! Fixed-window rate limiting per (device, provider).
//!
//! Windows are aligned to UTC minutes and days. The state is tiny and lives in the device's
//! `DeviceState` Durable Object, which serializes updates, so check-and-increment is atomic.

use serde::{Deserialize, Serialize};

use crate::RateLimit;

const MINUTE_MS: u64 = 60_000;
const DAY_MS: u64 = 86_400_000;

/// Persisted counters for the current minute and day windows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateWindows {
    pub minute: u64,
    pub minute_count: u32,
    pub day: u64,
    pub day_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// The request is allowed; persist the returned windows.
    Allowed(RateWindows),
    /// The request exceeds a limit; nothing changes.
    Limited { retry_after_secs: u64 },
}

impl RateWindows {
    pub fn check(self, limit: &RateLimit, now_ms: u64) -> RateDecision {
        let minute = now_ms / MINUTE_MS;
        let day = now_ms / DAY_MS;
        let minute_count = if self.minute == minute {
            self.minute_count
        } else {
            0
        };
        let day_count = if self.day == day { self.day_count } else { 0 };

        let retry_after =
            |window_end_ms: u64| window_end_ms.saturating_sub(now_ms).div_ceil(1000).max(1);
        if limit.per_minute.is_some_and(|max| minute_count >= max) {
            return RateDecision::Limited {
                retry_after_secs: retry_after((minute + 1) * MINUTE_MS),
            };
        }
        if limit.per_day.is_some_and(|max| day_count >= max) {
            return RateDecision::Limited {
                retry_after_secs: retry_after((day + 1) * DAY_MS),
            };
        }
        RateDecision::Allowed(Self {
            minute,
            minute_count: minute_count.saturating_add(1),
            day,
            day_count: day_count.saturating_add(1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_750_000_040_000; // 20 s into a minute

    fn run(limit: RateLimit, times: &[u64]) -> Vec<RateDecision> {
        let mut state = RateWindows::default();
        times
            .iter()
            .map(|&t| {
                let decision = state.check(&limit, t);
                if let RateDecision::Allowed(next) = decision {
                    state = next;
                }
                decision
            })
            .collect()
    }

    fn allowed(d: &RateDecision) -> bool {
        matches!(d, RateDecision::Allowed(_))
    }

    #[test]
    fn per_minute_limit_and_reset() {
        let limit = RateLimit {
            per_minute: Some(2),
            per_day: None,
        };
        let decisions = run(limit, &[T0, T0 + 1, T0 + 2, T0 + 40_000]);
        assert!(allowed(&decisions[0]) && allowed(&decisions[1]));
        assert_eq!(
            decisions[2],
            RateDecision::Limited {
                retry_after_secs: 40
            }
        );
        // Next minute window.
        assert!(allowed(&decisions[3]));
    }

    #[test]
    fn per_day_limit() {
        let limit = RateLimit {
            per_minute: None,
            per_day: Some(3),
        };
        let day_start = T0 - T0 % DAY_MS;
        let times = [
            day_start + 1,
            day_start + 120_000,
            day_start + 240_000,
            day_start + 360_000,
        ];
        let decisions = run(limit, &times);
        assert_eq!(decisions.iter().filter(|d| allowed(d)).count(), 3);
        assert_eq!(
            decisions[3],
            RateDecision::Limited {
                retry_after_secs: (DAY_MS - 360_000) / 1000
            }
        );
        // A new day resets the counter.
        assert!(allowed(&run(limit, &[day_start + DAY_MS])[0]));
    }

    #[test]
    fn limited_requests_do_not_count() {
        let limit = RateLimit {
            per_minute: Some(1),
            per_day: Some(10),
        };
        let mut state = RateWindows::default();
        let RateDecision::Allowed(next) = state.check(&limit, T0) else {
            panic!()
        };
        state = next;
        for i in 1..5 {
            assert!(!allowed(&state.check(&limit, T0 + i)));
        }
        assert_eq!(state.day_count, 1);
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        let limit = RateLimit {
            per_minute: Some(1),
            per_day: None,
        };
        let minute_end = (T0 / MINUTE_MS + 1) * MINUTE_MS;
        let decisions = run(limit, &[minute_end - 500, minute_end - 1]);
        assert_eq!(
            decisions[1],
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
    }
}
