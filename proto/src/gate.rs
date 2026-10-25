//! Pairing attempt limits.
//!
//! A 6 digit code with one step of slack either side is a 3 in a million guess,
//! so an endpoint open to the internet needs a hard ceiling on attempts, not
//! just a delay. Every attempt is counted *before* its code is checked:
//!
//! - at most [`FAILS_PER_WINDOW`] attempts per [`WINDOW_SECS`], and
//! - at most [`FAILS_TOTAL`] failures since the last success, after which
//!   pairing stays off until the host turns it back on (`cldp pair --reset`).
//!
//! A success clears both counts. A code is good once: its step must be later
//! than the last accepted one, so a code seen over someone's shoulder cannot
//! be replayed within its 90 second life.
//!
//! The worker keeps one [`PairState`] row and writes every change with a
//! compare-and-set on `ver`, so parallel requests cannot share a reservation.

use serde::{Deserialize, Serialize};

/// Length of a rate window.
pub const WINDOW_SECS: i64 = 3600;
/// Attempts allowed per window.
pub const FAILS_PER_WINDOW: i64 = 3;
/// Failures allowed in total before pairing is switched off.
pub const FAILS_TOTAL: i64 = 10;

/// The worker's single pairing row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairState {
    /// Bumped on every write; the compare-and-set key.
    pub ver: i64,
    /// The TOTP step of the last accepted code.
    pub last_step: i64,
    /// Attempts in the current window (counted before checking).
    pub fails: i64,
    /// Unix seconds the current window started.
    pub window_start: i64,
    /// Failures since the last success or host reset.
    pub total_fails: i64,
}

/// Whether an attempt may go ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Go ahead; store this state (the attempt already counted) first.
    Open(PairState),
    /// Too many attempts this window.
    Locked { retry_after: i64 },
    /// Too many failures overall; the host has to turn pairing back on.
    Disabled,
}

impl PairState {
    /// Count an attempt at `now` (unix seconds), or refuse it.
    pub fn reserve(&self, now: i64) -> Gate {
        if self.total_fails >= FAILS_TOTAL {
            return Gate::Disabled;
        }
        let mut next = *self;
        if now - self.window_start >= WINDOW_SECS || now < self.window_start {
            next.window_start = now;
            next.fails = 0;
        }
        if next.fails >= FAILS_PER_WINDOW {
            return Gate::Locked {
                retry_after: (next.window_start + WINDOW_SECS - now).max(1),
            };
        }
        next.fails += 1;
        next.total_fails += 1;
        next.ver += 1;
        Gate::Open(next)
    }

    /// The state after a correct code from `step`, or `None` if that step (or
    /// a later one) was already used.
    pub fn accept(&self, step: i64) -> Option<PairState> {
        (step > self.last_step).then_some(PairState {
            ver: self.ver + 1,
            last_step: step,
            fails: 0,
            window_start: self.window_start,
            total_fails: 0,
        })
    }

    /// The host turned pairing back on.
    pub fn reset(&self) -> PairState {
        PairState {
            ver: self.ver + 1,
            fails: 0,
            total_fails: 0,
            ..*self
        }
    }

    /// Pairing is switched off until a host reset.
    pub fn disabled(&self) -> bool {
        self.total_fails >= FAILS_TOTAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(g: Gate) -> PairState {
        match g {
            Gate::Open(s) => s,
            other => panic!("expected open, got {other:?}"),
        }
    }

    #[test]
    fn three_attempts_per_window_then_locked_until_it_ends() {
        let t0 = 10_000;
        let mut s = PairState::default();
        for i in 0..FAILS_PER_WINDOW {
            s = open(s.reserve(t0 + i));
        }
        assert_eq!(s.fails, FAILS_PER_WINDOW);
        assert_eq!(
            s.reserve(t0 + 10),
            Gate::Locked {
                retry_after: WINDOW_SECS - 10
            }
        );
        // A new window opens once the old one has run out.
        let s = open(s.reserve(t0 + WINDOW_SECS));
        assert_eq!(s.fails, 1);
        assert_eq!(s.window_start, t0 + WINDOW_SECS);
    }

    #[test]
    fn total_failures_switch_pairing_off_until_reset() {
        let mut s = PairState::default();
        let mut now = 0;
        while !s.disabled() {
            match s.reserve(now) {
                Gate::Open(next) => s = next,
                Gate::Locked { retry_after } => now += retry_after,
                Gate::Disabled => unreachable!(),
            }
        }
        assert_eq!(s.total_fails, FAILS_TOTAL);
        assert_eq!(s.reserve(now + 10 * WINDOW_SECS), Gate::Disabled);
        let s = s.reset();
        assert!(matches!(s.reserve(now + 10 * WINDOW_SECS), Gate::Open(_)));
    }

    #[test]
    fn success_clears_counts_and_burns_the_step() {
        let s = open(PairState::default().reserve(100));
        let ok = s.accept(5).expect("first use of step 5");
        assert_eq!((ok.fails, ok.total_fails, ok.last_step), (0, 0, 5));
        assert_eq!(ok.accept(5), None, "replay of the same step");
        assert_eq!(ok.accept(4), None, "older step");
        assert!(ok.accept(6).is_some());
    }

    #[test]
    fn every_write_bumps_the_version() {
        let s = PairState::default();
        let r = open(s.reserve(1));
        assert_eq!(r.ver, s.ver + 1);
        assert_eq!(r.accept(1).unwrap().ver, r.ver + 1);
        assert_eq!(r.reset().ver, r.ver + 1);
    }

    #[test]
    fn a_clock_step_backwards_starts_a_fresh_window() {
        let s = PairState {
            window_start: 5_000,
            fails: FAILS_PER_WINDOW,
            ..Default::default()
        };
        assert!(matches!(s.reserve(4_000), Gate::Open(_)));
    }
}
