use sockets_latch::{Decision, ErrorCode, Latch, Local, Operation, SocketsErrorCode};

const LATCH_NAME: &str = "latch-deny-random";

/// The fraction of operations denied when `probability` is not configured.
const DEFAULT_PROBABILITY: f64 = 0.1;

mod random {
    wit_bindgen::generate!({
        path: "../wit",
        world: "insecure-random",
        generate_all
    });
}

struct Config {
    /// The fraction of operations denied, from 0 to 1.
    probability: f64,
    /// Seeds the decisions, the same seed denies the same operations.
    seed: u64,
    reason: SocketsErrorCode,
}

impl Config {
    /// Load the config, logging why when the config is invalid.
    fn load() -> Result<Config, ErrorCode> {
        let config = sockets_latch::load_config(LATCH_NAME, |config| {
            Config::parse(config, || {
                random::wasi::random::insecure::get_insecure_random_u64()
            })
        })?;
        // the seed reproduces the decisions, e.g. a failure the random seed uncovered
        sockets_latch::warn!(
            "Randomly denying wasi:sockets operations PROBABILITY={} SEED={}",
            config.probability,
            config.seed
        );
        Ok(config)
    }

    fn parse(
        config: Vec<(String, String)>,
        random_seed: impl FnOnce() -> u64,
    ) -> Result<Config, String> {
        let mut probability = DEFAULT_PROBABILITY;
        let mut seed = None;
        let mut reason = SocketsErrorCode::AccessDenied;

        for (key, value) in config {
            let invalid = |err: &str| format!("KEY={key} VALUE={value} ERROR={err}");
            match key.as_str() {
                "probability" => {
                    probability = value
                        .parse::<f64>()
                        .ok()
                        .filter(|probability| (0.0..=1.0).contains(probability))
                        .ok_or_else(|| invalid("expected a number from 0 to 1"))?;
                }
                "seed" => {
                    seed = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| invalid("expected an unsigned 64 bit integer"))?,
                    );
                }
                "reason" => {
                    reason = get_error_code(value).unwrap_or(SocketsErrorCode::AccessDenied);
                }
                _ => {}
            }
        }

        Ok(Config {
            probability,
            seed: seed.unwrap_or_else(random_seed),
            reason,
        })
    }

    /// The decision for the operation observed after `observed` others.
    fn decide(&self, observed: u64) -> Decision {
        match sample(self.seed, observed) < self.probability {
            true => Decision::Denied(self.reason.clone()),
            false => Decision::Deferred,
        }
    }
}

/// A uniformly distributed number from 0 up to 1, the same for the same seed and index.
fn sample(seed: u64, index: u64) -> f64 {
    // splitmix64, each index is a step of the sequence the seed starts
    let mut z = seed.wrapping_add(index.wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    // the top 53 bits, the precision of an f64
    (z >> 11) as f64 / (1u64 << 53) as f64
}

fn get_error_code(value: String) -> Option<SocketsErrorCode> {
    match value.as_str() {
        "" => None,
        "access-denied" => Some(SocketsErrorCode::AccessDenied),
        "invalid-argument" => Some(SocketsErrorCode::InvalidArgument),
        "other" => Some(SocketsErrorCode::Other(None)),
        _ => Some(SocketsErrorCode::Other(Some(value))),
    }
}

/// `None` until the config is loaded.
static CONFIG: Local<Option<Result<Config, ErrorCode>>> = Local::new(None);

/// The number of operations observed.
static OBSERVED: Local<u64> = Local::new(0);

struct RandomLatch {}

impl Latch for RandomLatch {
    fn authorize(_operation: Operation) -> Result<Decision, ErrorCode> {
        // the decision only depends on how many operations were observed, authorizing does not
        // change it, so an operation another latch denied first does not shift the decisions
        match CONFIG.borrow_mut().get_or_insert_with(Config::load) {
            Ok(config) => Ok(config.decide(*OBSERVED.borrow())),
            Err(err) => Err(err.clone()),
        }
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        *OBSERVED.borrow_mut() += 1;
        Ok(())
    }
}

sockets_latch::export!(RandomLatch with_types_in sockets_latch::bindings);

#[cfg(test)]
mod tests {
    use super::*;

    fn config(entries: &[(&str, &str)]) -> Result<Config, String> {
        let entries = entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        Config::parse(entries, || 42)
    }

    fn denied(config: &Config, operations: u64) -> Vec<u64> {
        (0..operations)
            .filter(|observed| matches!(config.decide(*observed), Decision::Denied(_)))
            .collect()
    }

    #[test]
    fn defaults() {
        let config = config(&[]).expect("valid config");
        assert_eq!(config.probability, DEFAULT_PROBABILITY);
        assert_eq!(config.seed, 42, "seeded randomly");
        assert!(matches!(config.reason, SocketsErrorCode::AccessDenied));
    }

    #[test]
    fn denies_about_the_configured_fraction() {
        for probability in [0.1, 0.5, 0.9] {
            let config = config(&[("probability", &probability.to_string()), ("seed", "7")])
                .expect("valid config");
            let fraction = denied(&config, 10_000).len() as f64 / 10_000.0;
            assert!(
                (fraction - probability).abs() < 0.02,
                "probability={probability} fraction={fraction}"
            );
        }
    }

    #[test]
    fn never_or_always_denies() {
        let never = config(&[("probability", "0")]).expect("valid config");
        assert!(denied(&never, 1_000).is_empty());
        let always = config(&[("probability", "1")]).expect("valid config");
        assert_eq!(denied(&always, 1_000).len(), 1_000);
    }

    #[test]
    fn same_seed_same_decisions() {
        let first = config(&[("probability", "0.5"), ("seed", "1")]).expect("valid config");
        let again = config(&[("probability", "0.5"), ("seed", "1")]).expect("valid config");
        let other = config(&[("probability", "0.5"), ("seed", "2")]).expect("valid config");
        assert_eq!(denied(&first, 100), denied(&again, 100));
        assert_ne!(denied(&first, 100), denied(&other, 100));
    }

    #[test]
    fn denies_with_configured_reason() {
        let config =
            config(&[("probability", "1"), ("reason", "invalid-argument")]).expect("valid config");
        assert!(matches!(
            config.decide(0),
            Decision::Denied(SocketsErrorCode::InvalidArgument)
        ));
    }

    #[test]
    fn invalid_config() {
        for (key, value) in [
            ("probability", "1.5"),
            ("probability", "-0.1"),
            ("probability", "often"),
            ("seed", "-1"),
            ("seed", "random"),
        ] {
            let err = config(&[(key, value)]).err().expect("invalid config");
            assert!(
                err.starts_with(&format!("KEY={key} VALUE={value} ERROR=")),
                "{err}"
            );
        }
    }
}
