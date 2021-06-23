use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

/// Measures duration of round proceeding
pub struct Benchmark {
    results: Option<BenchmarkResults>,
}

impl Benchmark {
    pub fn enabled() -> Self {
        Self {
            results: Some(Default::default()),
        }
    }

    pub fn disabled() -> Self {
        Self { results: None }
    }

    pub fn start(&mut self) -> Stopwatch {
        Stopwatch {
            started_at: Instant::now(),
            b: self,
        }
    }

    fn add_measurement(&mut self, round: u16, time: Duration) {
        if let Some(results) = self.results.as_mut() {
            let m = results.entry(round).or_insert(Measurements {
                n: 0,
                total_time: Duration::default(),
            });
            m.n += 1;
            m.total_time += time;
        }
    }

    pub fn results(&self) -> Option<&BenchmarkResults> {
        self.results.as_ref()
    }
}

pub struct Stopwatch<'a> {
    started_at: Instant,
    b: &'a mut Benchmark,
}

impl<'a> Stopwatch<'a> {
    pub fn stop_and_save(self, round_n: u16) -> Duration {
        let time = Instant::now().duration_since(self.started_at);
        self.b.add_measurement(round_n, time);
        time
    }
}

/// Benchmark results for every particular round
pub type BenchmarkResults = BTreeMap<u16, Measurements>;

/// Benchmark results for particular round
///
/// `n` measurements took in total `total_time`
pub struct Measurements {
    pub n: u16,
    pub total_time: Duration,
}

impl fmt::Debug for Measurements {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.total_time / u32::from(self.n))
    }
}
