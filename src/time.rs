use std::time::Instant;

pub struct Clock {
    epoch: Instant,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }

    pub fn now_secs(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }
}
