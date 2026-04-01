use fuser::TimeOrNow;
use std::time::SystemTime;

pub trait ToEpochExt {
    fn to_u64(self) -> u64;
}

impl ToEpochExt for TimeOrNow {
    fn to_u64(self) -> u64 {
        let st = match self {
            TimeOrNow::SpecificTime(st) => st,
            TimeOrNow::Now => SystemTime::now(),
        };
        st.to_u64()
    }
}

impl ToEpochExt for SystemTime {
    fn to_u64(self) -> u64 {
        self.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
