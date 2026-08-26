use std::time::Duration;

use crate::spec::VerifiedRealtimeSpec;
use crate::RealtimeError;

pub const MUSIC_AUTOPLAY_PROGRAM_ID: &str = "genshin.music-autoplay.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartProgram {
    pub program_id: String,
    pub schema_version: u32,
    pub digest: String,
    pub maximum_duration: Duration,
    pub supervision_lease: Option<Duration>,
}

impl StartProgram {
    pub fn bind(self, installed: &VerifiedRealtimeSpec) -> Result<Self, RealtimeError> {
        if self.program_id != MUSIC_AUTOPLAY_PROGRAM_ID
            || self.program_id != installed.spec().id
            || self.schema_version != installed.spec().schema_version
            || self.digest != installed.digest()
            || !(Duration::from_secs(1)..=Duration::from_secs(600)).contains(&self.maximum_duration)
            || self.supervision_lease.is_some_and(|value| {
                !(Duration::from_millis(500)..=Duration::from_secs(5)).contains(&value)
            })
        {
            return Err(RealtimeError::new(
                "realtime.program_invalid",
                "program request does not match the installed signed spec",
            ));
        }
        Ok(self)
    }
}
