use fairypam_agent_protocol::worker_v1::WindowsIoMode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsIoArbiter {
    mode: WindowsIoMode,
    input_owner_epoch: u64,
    held_action_ids: Vec<String>,
}

impl Default for WindowsIoArbiter {
    fn default() -> Self {
        Self {
            mode: WindowsIoMode::Detached,
            input_owner_epoch: 0,
            held_action_ids: Vec::new(),
        }
    }
}

impl WindowsIoArbiter {
    pub const fn mode(&self) -> WindowsIoMode {
        self.mode
    }

    pub const fn input_owner_epoch(&self) -> u64 {
        self.input_owner_epoch
    }

    #[cfg(windows)]
    pub fn held_action_ids(&self) -> Vec<String> {
        self.held_action_ids.clone()
    }

    pub fn attach(&mut self) -> Result<(), &'static str> {
        self.require(WindowsIoMode::Detached)?;
        self.advance_owner()?;
        self.mode = WindowsIoMode::Generic;
        Ok(())
    }

    pub fn detach(&mut self) -> Result<(), &'static str> {
        if !self.held_action_ids.is_empty()
            || !matches!(self.mode, WindowsIoMode::Generic | WindowsIoMode::Faulted)
        {
            return Err("worker.io_busy");
        }
        self.advance_owner()?;
        self.mode = WindowsIoMode::Detached;
        Ok(())
    }

    pub fn allow_generic_input(&self, owner_epoch: u64) -> Result<(), &'static str> {
        self.require_owner(owner_epoch)?;
        self.require(WindowsIoMode::Generic)
    }

    pub fn record_generic_holds(
        &mut self,
        owner_epoch: u64,
        held_action_ids: Vec<String>,
    ) -> Result<(), &'static str> {
        self.allow_generic_input(owner_epoch)?;
        self.held_action_ids = held_action_ids;
        Ok(())
    }

    pub fn begin_realtime(&mut self, owner_epoch: u64) -> Result<(), &'static str> {
        self.allow_generic_input(owner_epoch)?;
        if !self.held_action_ids.is_empty() {
            return Err("worker.input_still_held");
        }
        self.mode = WindowsIoMode::GenericDraining;
        Ok(())
    }

    pub fn generic_drained(&mut self) -> Result<(), &'static str> {
        self.require(WindowsIoMode::GenericDraining)?;
        self.mode = WindowsIoMode::RealtimeStarting;
        Ok(())
    }

    pub fn cancel_realtime_start(&mut self) -> Result<(), &'static str> {
        if !matches!(
            self.mode,
            WindowsIoMode::GenericDraining | WindowsIoMode::RealtimeStarting
        ) {
            return Err("worker.io_mode_invalid");
        }
        self.held_action_ids.clear();
        self.mode = WindowsIoMode::Generic;
        Ok(())
    }

    pub fn realtime_started(&mut self) -> Result<u64, &'static str> {
        self.require(WindowsIoMode::RealtimeStarting)?;
        self.advance_owner()?;
        self.mode = WindowsIoMode::Realtime;
        Ok(self.input_owner_epoch)
    }

    pub fn begin_realtime_release(&mut self, owner_epoch: u64) -> Result<(), &'static str> {
        self.require_owner(owner_epoch)?;
        self.require(WindowsIoMode::Realtime)?;
        self.mode = WindowsIoMode::RealtimeReleasing;
        Ok(())
    }

    pub fn realtime_released(&mut self) -> Result<u64, &'static str> {
        self.require(WindowsIoMode::RealtimeReleasing)?;
        self.held_action_ids.clear();
        self.advance_owner()?;
        self.mode = WindowsIoMode::Generic;
        Ok(self.input_owner_epoch)
    }

    pub fn fault(&mut self) {
        self.mode = WindowsIoMode::Faulted;
        self.held_action_ids.clear();
        let _ = self.advance_owner();
    }

    fn require(&self, expected: WindowsIoMode) -> Result<(), &'static str> {
        (self.mode == expected)
            .then_some(())
            .ok_or("worker.io_mode_invalid")
    }

    fn require_owner(&self, owner_epoch: u64) -> Result<(), &'static str> {
        (owner_epoch == self.input_owner_epoch)
            .then_some(())
            .ok_or("worker.input_owner_stale")
    }

    fn advance_owner(&mut self) -> Result<(), &'static str> {
        self.input_owner_epoch = self
            .input_owner_epoch
            .checked_add(1)
            .ok_or("worker.input_owner_exhausted")?;
        Ok(())
    }
}

#[cfg(windows)]
pub struct RealtimeHost {
    program: Option<fairypam_agent_realtime::music_engine::windows::GenshinMusicProgram>,
}

#[cfg(windows)]
impl RealtimeHost {
    pub const fn new() -> Self {
        Self { program: None }
    }

    pub fn start(
        &mut self,
        hwnd: usize,
        spec: &fairypam_agent_realtime::spec::VerifiedRealtimeSpec,
        profile: &fairypam_agent_core::profile::VerifiedProfile,
        maximum_duration: std::time::Duration,
        supervision_lease: Option<std::time::Duration>,
    ) -> Result<(), fairypam_agent_realtime::RealtimeError> {
        use fairypam_agent_core::profile::ActionDefinition;
        use fairypam_agent_realtime::input_batch::PhysicalKey;

        if self.program.is_some() {
            return Err(fairypam_agent_realtime::RealtimeError::new(
                "realtime.program_already_running",
                "a realtime program is already running",
            ));
        }
        let keys = spec
            .spec()
            .lanes
            .iter()
            .map(
                |lane| match profile.profile().actions.get(&lane.action_id) {
                    Some(ActionDefinition::Hold {
                        physical_scan_code,
                        extended,
                        ..
                    }) => Ok(PhysicalKey {
                        action_id: lane.action_id.clone(),
                        scan_code: *physical_scan_code,
                        extended: *extended,
                    }),
                    _ => Err(fairypam_agent_realtime::RealtimeError::new(
                        "realtime.input_profile_invalid",
                        "lane action has no signed physical key mapping",
                    )),
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        self.program = Some(
            fairypam_agent_realtime::music_engine::windows::GenshinMusicProgram::start(
                hwnd,
                spec,
                keys,
                maximum_duration,
                supervision_lease,
            )?,
        );
        Ok(())
    }

    pub fn renew(
        &self,
        lease: std::time::Duration,
    ) -> Result<(), fairypam_agent_realtime::RealtimeError> {
        self.program
            .as_ref()
            .ok_or_else(|| {
                fairypam_agent_realtime::RealtimeError::new(
                    "realtime.program_not_running",
                    "realtime program is not running",
                )
            })?
            .renew(lease)
    }

    pub fn stop(
        &mut self,
    ) -> Option<fairypam_agent_realtime::music_engine::windows::MusicProgramResult> {
        self.program.take().map(|program| program.stop())
    }

    pub fn take_finished(
        &mut self,
    ) -> Option<fairypam_agent_realtime::music_engine::windows::MusicProgramResult> {
        if !self
            .program
            .as_ref()
            .is_some_and(|value| value.is_finished())
        {
            return None;
        }
        let mut program = self.program.take()?;
        Some(program.join())
    }

    pub fn held_action_ids(&self) -> Result<Vec<String>, fairypam_agent_realtime::RealtimeError> {
        self.program
            .as_ref()
            .map_or(Ok(Vec::new()), |program| program.held_action_ids())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_and_realtime_never_share_an_input_owner() {
        let mut arbiter = WindowsIoArbiter::default();
        arbiter.attach().unwrap();
        let generic_owner = arbiter.input_owner_epoch();
        arbiter.begin_realtime(generic_owner).unwrap();
        arbiter.generic_drained().unwrap();
        let realtime_owner = arbiter.realtime_started().unwrap();
        assert_ne!(generic_owner, realtime_owner);
        assert_eq!(
            arbiter.allow_generic_input(generic_owner),
            Err("worker.input_owner_stale")
        );
        assert_eq!(
            arbiter.allow_generic_input(realtime_owner),
            Err("worker.io_mode_invalid")
        );

        arbiter.begin_realtime_release(realtime_owner).unwrap();
        let next_generic_owner = arbiter.realtime_released().unwrap();
        assert!(arbiter.allow_generic_input(next_generic_owner).is_ok());
    }

    #[test]
    fn backend_cannot_switch_while_a_key_is_held() {
        let mut arbiter = WindowsIoArbiter::default();
        arbiter.attach().unwrap();
        let owner = arbiter.input_owner_epoch();
        arbiter
            .record_generic_holds(owner, vec!["move.forward".into()])
            .unwrap();
        assert_eq!(
            arbiter.begin_realtime(owner),
            Err("worker.input_still_held")
        );
    }

    #[test]
    fn fault_and_detach_invalidate_the_previous_owner() {
        let mut arbiter = WindowsIoArbiter::default();
        arbiter.attach().unwrap();
        let owner = arbiter.input_owner_epoch();
        arbiter.fault();
        assert_eq!(arbiter.mode(), WindowsIoMode::Faulted);
        assert_ne!(arbiter.input_owner_epoch(), owner);
        arbiter.detach().unwrap();
        assert_eq!(arbiter.mode(), WindowsIoMode::Detached);
    }

    #[test]
    fn failed_realtime_start_returns_to_generic_only_after_release() {
        let mut arbiter = WindowsIoArbiter::default();
        arbiter.attach().unwrap();
        let owner = arbiter.input_owner_epoch();
        arbiter.begin_realtime(owner).unwrap();
        arbiter.generic_drained().unwrap();
        arbiter.cancel_realtime_start().unwrap();
        assert!(arbiter.allow_generic_input(owner).is_ok());
    }
}
