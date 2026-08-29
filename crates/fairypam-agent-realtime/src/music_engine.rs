#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneState {
    pressed: bool,
}

impl LaneState {
    pub fn observe(&mut self, blue: u8, press_below: u8, release_at_or_above: u8) -> Option<bool> {
        let next = if self.pressed {
            blue < release_at_or_above
        } else {
            blue < press_below
        };
        if next == self.pressed {
            return None;
        }
        self.pressed = next;
        Some(next)
    }

    pub const fn pressed(&self) -> bool {
        self.pressed
    }
}

#[cfg(windows)]
pub mod windows {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::UI::WindowsAndMessaging::{GetClientRect, GetForegroundWindow, IsWindow};

    use super::LaneState;
    use crate::input_batch::windows::WindowsPhysicalInputBatch;
    use crate::input_batch::{KeyTransition, PhysicalInputBatch, PhysicalKey};
    use crate::local_input_monitor::windows::WindowsLocalInputMonitor;
    use crate::local_input_monitor::LocalInputMonitor;
    use crate::metrics::RealtimeMetrics;
    use crate::pixel_probe::windows::GdiPixelRowProbe;
    use crate::scheduler::wait_until;
    use crate::spec::VerifiedRealtimeSpec;
    use crate::RealtimeError;

    #[derive(Clone, Debug)]
    struct DetectedTransition {
        lane: usize,
        pressed: bool,
        detected_at: Instant,
    }

    #[derive(Default)]
    struct SamplerMetrics {
        samples: u64,
        missed_deadlines: u64,
        queue_overflows: u64,
        sample_intervals_us: Vec<u64>,
        scheduler_lateness_us: Vec<u64>,
    }

    pub struct MusicProgramResult {
        pub metrics: RealtimeMetrics,
        pub error: Option<RealtimeError>,
        pub release_uncertain: bool,
    }

    pub struct GenshinMusicProgram {
        stop: Arc<AtomicBool>,
        supervision_deadline: Arc<Mutex<Option<Instant>>>,
        held_action_ids: Arc<Mutex<BTreeSet<String>>>,
        thread: Option<JoinHandle<MusicProgramResult>>,
    }

    impl GenshinMusicProgram {
        pub fn start(
            hwnd: usize,
            spec: &VerifiedRealtimeSpec,
            keys: Vec<PhysicalKey>,
            maximum_duration: Duration,
            supervision_lease: Option<Duration>,
        ) -> Result<Self, RealtimeError> {
            let hwnd_value = hwnd;
            let hwnd = HWND(hwnd_value as *mut std::ffi::c_void);
            validate_target(hwnd, spec)?;
            let lane_keys = spec
                .spec()
                .lanes
                .iter()
                .map(|lane| {
                    keys.iter()
                        .find(|key| key.action_id == lane.action_id)
                        .cloned()
                        .ok_or_else(|| {
                            RealtimeError::new(
                                "realtime.input_profile_invalid",
                                "signed lane action has no physical mapping",
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let points: [(i32, i32); 6] = spec
                .spec()
                .lanes
                .iter()
                .map(|lane| {
                    let x = ppm(lane.x_ppm, spec.spec().required_client_size.width)?;
                    let y = ppm(lane.y_ppm, spec.spec().required_client_size.height)?;
                    Ok((x, y))
                })
                .collect::<Result<Vec<_>, RealtimeError>>()?
                .try_into()
                .map_err(|_| {
                    RealtimeError::new(
                        "realtime.spec_invalid",
                        "music program requires exactly six lanes",
                    )
                })?;
            let client_size = (
                spec.spec().required_client_size.width,
                spec.spec().required_client_size.height,
            );
            let stop = Arc::new(AtomicBool::new(false));
            let supervision_deadline = Arc::new(Mutex::new(
                supervision_lease.map(|value| Instant::now() + value),
            ));
            let worker_stop = Arc::clone(&stop);
            let worker_supervision = Arc::clone(&supervision_deadline);
            let held_action_ids = Arc::new(Mutex::new(BTreeSet::new()));
            let worker_held_action_ids = Arc::clone(&held_action_ids);
            let content = spec.spec().clone();
            let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
            let thread = std::thread::Builder::new()
                .name("fairypam-realtime-music".into())
                .spawn(move || {
                    run_genshin_music(
                        hwnd_value,
                        content,
                        lane_keys,
                        points,
                        client_size,
                        maximum_duration,
                        worker_supervision,
                        worker_stop,
                        worker_held_action_ids,
                        ready_sender,
                    )
                })
                .map_err(|error| RealtimeError::new("realtime.start_failed", error.to_string()))?;
            match ready_receiver.recv() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    stop.store(true, Ordering::Release);
                    let _ = thread.join();
                    return Err(error);
                }
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    let joined_error = thread.join().ok().and_then(|result| result.error);
                    return Err(joined_error.unwrap_or_else(|| {
                        RealtimeError::new("realtime.start_failed", error.to_string())
                    }));
                }
            }
            Ok(Self {
                stop,
                supervision_deadline,
                held_action_ids,
                thread: Some(thread),
            })
        }

        pub fn renew(&self, lease: Duration) -> Result<(), RealtimeError> {
            if self.thread.as_ref().is_none_or(JoinHandle::is_finished) {
                return Err(RealtimeError::new(
                    "realtime.program_not_running",
                    "music program is not running",
                ));
            }
            *self.supervision_deadline.lock().map_err(|_| {
                RealtimeError::new(
                    "realtime.supervision_unavailable",
                    "supervision state is poisoned",
                )
            })? = Some(Instant::now() + lease);
            Ok(())
        }

        pub fn is_finished(&self) -> bool {
            self.thread.as_ref().is_none_or(JoinHandle::is_finished)
        }

        pub fn held_action_ids(&self) -> Result<Vec<String>, RealtimeError> {
            self.held_action_ids
                .lock()
                .map(|held| held.iter().cloned().collect())
                .map_err(|_| {
                    RealtimeError::new(
                        "realtime.input_state_unavailable",
                        "realtime input state mirror is poisoned",
                    )
                })
        }

        pub fn stop(mut self) -> MusicProgramResult {
            self.stop.store(true, Ordering::Release);
            self.join()
        }

        pub fn join(&mut self) -> MusicProgramResult {
            let Some(thread) = self.thread.take() else {
                return MusicProgramResult {
                    metrics: RealtimeMetrics::default(),
                    error: Some(RealtimeError::new(
                        "realtime.join_invalid",
                        "music program was already joined",
                    )),
                    release_uncertain: false,
                };
            };
            thread.join().unwrap_or_else(|_| MusicProgramResult {
                metrics: RealtimeMetrics::default(),
                error: Some(RealtimeError::new(
                    "realtime.worker_panicked",
                    "music program worker panicked",
                )),
                release_uncertain: true,
            })
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_genshin_music(
        hwnd: usize,
        spec: crate::spec::RealtimeProgramSpec,
        keys: Vec<PhysicalKey>,
        points: [(i32, i32); 6],
        client_size: (u32, u32),
        maximum_duration: Duration,
        supervision_deadline: Arc<Mutex<Option<Instant>>>,
        stop: Arc<AtomicBool>,
        held_action_ids: Arc<Mutex<BTreeSet<String>>>,
        ready: mpsc::SyncSender<Result<(), RealtimeError>>,
    ) -> MusicProgramResult {
        let hwnd_value = hwnd;
        let hwnd = HWND(hwnd_value as *mut std::ffi::c_void);
        let (sender, receiver) = mpsc::sync_channel(spec.safety.maximum_queue_depth as usize);
        let sampler_error = Arc::new(Mutex::new(None));
        let sampler = std::thread::spawn({
            let sampler_stop = Arc::clone(&stop);
            let sampler_first_error = Arc::clone(&sampler_error);
            let lanes = spec.lanes.clone();
            let interval = Duration::from_micros(u64::from(spec.sample_interval_us));
            move || {
                let probe = match GdiPixelRowProbe::new(
                    HWND(hwnd_value as *mut std::ffi::c_void),
                    &points,
                    client_size,
                ) {
                    Ok(probe) => probe,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        sampler_stop.store(true, Ordering::Release);
                        return SamplerMetrics::default();
                    }
                };
                if ready.send(Ok(())).is_err() {
                    sampler_stop.store(true, Ordering::Release);
                    return SamplerMetrics::default();
                }
                row_loop(
                    probe,
                    lanes,
                    interval,
                    sender,
                    sampler_first_error,
                    sampler_stop,
                )
            }
        });

        let started = Instant::now();
        let maximum_deadline = started + maximum_duration;
        let freshness = Duration::from_micros(u64::from(spec.event_freshness_us));
        let mut metrics = RealtimeMetrics::default();
        let monitor = WindowsLocalInputMonitor::start();
        let mut input = WindowsPhysicalInputBatch::new(keys.clone());
        let mut first_error = monitor
            .as_ref()
            .err()
            .cloned()
            .or_else(|| input.as_ref().err().cloned());
        let mut next_target_check = started;
        while first_error.is_none() && !stop.load(Ordering::Acquire) {
            let now = Instant::now();
            if now >= maximum_deadline {
                break;
            }
            if supervision_deadline
                .lock()
                .ok()
                .and_then(|value| *value)
                .is_some_and(|deadline| now >= deadline)
            {
                first_error = Some(RealtimeError::new(
                    "realtime.supervision_expired",
                    "realtime supervision lease expired",
                ));
                break;
            }
            if now >= next_target_check {
                if let Err(error) = validate_target_size(hwnd, &spec) {
                    first_error = Some(error);
                    break;
                }
                next_target_check =
                    now + Duration::from_millis(u64::from(spec.safety.target_revalidate_ms));
            }
            if let Ok(monitor) = &monitor {
                if let Err(error) = monitor.check() {
                    first_error = Some(error);
                    break;
                }
            }
            let first = match receiver.recv_timeout(Duration::from_millis(1)) {
                Ok(value) => value,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let mut detected = vec![first];
            while let Ok(value) = receiver.try_recv() {
                detected.push(value);
            }
            let send_at = Instant::now();
            detected.retain(|value| {
                let fresh = send_at.saturating_duration_since(value.detected_at) < freshness;
                if !fresh {
                    metrics.stale_events += 1;
                }
                fresh
            });
            if detected.is_empty() {
                continue;
            }
            if detected.len() > 1 {
                let first = detected
                    .iter()
                    .map(|value| value.detected_at)
                    .min()
                    .unwrap();
                let last = detected
                    .iter()
                    .map(|value| value.detected_at)
                    .max()
                    .unwrap();
                metrics
                    .chord_skew_us
                    .push(last.saturating_duration_since(first).as_micros() as u64);
            }
            detected.sort_by_key(|value| value.lane);
            let transitions = detected
                .iter()
                .map(|value| {
                    lane_key(&spec, value, &keys).map(|key| KeyTransition {
                        key,
                        pressed: value.pressed,
                    })
                })
                .collect::<Result<Vec<_>, _>>();
            let transitions = match transitions {
                Ok(value) => value,
                Err(error) => {
                    first_error = Some(error);
                    break;
                }
            };
            if let Err(error) = input.as_mut().unwrap().apply(&transitions) {
                first_error = Some(error);
                break;
            }
            let state_update = held_action_ids.lock().map(|mut held| {
                for transition in &transitions {
                    if transition.pressed {
                        held.insert(transition.key.action_id.clone());
                    } else {
                        held.remove(&transition.key.action_id);
                    }
                }
            });
            if state_update.is_err() {
                first_error = Some(RealtimeError::new(
                    "realtime.input_state_unavailable",
                    "realtime input state mirror is poisoned",
                ));
                break;
            }
            let applied_at = Instant::now();
            metrics.transition_count += transitions.len() as u64;
            metrics
                .detection_to_input_us
                .extend(detected.iter().map(|value| {
                    applied_at
                        .saturating_duration_since(value.detected_at)
                        .as_micros() as u64
                }));
        }
        stop.store(true, Ordering::Release);
        match sampler.join() {
            Ok(sampler) => {
                metrics.sample_count += sampler.samples;
                metrics.missed_deadlines += sampler.missed_deadlines;
                metrics.queue_overflows += sampler.queue_overflows;
                metrics
                    .sample_intervals_us
                    .extend(sampler.sample_intervals_us);
                metrics
                    .scheduler_lateness_us
                    .extend(sampler.scheduler_lateness_us);
            }
            Err(_) if first_error.is_none() => {
                first_error = Some(RealtimeError::new(
                    "realtime.sampler_panicked",
                    "realtime row sampler panicked",
                ));
            }
            Err(_) => {}
        }
        if first_error.is_none() {
            first_error = sampler_error.lock().ok().and_then(|mut value| value.take());
        }
        let release = input.as_mut().ok().map(PhysicalInputBatch::release_all);
        let release_uncertain = release.as_ref().is_some_and(|result| result.is_err());
        if !release_uncertain {
            if let Ok(mut held) = held_action_ids.lock() {
                held.clear();
            }
        }
        if first_error.is_none() {
            first_error = release.and_then(Result::err);
        }
        MusicProgramResult {
            metrics,
            error: first_error,
            release_uncertain,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn row_loop(
        probe: GdiPixelRowProbe<6>,
        lanes: Vec<crate::spec::LaneSpec>,
        interval: Duration,
        sender: mpsc::SyncSender<DetectedTransition>,
        first_error: Arc<Mutex<Option<RealtimeError>>>,
        stop: Arc<AtomicBool>,
    ) -> SamplerMetrics {
        let mut state = [LaneState::default(); 6];
        let mut deadline = Instant::now();
        let mut previous = deadline;
        let mut metrics = SamplerMetrics::default();
        while !stop.load(Ordering::Acquire) {
            let lateness = wait_until(deadline);
            let now = Instant::now();
            metrics
                .sample_intervals_us
                .push(now.saturating_duration_since(previous).as_micros() as u64);
            metrics
                .scheduler_lateness_us
                .push(lateness.as_micros() as u64);
            previous = now;
            if lateness > interval {
                metrics.missed_deadlines += 1;
                deadline = now;
            }
            let mut send_failed = false;
            match probe.sample_blue() {
                Ok(blue) => {
                    metrics.samples += 1;
                    for (lane, ((state, blue), lane_spec)) in
                        state.iter_mut().zip(blue).zip(lanes.iter()).enumerate()
                    {
                        if let Some(pressed) = state.observe(
                            blue,
                            lane_spec.press_below,
                            lane_spec.release_at_or_above,
                        ) {
                            if let Err(error) = sender.try_send(DetectedTransition {
                                lane,
                                pressed,
                                detected_at: now,
                            }) {
                                if matches!(error, mpsc::TrySendError::Full(_)) {
                                    metrics.queue_overflows += 1;
                                    record_error(
                                        &first_error,
                                        RealtimeError::new(
                                            "realtime.queue_overflow",
                                            "realtime transition queue overflowed",
                                        ),
                                    );
                                }
                                stop.store(true, Ordering::Release);
                                send_failed = true;
                                break;
                            }
                        }
                    }
                }
                Err(error) => {
                    record_error(&first_error, error);
                    stop.store(true, Ordering::Release);
                    break;
                }
            }
            if send_failed {
                break;
            }
            deadline += interval;
        }
        if let Err(error) = probe.close() {
            record_error(&first_error, error);
        }
        metrics
    }

    fn lane_key(
        spec: &crate::spec::RealtimeProgramSpec,
        transition: &DetectedTransition,
        keys: &[PhysicalKey],
    ) -> Result<PhysicalKey, RealtimeError> {
        let action_id = &spec.lanes[transition.lane].action_id;
        keys.iter()
            .find(|key| &key.action_id == action_id)
            .cloned()
            .ok_or_else(|| {
                RealtimeError::new(
                    "realtime.input_profile_invalid",
                    "lane key disappeared from the installed map",
                )
            })
    }

    fn record_error(slot: &Mutex<Option<RealtimeError>>, error: RealtimeError) {
        if let Ok(mut slot) = slot.lock() {
            slot.get_or_insert(error);
        }
    }

    fn validate_target(hwnd: HWND, spec: &VerifiedRealtimeSpec) -> Result<(), RealtimeError> {
        validate_target_size(hwnd, spec.spec())
    }

    fn validate_target_size(
        hwnd: HWND,
        spec: &crate::spec::RealtimeProgramSpec,
    ) -> Result<(), RealtimeError> {
        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() || unsafe { GetForegroundWindow() } != hwnd {
            return Err(RealtimeError::new(
                "realtime.target_invalid",
                "realtime target is invalid or not foreground",
            ));
        }
        let mut rect = RECT::default();
        unsafe { GetClientRect(hwnd, &mut rect) }
            .map_err(|error| RealtimeError::new("realtime.target_invalid", error.to_string()))?;
        if u32::try_from(rect.right - rect.left).ok() != Some(spec.required_client_size.width)
            || u32::try_from(rect.bottom - rect.top).ok() != Some(spec.required_client_size.height)
        {
            return Err(RealtimeError::new(
                "realtime.target_size_changed",
                "realtime target does not match required client size",
            ));
        }
        Ok(())
    }

    fn ppm(value: u32, extent: u32) -> Result<i32, RealtimeError> {
        if value > 1_000_000 || extent == 0 {
            return Err(RealtimeError::new(
                "realtime.spec_invalid",
                "lane coordinate is invalid",
            ));
        }
        i32::try_from((u64::from(extent - 1) * u64::from(value) + 500_000) / 1_000_000)
            .map_err(|_| RealtimeError::new("realtime.spec_invalid", "coordinate overflow"))
    }
}
