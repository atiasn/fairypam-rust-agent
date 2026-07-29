#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureEncoding {
    Jpeg { quality: u8 },
    Png,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputProbeAction {
    MoveForward,
    QuickUse,
    MouseLeft,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeCommand {
    Status,
    Doctor,
    ListProfiles,
    EnumerateTargets {
        profile_id: String,
    },
    LockTarget {
        profile_id: String,
        candidate_id: String,
    },
    FocusTarget,
    StartCapture {
        source_id: String,
        fps: u8,
        encoding: CaptureEncoding,
    },
    StopCapture {
        source_id: String,
    },
    ReleaseAll,
    ResetEmergencyStop,
    UpdateStatus,
    StartupStatus,
    GetConnectionStatus,
    RunEnvironmentCheck,
    GetLogTail {
        lines: u16,
        level: LogLevel,
    },
    ScanInstalledGames,
    LaunchTarget {
        profile_id: String,
    },
    CloseTarget,
    CapturePreview,
    InputProbe {
        action: InputProbeAction,
    },
    ShutdownAgent,
    RegisterHub {
        hub_address: String,
        registration_code: String,
    },
}
