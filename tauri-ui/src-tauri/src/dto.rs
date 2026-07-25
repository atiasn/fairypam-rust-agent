use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusDto {
    pub state: String,
    pub capture_active: bool,
    pub build_id: String,
    pub suite_version: String,
    pub guardian_state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorDto {
    pub profiles: Vec<String>,
    pub runtime: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportStatusDto {
    pub status: String,
}

/// RegisterHub is intentionally asynchronous: the local Pipe only accepts
/// the request while the elevated Agent completes the direct claim.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationStatusDto {
    pub status: RegistrationPendingStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RegistrationPendingStatus {
    #[serde(rename = "pending")]
    Pending,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionStatusDto {
    pub control: String,
    pub frame: String,
    pub capture_active: bool,
    pub recovery_code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentCheckItemDto {
    pub id: String,
    pub status: String,
    pub code: String,
    pub recovery: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentCheckDto {
    pub registration_ready: bool,
    pub registration_pending: bool,
    pub checks: Vec<EnvironmentCheckItemDto>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntryDto {
    pub level: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogTailDto {
    pub entries: Vec<LogEntryDto>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledGameDto {
    pub discovery_id: String,
    pub name: String,
    pub version: Option<String>,
    pub installed: bool,
    pub supported: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledGamesDto {
    pub games: Vec<InstalledGameDto>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewDto {
    pub status: StatusDto,
    pub doctor: DoctorDto,
}
