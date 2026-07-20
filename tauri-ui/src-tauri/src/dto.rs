use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusDto {
    pub state: String,
    pub capture_active: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorDto {
    pub profiles: Vec<String>,
    pub runtime: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilesDto {
    pub profiles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCandidateDto {
    pub candidate_id: String,
    pub pid: u32,
    pub process_path_sha256: String,
    pub window_class: String,
    pub title: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetsDto {
    pub candidates: Vec<TargetCandidateDto>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedTargetDto {
    pub profile_id: String,
    pub pid: u32,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FocusedTargetDto {
    pub profile_id: String,
    pub foreground: bool,
    pub minimized: bool,
    pub capturable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureStateDto {
    pub capture_source_id: String,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAllDto {
    pub state: String,
    pub holds: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportStatusDto {
    pub status: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewDto {
    pub status: StatusDto,
    pub doctor: DoctorDto,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResultDto {
    pub saved: bool,
    pub reason_code: Option<String>,
}
