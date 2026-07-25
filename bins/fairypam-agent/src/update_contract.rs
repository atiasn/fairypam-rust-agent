use fairypam_agent_core::AgentError;
use http::Uri;

const MAX_ARTIFACT_URL_LENGTH: usize = 2048;

pub(crate) fn artifact_uri(url: &str, agent_id: &str, update_id: &str) -> Result<Uri, AgentError> {
    let uri = url.parse::<Uri>().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    let expected_path = format!("/api/v1/agents/{agent_id}/updates/{update_id}/artifact");
    if url.len() > MAX_ARTIFACT_URL_LENGTH
        || uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || authority.host().is_empty()
        || uri.path_and_query().map(|value| value.as_str()) != Some(expected_path.as_str())
    {
        return Err(invalid());
    }
    Ok(uri)
}

fn invalid() -> AgentError {
    AgentError::new("update.invalid", "update directive or artifact is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT_ID: &str = "76e99453-7395-43aa-8b33-4988f5e8ce0a";
    const UPDATE_ID: &str = "2e10397f-53ce-454c-915b-8a0f4a3548aa";

    #[test]
    fn accepts_only_exact_https_artifact_url() {
        let expected =
            "https://updates.example.test:8443/api/v1/agents/76e99453-7395-43aa-8b33-4988f5e8ce0a/updates/2e10397f-53ce-454c-915b-8a0f4a3548aa/artifact";
        assert_eq!(
            artifact_uri(expected, AGENT_ID, UPDATE_ID)
                .unwrap()
                .to_string(),
            expected
        );
        for invalid in [
            expected.replacen("https://", "http://", 1),
            format!("{expected}?redirect=https://evil.example"),
            expected.replace(AGENT_ID, "wrong-agent"),
            expected.replace(UPDATE_ID, "wrong-update"),
            expected.replacen("updates.example.test", "user@updates.example.test", 1),
        ] {
            assert!(artifact_uri(&invalid, AGENT_ID, UPDATE_ID).is_err());
        }
    }
}
