use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub http: Option<HttpConfig>,
    #[serde(default)]
    pub certificates: Option<CertificateConfig>,
    pub auth: AuthConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub realm: String,
    pub external_ip: String,
    #[serde(default)]
    pub relay_bind_ip: Option<String>,
    pub start_port: u16,
    pub end_port: u16,
    pub listening: Vec<ListenConfig>,
    pub max_concurrent_allocations: Option<usize>,
    pub max_bandwidth_bytes_per_sec: Option<u64>,
    pub max_allocation_duration_secs: Option<u32>,
    #[serde(default = "ServerConfig::default_stats_dump_interval_secs")]
    pub stats_dump_interval_secs: u64,
    #[serde(default = "ServerConfig::default_stats_dump_skip_if_no_change")]
    pub stats_dump_skip_if_no_change: bool,
    #[serde(default = "ServerConfig::default_server_name")]
    pub server_name: String,
    #[serde(default = "ServerConfig::default_stun_enabled")]
    pub stun_enabled: bool,
    #[serde(default = "ServerConfig::default_turn_enabled")]
    pub turn_enabled: bool,
}

impl ServerConfig {
    fn default_stats_dump_interval_secs() -> u64 {
        30
    }

    fn default_stats_dump_skip_if_no_change() -> bool {
        true
    }

    fn default_server_name() -> String {
        format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
    }

    fn default_stun_enabled() -> bool {
        true
    }

    fn default_turn_enabled() -> bool {
        true
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ListenConfig {
    pub protocol: String,
    pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HttpConfig {
    pub address: String,
    /// Enable TURN REST API for WebRTC credential generation
    pub turn_rest_enabled: Option<bool>,
    /// Secret key for TURN REST API HMAC authentication
    pub turn_rest_secret: Option<String>,
    /// Default lifetime for TURN REST credentials in seconds
    pub turn_rest_default_lifetime: Option<u64>,
    /// Admin console username (separate from auth.users)
    pub admin_username: Option<String>,
    /// Admin console password
    pub admin_password: Option<String>,
    /// Admin console ACL: list of allowed IPs/CIDRs (default: ["127.0.0.1"])
    #[serde(default = "HttpConfig::default_admin_acl")]
    pub admin_acl: Vec<String>,
    /// Trust X-Forwarded-For and X-Real-IP headers for admin ACL IP detection
    #[serde(default = "HttpConfig::default_trust_proxy")]
    pub trust_proxy: Option<bool>,
}

impl HttpConfig {
    fn default_admin_acl() -> Vec<String> {
        vec!["127.0.0.1".to_string()]
    }
    fn default_trust_proxy() -> Option<bool> {
        Some(false)
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8080".to_string(),
            turn_rest_enabled: Some(false),
            turn_rest_secret: None,
            turn_rest_default_lifetime: Some(3600),
            admin_username: None,
            admin_password: None,
            admin_acl: Self::default_admin_acl(),
            trust_proxy: Self::default_trust_proxy(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CertificateConfig {
    /// "local", "letsencrypt", or "sds"
    pub source: String,
    /// PEM certificate chain path for source="local"
    pub cert_path: Option<String>,
    /// PEM private key path for source="local"
    pub key_path: Option<String>,
    /// Domains/SANs for source="letsencrypt"
    #[serde(default)]
    pub domains: Vec<String>,
    /// Optional account contact email for Let's Encrypt
    pub email: Option<String>,
    /// "production" or "staging" for source="letsencrypt"
    pub environment: Option<String>,
    /// Cache directory for ACME account, certificate chain, and private key
    pub cache_dir: Option<String>,
    /// Address for temporary HTTP-01 challenge server, usually "0.0.0.0:80"
    pub http01_address: Option<String>,
    /// Renew cached certificate when it expires within this many days
    pub renew_before_days: Option<u64>,
    /// SDS/xDS gRPC endpoint for source="sds", e.g. "http://127.0.0.1:18000"
    pub sds_address: Option<String>,
    /// xDS stream API for source="sds": "ads", "sds", "delta_ads", or "delta_sds"
    pub sds_api: Option<String>,
    /// SDS resource name to subscribe for source="sds"
    pub sds_resource_name: Option<String>,
    /// Envoy Node id sent in SDS requests; empty or omitted uses the host name
    pub sds_node_id: Option<String>,
    /// Optional Envoy Node cluster sent in the SDS DiscoveryRequest
    pub sds_cluster: Option<String>,
    /// Timeout in seconds while waiting for the first SDS response
    pub sds_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogConfig {
    pub log_file: Option<String>,
    #[serde(default = "LogConfig::default_level")]
    pub log_level: String,
}

impl LogConfig {
    fn default_level() -> String {
        "info".to_string()
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_file: None,
            log_level: Self::default_level(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthConfig {
    #[serde(default)]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub api_keys: HashMap<String, String>,
    #[serde(default)]
    pub acl_rules: Vec<AclRuleConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
    pub user_type: String,
    pub expires_at: Option<u64>,
    pub max_allocations: Option<usize>,
    pub bandwidth_limit: Option<u64>,
    pub ip_whitelist: Option<Vec<String>>,
    pub max_allocation_duration_secs: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AclRuleConfig {
    pub ip_range: String,
    pub action: String,
    pub priority: Option<u32>,
}

impl Config {
    pub fn load(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig {
                realm: "miuturn".to_string(),
                external_ip: "0.0.0.0".to_string(),
                relay_bind_ip: None,
                start_port: 49152,
                end_port: 65535,
                listening: vec![
                    ListenConfig {
                        protocol: "udp".to_string(),
                        address: "0.0.0.0:3478".to_string(),
                    },
                    ListenConfig {
                        protocol: "tcp".to_string(),
                        address: "0.0.0.0:3478".to_string(),
                    },
                ],
                max_concurrent_allocations: None,
                max_bandwidth_bytes_per_sec: None,
                max_allocation_duration_secs: None,
                stats_dump_interval_secs: 30,
                stats_dump_skip_if_no_change: true,
                server_name: ServerConfig::default_server_name(),
                stun_enabled: true,
                turn_enabled: true,
            },
            http: None,
            certificates: None,
            log: LogConfig::default(),
            auth: AuthConfig {
                users: vec![],
                api_keys: HashMap::new(),
                acl_rules: vec![AclRuleConfig {
                    ip_range: "0.0.0.0/0".to_string(),
                    action: "Allow".to_string(),
                    priority: Some(0),
                }],
            },
        }
    }
}

impl ListenConfig {
    pub fn addr(&self) -> SocketAddr {
        self.address.parse().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.server.realm, "miuturn");
        assert_eq!(config.server.external_ip, "0.0.0.0");
        assert_eq!(config.server.relay_bind_ip, None);
        assert_eq!(config.server.start_port, 49152);
        assert_eq!(config.server.end_port, 65535);
        assert!(config.server.max_concurrent_allocations.is_none());
        assert!(config.server.stun_enabled);
        assert!(config.server.turn_enabled);
    }

    #[test]
    fn test_http_config_default() {
        let http = HttpConfig::default();
        assert_eq!(http.address, "0.0.0.0:8080");
        assert_eq!(http.turn_rest_enabled, Some(false));
        assert_eq!(http.turn_rest_default_lifetime, Some(3600));
        assert!(http.turn_rest_secret.is_none());
    }

    #[test]
    fn test_config_toml_roundtrip() {
        let config = Config::default();
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.server.realm, config.server.realm);
        assert_eq!(deserialized.server.external_ip, config.server.external_ip);
    }

    #[test]
    fn test_config_with_turn_rest() {
        let toml_content = r#"
[server]
realm = "test-realm"
external_ip = "192.168.1.1"
relay_bind_ip = "0.0.0.0"
start_port = 49152
end_port = 65535
max_concurrent_allocations = 100
max_allocation_duration_secs = 600
stun_enabled = false
turn_enabled = true

[[server.listening]]
protocol = "udp"
address = "0.0.0.0:3478"

[[server.listening]]
protocol = "tcp"
address = "0.0.0.0:3478"

[http]
address = "0.0.0.0:8080"
turn_rest_enabled = true
turn_rest_secret = "my-secret-key"
turn_rest_default_lifetime = 7200

[auth]
users = []

[auth.api_keys]
key1 = "user1"

[[auth.acl_rules]]
ip_range = "0.0.0.0/0"
action = "Allow"
priority = 0
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.server.realm, "test-realm");
        assert_eq!(config.server.external_ip, "192.168.1.1");
        assert_eq!(config.server.relay_bind_ip.as_deref(), Some("0.0.0.0"));
        assert!(!config.server.stun_enabled);
        assert!(config.server.turn_enabled);
        assert_eq!(config.http.as_ref().unwrap().turn_rest_enabled, Some(true));
        assert_eq!(
            config.http.as_ref().unwrap().turn_rest_secret,
            Some("my-secret-key".to_string())
        );
        assert_eq!(
            config.http.as_ref().unwrap().turn_rest_default_lifetime,
            Some(7200)
        );
        assert_eq!(config.auth.api_keys.get("key1"), Some(&"user1".to_string()));
    }

    #[test]
    fn test_listen_config_addr() {
        let config = ListenConfig {
            protocol: "udp".to_string(),
            address: "192.168.1.1:3478".to_string(),
        };
        let addr = config.addr();
        assert_eq!(addr.port(), 3478);
    }

    #[test]
    fn test_certificate_config_letsencrypt() {
        let toml_content = r#"
[server]
realm = "test-realm"
external_ip = "192.168.1.1"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "tls"
address = "0.0.0.0:5349"

[certificates]
source = "letsencrypt"
environment = "staging"
domains = ["turn.example.com"]
email = "admin@example.com"
http01_address = "0.0.0.0:80"
cache_dir = "./cert-cache"
renew_before_days = 30

[auth]
users = []
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        let certs = config.certificates.unwrap();
        assert_eq!(certs.source, "letsencrypt");
        assert_eq!(certs.environment.as_deref(), Some("staging"));
        assert_eq!(certs.domains, vec!["turn.example.com".to_string()]);
        assert_eq!(certs.renew_before_days, Some(30));
    }

    #[test]
    fn test_certificate_config_sds() {
        let toml_content = r#"
[server]
realm = "test-realm"
external_ip = "192.168.1.1"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "dtls"
address = "0.0.0.0:5349"

[certificates]
source = "sds"
sds_address = "http://127.0.0.1:18000"
sds_api = "ads"
sds_resource_name = "turn-cert"
sds_node_id = "miuturn"
sds_cluster = "turn"
sds_timeout_secs = 5
cache_dir = "./cert-cache"

[auth]
users = []
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        let certs = config.certificates.unwrap();
        assert_eq!(certs.source, "sds");
        assert_eq!(certs.sds_address.as_deref(), Some("http://127.0.0.1:18000"));
        assert_eq!(certs.sds_api.as_deref(), Some("ads"));
        assert_eq!(certs.sds_resource_name.as_deref(), Some("turn-cert"));
        assert_eq!(certs.sds_node_id.as_deref(), Some("miuturn"));
        assert_eq!(certs.sds_cluster.as_deref(), Some("turn"));
        assert_eq!(certs.sds_timeout_secs, Some(5));
    }

    #[test]
    fn test_user_config() {
        let user = UserConfig {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            user_type: "fixed".to_string(),
            expires_at: Some(9999999999),
            max_allocations: Some(5),
            bandwidth_limit: Some(1000000),
            ip_whitelist: None,
            max_allocation_duration_secs: Some(600),
        };
        assert_eq!(user.username, "testuser");
        assert_eq!(user.user_type, "fixed");
        assert!(user.expires_at.is_some());
    }

    #[test]
    fn test_acl_rule_config() {
        let rule = AclRuleConfig {
            ip_range: "10.0.0.0/8".to_string(),
            action: "Allow".to_string(),
            priority: Some(10),
        };
        assert_eq!(rule.ip_range, "10.0.0.0/8");
        assert_eq!(rule.action, "Allow");
        assert_eq!(rule.priority, Some(10));
    }

    #[test]
    fn test_config_toml_with_full_user_config() {
        let toml_content = r#"
[server]
realm = "test-realm"
external_ip = "192.168.1.1"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "udp"
address = "0.0.0.0:3478"

[http]
address = "0.0.0.0:8080"

[[auth.users]]
username = "fulluser"
password = "secret"
user_type = "fixed"
max_allocations = 5
bandwidth_limit = 1048576
max_allocation_duration_secs = 600
ip_whitelist = ["192.168.1.0/24", "10.0.0.1"]

[auth.api_keys]

[[auth.acl_rules]]
ip_range = "0.0.0.0/0"
action = "Allow"
priority = 0
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.auth.users.len(), 1);
        let user = &config.auth.users[0];
        assert_eq!(user.username, "fulluser");
        assert_eq!(user.bandwidth_limit, Some(1048576));
        assert_eq!(user.max_allocation_duration_secs, Some(600));
        assert_eq!(user.ip_whitelist.as_ref().unwrap().len(), 2);
        assert!(
            user.ip_whitelist
                .as_ref()
                .unwrap()
                .contains(&"192.168.1.0/24".to_string())
        );
    }

    #[test]
    fn test_user_config_with_minimal_fields() {
        let user = UserConfig {
            username: "minimal".to_string(),
            password: "pass".to_string(),
            user_type: "temporary".to_string(),
            expires_at: None,
            max_allocations: None,
            bandwidth_limit: None,
            ip_whitelist: None,
            max_allocation_duration_secs: None,
        };
        assert_eq!(user.username, "minimal");
        assert!(user.bandwidth_limit.is_none());
        assert!(user.ip_whitelist.is_none());
        assert!(user.max_allocation_duration_secs.is_none());
    }

    #[test]
    fn test_user_config_serialize_to_toml() {
        let user = UserConfig {
            username: "test".to_string(),
            password: "pass".to_string(),
            user_type: "fixed".to_string(),
            expires_at: Some(1234567890),
            max_allocations: Some(10),
            bandwidth_limit: Some(2097152),
            ip_whitelist: Some(vec!["192.168.0.0/16".to_string()]),
            max_allocation_duration_secs: Some(1800),
        };
        let toml = toml::to_string(&user).unwrap();
        assert!(toml.contains("bandwidth_limit = 2097152"));
        assert!(toml.contains("max_allocation_duration_secs = 1800"));
        assert!(toml.contains("\"192.168.0.0/16\""));
    }

    #[test]
    fn test_user_config_empty_ip_whitelist() {
        let toml_content = r#"
username = "nowhitelist"
password = "pass"
user_type = "fixed"
ip_whitelist = []
"#;
        let user: UserConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(user.ip_whitelist.as_ref().unwrap().len(), 0);
    }
}
