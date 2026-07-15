//! TLS certificate loading and ACME provisioning for TURN over TLS.

use crate::config::CertificateConfig;
use crate::sds::{SdsCertificate, fetch_sds_certificate, watch_sds_certificates};
use axum::{
    Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use dtls::config::Config as DtlsConfig;
use dtls::crypto::Certificate as DtlsCertificate;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use p256::SecretKey as P256SecretKey;
use p256::pkcs8::EncodePrivateKey;
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, oneshot};
use x509_parser::prelude::parse_x509_certificate;

type ChallengeStore = Arc<RwLock<HashMap<String, String>>>;

const DEFAULT_CACHE_DIR: &str = "./cert-cache";
const DEFAULT_HTTP01_ADDRESS: &str = "0.0.0.0:80";
const DEFAULT_RENEW_BEFORE_DAYS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateKeyKind {
    Pkcs1,
    Pkcs8,
    Sec1,
}

/// TLS configuration for TURN server.
#[derive(Clone)]
pub struct TlsConfig {
    /// DER-encoded leaf certificate for backwards-compatible callers.
    pub cert_der: Vec<u8>,
    /// DER-encoded certificate chain, leaf first.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// DER-encoded private key.
    pub key_der: Vec<u8>,
    key_kind: PrivateKeyKind,
}

impl TlsConfig {
    /// Load TLS configuration from PEM files.
    pub fn from_files(
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert_data = fs::read(cert_path)?;
        let key_data = fs::read(key_path)?;
        Self::from_pem(&cert_data, &key_data)
    }

    /// Load TLS configuration from PEM bytes.
    pub fn from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert_chain_der = parse_certificate_chain(cert_pem)?;
        let (key_der, key_kind) = parse_private_key(key_pem)?;
        let cert_der = cert_chain_der
            .first()
            .ok_or("certificate chain is empty")?
            .clone();

        Ok(Self {
            cert_der,
            cert_chain_der,
            key_der,
            key_kind,
        })
    }

    /// Generate self-signed certificate for testing.
    pub fn generate_self_signed(
        domain: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert = generate_simple_self_signed([domain.to_string()])?;

        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        Ok(Self {
            cert_der: cert_der.clone(),
            cert_chain_der: vec![cert_der],
            key_der,
            key_kind: PrivateKeyKind::Pkcs8,
        })
    }

    /// Create Rustls ServerConfig.
    pub fn into_server_config(
        self,
    ) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        ensure_rustls_crypto_provider();
        let key = self.private_key_der();
        let certs = self
            .cert_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect::<Vec<_>>();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(Arc::new(config))
    }

    fn into_certified_key(
        self,
    ) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error + Send + Sync>> {
        ensure_rustls_crypto_provider();
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let key = self.private_key_der();
        let certs = self
            .cert_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect::<Vec<_>>();
        Ok(Arc::new(CertifiedKey::from_der(certs, key, &provider)?))
    }

    fn private_key_der(&self) -> PrivateKeyDer<'static> {
        match self.key_kind {
            PrivateKeyKind::Pkcs1 => {
                PrivateKeyDer::from(PrivatePkcs1KeyDer::from(self.key_der.clone()))
            }
            PrivateKeyKind::Pkcs8 => {
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.key_der.clone()))
            }
            PrivateKeyKind::Sec1 => {
                PrivateKeyDer::from(PrivateSec1KeyDer::from(self.key_der.clone()))
            }
        }
    }
}

struct DynamicCertResolver {
    certified_key: parking_lot::RwLock<Arc<CertifiedKey>>,
}

impl DynamicCertResolver {
    fn new(certified_key: Arc<CertifiedKey>) -> Self {
        Self {
            certified_key: parking_lot::RwLock::new(certified_key),
        }
    }

    fn update_from_pem(
        &self,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let certified_key =
            TlsConfig::from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?.into_certified_key()?;
        *self.certified_key.write() = certified_key;
        Ok(())
    }
}

impl fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.read().clone())
    }
}

/// Install the process-wide rustls crypto provider used by TLS and DTLS.
pub fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Load local certificates or obtain/cache Let's Encrypt certificates.
pub async fn load_certificate_config(
    config: &CertificateConfig,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    if config.source == "sds" {
        return load_dynamic_sds_certificate_config(config).await;
    }

    let (cert_pem, key_pem) = load_certificate_pem(config).await?;
    TlsConfig::from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?.into_server_config()
}

/// Load local certificates or obtain/cache Let's Encrypt certificates for DTLS.
pub async fn load_dtls_certificate_config(
    config: &CertificateConfig,
) -> Result<DtlsConfig, Box<dyn std::error::Error + Send + Sync>> {
    ensure_rustls_crypto_provider();
    let (cert_pem, key_pem) = load_certificate_pem(config).await?;
    if config.source == "sds" {
        start_sds_cache_watcher(config.clone())?;
    }
    let certificate = dtls_certificate_from_pem(&cert_pem, &key_pem)?;

    Ok(DtlsConfig {
        certificates: vec![certificate],
        ..Default::default()
    })
}

async fn load_dynamic_sds_certificate_config(
    config: &CertificateConfig,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_pem, key_pem) = load_sds_certificate(config).await?;
    let certified_key =
        TlsConfig::from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?.into_certified_key()?;
    let resolver = Arc::new(DynamicCertResolver::new(certified_key));
    start_sds_tls_watcher(config.clone(), resolver.clone())?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    Ok(Arc::new(config))
}

async fn load_certificate_pem(
    config: &CertificateConfig,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    match config.source.as_str() {
        "local" => {
            let cert_path = config
                .cert_path
                .as_deref()
                .ok_or("certificates.cert_path is required for source=\"local\"")?;
            let key_path = config
                .key_path
                .as_deref()
                .ok_or("certificates.key_path is required for source=\"local\"")?;
            let cert_pem = String::from_utf8(fs::read(Path::new(cert_path))?)?;
            let key_pem = String::from_utf8(fs::read(Path::new(key_path))?)?;
            Ok((cert_pem, key_pem))
        }
        "letsencrypt" => provision_letsencrypt(config).await,
        "sds" => load_sds_certificate(config).await,
        other => Err(format!(
            "unsupported certificates.source \"{}\"; expected \"local\", \"letsencrypt\", or \"sds\"",
            other
        )
        .into()),
    }
}

/// Create a default TLS config for testing.
pub fn default_test_tls_config() -> Result<TlsConfig, Box<dyn std::error::Error + Send + Sync>> {
    TlsConfig::generate_self_signed("localhost")
}

fn parse_certificate_chain(
    cert_pem: &[u8],
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let certs = pem::parse_many(cert_pem)?
        .into_iter()
        .filter(|pem| pem.tag() == "CERTIFICATE")
        .map(|pem| pem.into_contents())
        .collect::<Vec<_>>();

    if certs.is_empty() {
        return Err("no CERTIFICATE blocks found in certificate PEM".into());
    }

    Ok(certs)
}

fn parse_private_key(
    key_pem: &[u8],
) -> Result<(Vec<u8>, PrivateKeyKind), Box<dyn std::error::Error + Send + Sync>> {
    let mut errors = Vec::new();

    for block in pem::parse_many(key_pem)? {
        let tag = block.tag().to_string();
        let der = block.into_contents();

        match PrivateKeyDer::try_from(der.clone()) {
            Ok(key) => {
                let kind = match key {
                    PrivateKeyDer::Pkcs1(_) => PrivateKeyKind::Pkcs1,
                    PrivateKeyDer::Pkcs8(_) => PrivateKeyKind::Pkcs8,
                    PrivateKeyDer::Sec1(_) => PrivateKeyKind::Sec1,
                    _ => unreachable!("rustls-pki-types private key variants are exhaustive"),
                };
                return Ok((der, kind));
            }
            Err(err) => errors.push(format!("{}: {}", tag, err)),
        }
    }

    Err(format!(
        "no supported private key block found in key PEM; tried DER auto-detection ({})",
        errors.join("; ")
    )
    .into())
}

fn dtls_certificate_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<DtlsCertificate, Box<dyn std::error::Error + Send + Sync>> {
    let key_pem = normalize_dtls_private_key_pem(key_pem.as_bytes())?;
    let dtls_pem = format!("{}\n{}", key_pem.trim(), cert_pem.trim());
    Ok(DtlsCertificate::from_pem(&dtls_pem)?)
}

fn normalize_dtls_private_key_pem(
    key_pem: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut errors = Vec::new();

    for block in pem::parse_many(key_pem)? {
        let tag = block.tag().to_string();
        let der = block.contents();

        match parse_dtls_pkcs8_private_key_der(der) {
            Ok(key_der) => return Ok(encode_dtls_private_key_pem(key_der)),
            Err(err) => errors.push(format!("{} as PKCS#8: {}", tag, err)),
        }

        match parse_dtls_p256_sec1_private_key_der(der) {
            Ok(key_der) => return Ok(encode_dtls_private_key_pem(key_der)),
            Err(err) => errors.push(format!("{} as P-256 SEC1: {}", tag, err)),
        }
    }

    Err(format!(
        "no supported DTLS private key block found; tried PKCS#8 and P-256 SEC1 ({})",
        errors.join("; ")
    )
    .into())
}

fn parse_dtls_pkcs8_private_key_der(
    key_der: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match PrivateKeyDer::try_from(key_der.to_vec())? {
        PrivateKeyDer::Pkcs8(_) => Ok(key_der.to_vec()),
        PrivateKeyDer::Pkcs1(_) | PrivateKeyDer::Sec1(_) => {
            Err("private key DER is not PKCS#8".into())
        }
        _ => unreachable!("rustls-pki-types private key variants are exhaustive"),
    }
}

fn parse_dtls_p256_sec1_private_key_der(
    key_der: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let secret_key = P256SecretKey::from_sec1_der(key_der)?;
    let pkcs8_der = secret_key.to_pkcs8_der()?;
    Ok(pkcs8_der.as_bytes().to_vec())
}

fn encode_dtls_private_key_pem(key_der: Vec<u8>) -> String {
    pem::encode(&pem::Pem::new("PRIVATE_KEY", key_der))
}

async fn provision_letsencrypt(
    config: &CertificateConfig,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    if config.domains.is_empty() {
        return Err("certificates.domains must contain at least one domain".into());
    }

    let environment = config.environment.as_deref().unwrap_or("staging");
    let cache_dir = PathBuf::from(config.cache_dir.as_deref().unwrap_or(DEFAULT_CACHE_DIR));
    let renew_before_days = config
        .renew_before_days
        .unwrap_or(DEFAULT_RENEW_BEFORE_DAYS);
    fs::create_dir_all(&cache_dir)?;

    let cache_prefix = cache_prefix(environment, &config.domains);
    let cert_path = cache_dir.join(format!("{}.fullchain.pem", cache_prefix));
    let key_path = cache_dir.join(format!("{}.privkey.pem", cache_prefix));

    if cached_certificate_is_usable(&cert_path, &key_path, renew_before_days)? {
        tracing::info!(
            cert_path = %cert_path.display(),
            key_path = %key_path.display(),
            "using cached Let's Encrypt certificate"
        );
        let cert_pem = String::from_utf8(fs::read(&cert_path)?)?;
        let key_pem = String::from_utf8(fs::read(&key_path)?)?;
        return Ok((cert_pem, key_pem));
    }

    let directory_url = letsencrypt_directory_url(environment)?;
    let account = load_or_create_account(config, &cache_dir, environment, directory_url).await?;
    let identifiers = config
        .domains
        .iter()
        .map(|domain| Identifier::Dns(domain.clone()))
        .collect::<Vec<_>>();
    let mut order = account
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await?;

    let store = Arc::new(RwLock::new(HashMap::new()));
    let http01_address = config
        .http01_address
        .as_deref()
        .unwrap_or(DEFAULT_HTTP01_ADDRESS)
        .parse::<SocketAddr>()?;
    let shutdown = start_http01_server(http01_address, store.clone()).await?;

    let result = complete_http01_order(&mut order, store).await;
    let _ = shutdown.send(());
    let (private_key_pem, cert_chain_pem) = result?;

    fs::write(&cert_path, cert_chain_pem.as_bytes())?;
    fs::write(&key_path, private_key_pem.as_bytes())?;

    tracing::info!(
        cert_path = %cert_path.display(),
        key_path = %key_path.display(),
        "cached new Let's Encrypt certificate"
    );

    Ok((cert_chain_pem, private_key_pem))
}

async fn load_sds_certificate(
    config: &CertificateConfig,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let (resource_name, cert_path, key_path, renew_before_days) = sds_cache_paths(config)?;

    match fetch_sds_certificate(config).await {
        Ok((cert_pem, key_pem)) => {
            TlsConfig::from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
            write_cached_certificate(&cert_path, &key_path, &cert_pem, &key_pem)?;
            tracing::info!(
                resource_name = %resource_name,
                cert_path = %cert_path.display(),
                key_path = %key_path.display(),
                "cached SDS certificate"
            );
            Ok((cert_pem, key_pem))
        }
        Err(err) => {
            if cached_certificate_is_usable(&cert_path, &key_path, renew_before_days)? {
                tracing::warn!(
                    resource_name = %resource_name,
                    cert_path = %cert_path.display(),
                    key_path = %key_path.display(),
                    error = %err,
                    "failed to fetch SDS certificate; using cached certificate"
                );
                let cert_pem = String::from_utf8(fs::read(&cert_path)?)?;
                let key_pem = String::from_utf8(fs::read(&key_path)?)?;
                return Ok((cert_pem, key_pem));
            }

            Err(format!(
                "failed to fetch SDS certificate for resource \"{}\" and no usable cache was found: {}",
                resource_name, err
            )
            .into())
        }
    }
}

fn start_sds_tls_watcher(
    config: CertificateConfig,
    resolver: Arc<DynamicCertResolver>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let watcher_key = sds_watcher_key(&config)?;
    if !register_sds_watcher(watcher_key) {
        return Ok(());
    }

    let (resource_name, cert_path, key_path, _renew_before_days) = sds_cache_paths(&config)?;
    let on_update = Arc::new(move |certificate: SdsCertificate| {
        resolver.update_from_pem(&certificate.cert_pem, &certificate.key_pem)?;
        write_cached_certificate(
            &cert_path,
            &key_path,
            &certificate.cert_pem,
            &certificate.key_pem,
        )?;
        tracing::info!(
            resource_name = %resource_name,
            version_info = %certificate.version_info,
            nonce = %certificate.nonce,
            "updated TLS certificate from SDS"
        );
        Ok(())
    });

    tokio::spawn(async move {
        if let Err(err) = watch_sds_certificates(config, on_update).await {
            tracing::error!(error = %err, "SDS TLS certificate watcher stopped");
        }
    });

    Ok(())
}

fn start_sds_cache_watcher(
    config: CertificateConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let watcher_key = sds_watcher_key(&config)?;
    if !register_sds_watcher(watcher_key) {
        return Ok(());
    }

    let (resource_name, cert_path, key_path, _renew_before_days) = sds_cache_paths(&config)?;
    let on_update = Arc::new(move |certificate: SdsCertificate| {
        TlsConfig::from_pem(
            certificate.cert_pem.as_bytes(),
            certificate.key_pem.as_bytes(),
        )?;
        write_cached_certificate(
            &cert_path,
            &key_path,
            &certificate.cert_pem,
            &certificate.key_pem,
        )?;
        tracing::info!(
            resource_name = %resource_name,
            version_info = %certificate.version_info,
            nonce = %certificate.nonce,
            "cached updated SDS certificate; restart DTLS listener to use it"
        );
        Ok(())
    });

    tokio::spawn(async move {
        if let Err(err) = watch_sds_certificates(config, on_update).await {
            tracing::error!(error = %err, "SDS certificate cache watcher stopped");
        }
    });

    Ok(())
}

fn sds_cache_paths(
    config: &CertificateConfig,
) -> Result<(String, PathBuf, PathBuf, u64), Box<dyn std::error::Error + Send + Sync>> {
    let resource_name = config
        .sds_resource_name
        .as_deref()
        .ok_or("certificates.sds_resource_name is required for source=\"sds\"")?
        .to_string();
    let cache_dir = PathBuf::from(config.cache_dir.as_deref().unwrap_or(DEFAULT_CACHE_DIR));
    let renew_before_days = config
        .renew_before_days
        .unwrap_or(DEFAULT_RENEW_BEFORE_DAYS);
    fs::create_dir_all(&cache_dir)?;

    let cache_prefix = cache_prefix("sds", std::slice::from_ref(&resource_name));
    let cert_path = cache_dir.join(format!("{}.fullchain.pem", cache_prefix));
    let key_path = cache_dir.join(format!("{}.privkey.pem", cache_prefix));
    Ok((resource_name, cert_path, key_path, renew_before_days))
}

fn write_cached_certificate(
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fs::write(cert_path, cert_pem.as_bytes())?;
    fs::write(key_path, key_pem.as_bytes())?;
    Ok(())
}

fn sds_watcher_key(
    config: &CertificateConfig,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let address = config
        .sds_address
        .as_deref()
        .ok_or("certificates.sds_address is required for source=\"sds\"")?;
    let resource_name = config
        .sds_resource_name
        .as_deref()
        .ok_or("certificates.sds_resource_name is required for source=\"sds\"")?;
    Ok(format!("{}|{}", address, resource_name))
}

fn register_sds_watcher(watcher_key: String) -> bool {
    static WATCHERS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let mut watchers = WATCHERS
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .expect("SDS watcher registry mutex poisoned");
    watchers.insert(watcher_key)
}

async fn load_or_create_account(
    config: &CertificateConfig,
    cache_dir: &Path,
    environment: &str,
    directory_url: String,
) -> Result<Account, Box<dyn std::error::Error + Send + Sync>> {
    let account_path = cache_dir.join(format!("account-{}.json", environment));
    if account_path.exists() {
        let credentials: AccountCredentials = serde_json::from_slice(&fs::read(&account_path)?)?;
        return Ok(Account::builder()?.from_credentials(credentials).await?);
    }

    let contacts = config
        .email
        .as_ref()
        .map(|email| vec![format!("mailto:{}", email)])
        .unwrap_or_default();
    let contact_refs = contacts.iter().map(String::as_str).collect::<Vec<_>>();
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: contact_refs.as_slice(),
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await?;
    fs::write(&account_path, serde_json::to_vec_pretty(&credentials)?)?;
    Ok(account)
}

async fn complete_http01_order(
    order: &mut instant_acme::Order,
    store: ChallengeStore,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => {
                return Err(format!("unexpected authorization status: {:?}", authz.status).into());
            }
        }

        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or("no http-01 challenge found")?;
        let token = challenge.token.clone();
        let key_authorization = challenge.key_authorization().as_str().to_string();
        store.write().await.insert(token.clone(), key_authorization);
        challenge.set_ready().await?;
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        return Err(format!("unexpected order status after HTTP-01: {:?}", status).into());
    }

    let private_key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
    Ok((private_key_pem, cert_chain_pem))
}

async fn start_http01_server(
    addr: SocketAddr,
    store: ChallengeStore,
) -> Result<oneshot::Sender<()>, Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    let app = Router::new()
        .route(
            "/.well-known/acme-challenge/:token",
            get(http01_challenge_handler),
        )
        .with_state(store);
    let (tx, rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        tracing::info!("ACME HTTP-01 challenge server listening on {}", addr);
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
        {
            tracing::error!("ACME HTTP-01 challenge server error: {}", e);
        }
    });

    Ok(tx)
}

async fn http01_challenge_handler(
    AxumPath(token): AxumPath<String>,
    State(store): State<ChallengeStore>,
) -> impl IntoResponse {
    match store.read().await.get(&token).cloned() {
        Some(value) => (StatusCode::OK, value).into_response(),
        None => (StatusCode::NOT_FOUND, "challenge token not found").into_response(),
    }
}

fn letsencrypt_directory_url(
    environment: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    match environment {
        "production" => Ok(LetsEncrypt::Production.url().to_string()),
        "staging" => Ok(LetsEncrypt::Staging.url().to_string()),
        other => Err(format!(
            "unsupported certificates.environment \"{}\"; expected \"production\" or \"staging\"",
            other
        )
        .into()),
    }
}

fn cache_prefix(environment: &str, domains: &[String]) -> String {
    let domain_part = domains
        .iter()
        .map(|domain| sanitize_filename(domain))
        .collect::<Vec<_>>()
        .join("-");
    format!("letsencrypt-{}-{}", environment, domain_part)
}

fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn cached_certificate_is_usable(
    cert_path: &Path,
    key_path: &Path,
    renew_before_days: u64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if !cert_path.exists() || !key_path.exists() {
        return Ok(false);
    }

    let cert_data = fs::read(cert_path)?;
    let certs = parse_certificate_chain(&cert_data)?;
    let (_, cert) = parse_x509_certificate(&certs[0])?;
    let not_after = cert.validity().not_after.timestamp();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let renew_before = Duration::from_secs(renew_before_days.saturating_mul(24 * 60 * 60));
    let renew_at = not_after.saturating_sub(renew_before.as_secs() as i64);

    Ok(now < renew_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert() {
        let config = TlsConfig::generate_self_signed("test.example.com").unwrap();
        assert!(!config.cert_der.is_empty());
        assert_eq!(config.cert_chain_der.len(), 1);
        assert!(!config.key_der.is_empty());
    }

    #[test]
    fn test_generate_localhost_cert() {
        let config = TlsConfig::generate_self_signed("localhost").unwrap();
        assert!(!config.cert_der.is_empty());
        assert!(!config.key_der.is_empty());
    }

    #[test]
    fn test_tls_config_into_server_config() {
        let config = TlsConfig::generate_self_signed("localhost").unwrap();
        let server_config = config.into_server_config();
        assert!(server_config.is_ok());
    }

    #[test]
    fn test_default_test_tls_config() {
        let config = default_test_tls_config();
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(!config.cert_der.is_empty());
        assert!(!config.key_der.is_empty());
    }

    #[test]
    fn test_cert_and_key_different() {
        let config1 = TlsConfig::generate_self_signed("domain1.example.com").unwrap();
        let config2 = TlsConfig::generate_self_signed("domain2.example.com").unwrap();
        assert_ne!(config1.cert_der, config2.cert_der);
        assert_ne!(config1.key_der, config2.key_der);
    }

    #[test]
    fn test_tls_config_clone() {
        let config = TlsConfig::generate_self_signed("test.com").unwrap();
        let cloned = config.clone();
        assert_eq!(cloned.cert_der, config.cert_der);
        assert_eq!(cloned.key_der, config.key_der);
        assert_eq!(cloned.cert_chain_der, config.cert_chain_der);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("turn.example.com"), "turn.example.com");
        assert_eq!(sanitize_filename("*.example.com"), "_.example.com");
        assert_eq!(sanitize_filename("bad/name"), "bad_name");
    }

    #[test]
    fn test_private_key_parsing_uses_der_not_pem_tag() {
        use p256::elliptic_curve::rand_core::OsRng;

        let secret_key = P256SecretKey::random(&mut OsRng);
        let sec1_der = secret_key.to_sec1_der().unwrap();
        let sec1_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", sec1_der.to_vec()));

        let parsed_tls = parse_private_key(sec1_pem.as_bytes()).unwrap();
        assert_eq!(parsed_tls.1, PrivateKeyKind::Sec1);
        let normalized_dtls = normalize_dtls_private_key_pem(sec1_pem.as_bytes()).unwrap();
        assert!(normalized_dtls.contains("-----BEGIN PRIVATE_KEY-----"));
    }
}
