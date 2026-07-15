//! Envoy SDS/xDS client for subscribing TLS certificates at startup.

use crate::config::CertificateConfig;
use prost::Message;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

const SECRET_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
const SDS_STREAM_SECRETS_PATH: &str =
    "/envoy.service.secret.v3.SecretDiscoveryService/StreamSecrets";
const ADS_STREAM_AGGREGATED_RESOURCES_PATH: &str =
    "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources";
const SDS_DELTA_SECRETS_PATH: &str = "/envoy.service.secret.v3.SecretDiscoveryService/DeltaSecrets";
const ADS_DELTA_AGGREGATED_RESOURCES_PATH: &str =
    "/envoy.service.discovery.v3.AggregatedDiscoveryService/DeltaAggregatedResources";
const DEFAULT_SDS_TIMEOUT_SECS: u64 = 10;
const SDS_RECONNECT_DELAY_SECS: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XdsStreamApi {
    Ads,
    Sds,
    DeltaAds,
    DeltaSds,
}

impl XdsStreamApi {
    fn from_config(
        config: &CertificateConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match config.sds_api.as_deref().unwrap_or("ads") {
            "ads" => Ok(Self::Ads),
            "sds" => Ok(Self::Sds),
            "delta_ads" => Ok(Self::DeltaAds),
            "delta_sds" => Ok(Self::DeltaSds),
            other => Err(format!(
                "unsupported certificates.sds_api \"{}\"; expected \"ads\", \"sds\", \"delta_ads\", or \"delta_sds\"",
                other
            )
            .into()),
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Ads => ADS_STREAM_AGGREGATED_RESOURCES_PATH,
            Self::Sds => SDS_STREAM_SECRETS_PATH,
            Self::DeltaAds => ADS_DELTA_AGGREGATED_RESOURCES_PATH,
            Self::DeltaSds => SDS_DELTA_SECRETS_PATH,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Ads => "ads",
            Self::Sds => "sds",
            Self::DeltaAds => "delta_ads",
            Self::DeltaSds => "delta_sds",
        }
    }

    fn is_delta(self) -> bool {
        matches!(self, Self::DeltaAds | Self::DeltaSds)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdsCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    pub version_info: String,
    pub nonce: String,
}

#[derive(Clone)]
struct SdsSubscription {
    endpoint: String,
    api: XdsStreamApi,
    resource_name: String,
    node: envoy::config::core::v3::Node,
    timeout: Duration,
}

impl SdsSubscription {
    fn from_config(
        config: &CertificateConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let address = config
            .sds_address
            .as_deref()
            .ok_or("certificates.sds_address is required for source=\"sds\"")?;
        let resource_name = config
            .sds_resource_name
            .as_deref()
            .ok_or("certificates.sds_resource_name is required for source=\"sds\"")?;
        Ok(Self {
            endpoint: normalize_endpoint(address),
            api: XdsStreamApi::from_config(config)?,
            resource_name: resource_name.to_string(),
            node: envoy::config::core::v3::Node {
                id: configured_or_hostname(config.sds_node_id.as_deref()),
                cluster: config.sds_cluster.clone().unwrap_or_default(),
            },
            timeout: Duration::from_secs(
                config.sds_timeout_secs.unwrap_or(DEFAULT_SDS_TIMEOUT_SECS),
            ),
        })
    }

    fn initial_sotw_request(&self) -> envoy::service::discovery::v3::DiscoveryRequest {
        envoy::service::discovery::v3::DiscoveryRequest {
            node: Some(self.node.clone()),
            resource_names: vec![self.resource_name.clone()],
            type_url: SECRET_TYPE_URL.to_string(),
            ..Default::default()
        }
    }

    fn ack_sotw_request(
        &self,
        response: &envoy::service::discovery::v3::DiscoveryResponse,
    ) -> envoy::service::discovery::v3::DiscoveryRequest {
        envoy::service::discovery::v3::DiscoveryRequest {
            version_info: response.version_info.clone(),
            node: Some(self.node.clone()),
            resource_names: vec![self.resource_name.clone()],
            type_url: SECRET_TYPE_URL.to_string(),
            response_nonce: response.nonce.clone(),
        }
    }

    fn initial_delta_request(&self) -> envoy::service::discovery::v3::DeltaDiscoveryRequest {
        envoy::service::discovery::v3::DeltaDiscoveryRequest {
            node: Some(self.node.clone()),
            resource_names_subscribe: vec![self.resource_name.clone()],
            type_url: SECRET_TYPE_URL.to_string(),
            ..Default::default()
        }
    }

    fn ack_delta_request(
        &self,
        response: &envoy::service::discovery::v3::DeltaDiscoveryResponse,
    ) -> envoy::service::discovery::v3::DeltaDiscoveryRequest {
        envoy::service::discovery::v3::DeltaDiscoveryRequest {
            node: Some(self.node.clone()),
            type_url: SECRET_TYPE_URL.to_string(),
            response_nonce: response.nonce.clone(),
            ..Default::default()
        }
    }
}

pub async fn fetch_sds_certificate(
    config: &CertificateConfig,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let certificate = fetch_sds_certificate_update(config).await?;
    Ok((certificate.cert_pem, certificate.key_pem))
}

pub async fn fetch_sds_certificate_update(
    config: &CertificateConfig,
) -> Result<SdsCertificate, Box<dyn std::error::Error + Send + Sync>> {
    let subscription = SdsSubscription::from_config(config)?;
    if subscription.api.is_delta() {
        return fetch_delta_sds_certificate_update(&subscription).await;
    }

    fetch_sotw_sds_certificate_update(&subscription).await
}

async fn fetch_sotw_sds_certificate_update(
    subscription: &SdsSubscription,
) -> Result<SdsCertificate, Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_channel(&subscription).await?;
    let mut client = XdsStreamClient::new(channel, subscription.api);
    let (tx, rx) = mpsc::channel(4);
    tx.send(subscription.initial_sotw_request()).await?;

    tracing::info!(
        sds_api = subscription.api.as_str(),
        path = subscription.api.path(),
        endpoint = %subscription.endpoint,
        resource_name = %subscription.resource_name,
        node_id = %subscription.node.id,
        node_cluster = %subscription.node.cluster,
        "opening xDS certificate stream"
    );

    let mut stream = client
        .stream_resources(Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();

    let wait_for_certificate = async {
        while let Some(response) = stream.message().await? {
            if let Some(certificate) =
                try_extract_certificate_from_sotw_response(&response, &subscription.resource_name)?
            {
                return Ok(certificate);
            }
            tx.send(subscription.ack_sotw_request(&response)).await?;
        }

        Err("SDS stream closed before sending the requested Secret".into())
    };

    match tokio::time::timeout(subscription.timeout, wait_for_certificate).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "timed out after {}s waiting for SDS resource \"{}\"",
            subscription.timeout.as_secs(),
            subscription.resource_name
        )
        .into()),
    }
}

async fn fetch_delta_sds_certificate_update(
    subscription: &SdsSubscription,
) -> Result<SdsCertificate, Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_channel(&subscription).await?;
    let mut client = XdsStreamClient::new(channel, subscription.api);
    let (tx, rx) = mpsc::channel(4);
    tx.send(subscription.initial_delta_request()).await?;

    tracing::info!(
        sds_api = subscription.api.as_str(),
        path = subscription.api.path(),
        endpoint = %subscription.endpoint,
        resource_name = %subscription.resource_name,
        node_id = %subscription.node.id,
        node_cluster = %subscription.node.cluster,
        "opening Delta xDS certificate stream"
    );

    let mut stream = client
        .stream_delta_resources(Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();

    let wait_for_certificate = async {
        while let Some(response) = stream.message().await? {
            if let Some(certificate) =
                try_extract_certificate_from_delta_response(&response, &subscription.resource_name)?
            {
                return Ok(certificate);
            }
            tx.send(subscription.ack_delta_request(&response)).await?;
        }

        Err("Delta SDS stream closed before sending the requested Secret".into())
    };

    match tokio::time::timeout(subscription.timeout, wait_for_certificate).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "timed out after {}s waiting for Delta SDS resource \"{}\"",
            subscription.timeout.as_secs(),
            subscription.resource_name
        )
        .into()),
    }
}

pub async fn watch_sds_certificates(
    config: CertificateConfig,
    on_update: Arc<
        dyn Fn(SdsCertificate) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
            + Send
            + Sync,
    >,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscription = SdsSubscription::from_config(&config)?;
    loop {
        let result = if subscription.api.is_delta() {
            watch_delta_sds_certificates_once(&subscription, on_update.clone()).await
        } else {
            watch_sotw_sds_certificates_once(&subscription, on_update.clone()).await
        };
        if let Err(err) = result {
            tracing::warn!(
                resource_name = %subscription.resource_name,
                sds_api = subscription.api.as_str(),
                error = %err,
                "SDS certificate watch disconnected; reconnecting"
            );
            tokio::time::sleep(Duration::from_secs(SDS_RECONNECT_DELAY_SECS)).await;
        }
    }
}

async fn watch_sotw_sds_certificates_once(
    subscription: &SdsSubscription,
    on_update: Arc<
        dyn Fn(SdsCertificate) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
            + Send
            + Sync,
    >,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_channel(subscription).await?;
    let mut client = XdsStreamClient::new(channel, subscription.api);
    let (tx, rx) = mpsc::channel(16);
    tx.send(subscription.initial_sotw_request()).await?;

    tracing::info!(
        sds_api = subscription.api.as_str(),
        path = subscription.api.path(),
        endpoint = %subscription.endpoint,
        resource_name = %subscription.resource_name,
        node_id = %subscription.node.id,
        node_cluster = %subscription.node.cluster,
        "opening xDS certificate watch stream"
    );

    let mut stream = client
        .stream_resources(Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();

    while let Some(response) = stream.message().await? {
        if let Some(certificate) =
            try_extract_certificate_from_sotw_response(&response, &subscription.resource_name)?
        {
            on_update(certificate)?;
        }
        tx.send(subscription.ack_sotw_request(&response)).await?;
    }

    Err("SDS stream closed".into())
}

async fn watch_delta_sds_certificates_once(
    subscription: &SdsSubscription,
    on_update: Arc<
        dyn Fn(SdsCertificate) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
            + Send
            + Sync,
    >,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_channel(subscription).await?;
    let mut client = XdsStreamClient::new(channel, subscription.api);
    let (tx, rx) = mpsc::channel(16);
    tx.send(subscription.initial_delta_request()).await?;

    tracing::info!(
        sds_api = subscription.api.as_str(),
        path = subscription.api.path(),
        endpoint = %subscription.endpoint,
        resource_name = %subscription.resource_name,
        node_id = %subscription.node.id,
        node_cluster = %subscription.node.cluster,
        "opening Delta xDS certificate watch stream"
    );

    let mut stream = client
        .stream_delta_resources(Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();

    while let Some(response) = stream.message().await? {
        if let Some(certificate) =
            try_extract_certificate_from_delta_response(&response, &subscription.resource_name)?
        {
            on_update(certificate)?;
        }
        tx.send(subscription.ack_delta_request(&response)).await?;
    }

    Err("Delta SDS stream closed".into())
}

async fn connect_channel(
    subscription: &SdsSubscription,
) -> Result<Channel, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Endpoint::from_shared(subscription.endpoint.clone())?
        .timeout(subscription.timeout)
        .connect()
        .await?)
}

fn normalize_endpoint(address: &str) -> String {
    if address.contains("://") {
        address.to_string()
    } else {
        format!("http://{}", address)
    }
}

fn configured_or_hostname(configured: Option<&str>) -> String {
    if let Some(value) = configured.map(str::trim).filter(|value| !value.is_empty()) {
        return value.to_string();
    }

    system_hostname().unwrap_or_else(|| "miuturn".to_string())
}

fn system_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
}

fn try_extract_certificate_from_sotw_response(
    response: &envoy::service::discovery::v3::DiscoveryResponse,
    resource_name: &str,
) -> Result<Option<SdsCertificate>, Box<dyn std::error::Error + Send + Sync>> {
    tracing::debug!(
        version_info = %response.version_info,
        nonce = %response.nonce,
        type_url = %response.type_url,
        resource_count = response.resources.len(),
        expected_resource_name = %resource_name,
        "received SDS DiscoveryResponse"
    );

    if response.type_url != SECRET_TYPE_URL {
        return Err(format!(
            "unexpected SDS DiscoveryResponse type_url \"{}\"",
            response.type_url
        )
        .into());
    }

    let mut received_secret_names = Vec::new();
    for resource in &response.resources {
        tracing::debug!(
            resource_type_url = %resource.type_url,
            value_len = resource.value.len(),
            expected_resource_name = %resource_name,
            "inspecting SDS resource"
        );

        if resource.type_url != SECRET_TYPE_URL {
            tracing::debug!(
                resource_type_url = %resource.type_url,
                expected_type_url = SECRET_TYPE_URL,
                "skipping SDS resource with unexpected type_url"
            );
            continue;
        }

        let secret = envoy::extensions::transport_sockets::tls::v3::Secret::decode(
            resource.value.as_slice(),
        )?;
        received_secret_names.push(secret.name.clone());
        tracing::info!(
            secret_name = %secret.name,
            expected_resource_name = %resource_name,
            "received SDS Secret"
        );
        tracing::debug!(
            secret_name = %secret.name,
            expected_resource_name = %resource_name,
            "decoded SDS Secret"
        );
        if secret.name != resource_name {
            tracing::debug!(
                secret_name = %secret.name,
                expected_resource_name = %resource_name,
                "skipping SDS Secret because name does not match requested resource"
            );
            continue;
        }

        let (cert_pem, key_pem) = extract_certificate_from_secret(&secret)?;
        return Ok(Some(SdsCertificate {
            cert_pem,
            key_pem,
            version_info: response.version_info.clone(),
            nonce: response.nonce.clone(),
        }));
    }

    tracing::warn!(
        expected_resource_name = %resource_name,
        received_secret_names = ?received_secret_names,
        "SDS response did not contain the requested Secret"
    );

    Ok(None)
}

fn try_extract_certificate_from_delta_response(
    response: &envoy::service::discovery::v3::DeltaDiscoveryResponse,
    resource_name: &str,
) -> Result<Option<SdsCertificate>, Box<dyn std::error::Error + Send + Sync>> {
    tracing::debug!(
        system_version_info = %response.system_version_info,
        nonce = %response.nonce,
        type_url = %response.type_url,
        resource_count = response.resources.len(),
        removed_resources = ?response.removed_resources,
        expected_resource_name = %resource_name,
        "received Delta SDS DiscoveryResponse"
    );

    if response.type_url != SECRET_TYPE_URL {
        return Err(format!(
            "unexpected Delta SDS DiscoveryResponse type_url \"{}\"",
            response.type_url
        )
        .into());
    }

    if response
        .removed_resources
        .iter()
        .any(|name| name == resource_name)
    {
        tracing::warn!(
            expected_resource_name = %resource_name,
            "Delta SDS removed the requested Secret"
        );
        return Ok(None);
    }

    let mut received_secret_names = Vec::new();
    for resource in &response.resources {
        let Some(any) = resource.resource.as_ref() else {
            tracing::debug!(
                resource_name = %resource.name,
                expected_resource_name = %resource_name,
                "skipping Delta SDS resource without protobuf Any payload"
            );
            continue;
        };

        tracing::debug!(
            delta_resource_name = %resource.name,
            delta_resource_version = %resource.version,
            resource_type_url = %any.type_url,
            value_len = any.value.len(),
            expected_resource_name = %resource_name,
            "inspecting Delta SDS resource"
        );

        if any.type_url != SECRET_TYPE_URL {
            tracing::debug!(
                resource_type_url = %any.type_url,
                expected_type_url = SECRET_TYPE_URL,
                "skipping Delta SDS resource with unexpected type_url"
            );
            continue;
        }

        let secret =
            envoy::extensions::transport_sockets::tls::v3::Secret::decode(any.value.as_slice())?;
        received_secret_names.push(secret.name.clone());
        tracing::info!(
            delta_resource_name = %resource.name,
            secret_name = %secret.name,
            expected_resource_name = %resource_name,
            "received Delta SDS Secret"
        );

        if resource.name != resource_name && secret.name != resource_name {
            tracing::debug!(
                delta_resource_name = %resource.name,
                secret_name = %secret.name,
                expected_resource_name = %resource_name,
                "skipping Delta SDS Secret because name does not match requested resource"
            );
            continue;
        }

        let (cert_pem, key_pem) = extract_certificate_from_secret(&secret)?;
        let version_info = if resource.version.is_empty() {
            response.system_version_info.clone()
        } else {
            resource.version.clone()
        };
        return Ok(Some(SdsCertificate {
            cert_pem,
            key_pem,
            version_info,
            nonce: response.nonce.clone(),
        }));
    }

    tracing::warn!(
        expected_resource_name = %resource_name,
        received_secret_names = ?received_secret_names,
        "Delta SDS response did not contain the requested Secret"
    );

    Ok(None)
}

fn extract_certificate_from_secret(
    secret: &envoy::extensions::transport_sockets::tls::v3::Secret,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let Some(envoy::extensions::transport_sockets::tls::v3::secret::Type::TlsCertificate(
        tls_certificate,
    )) = &secret.r#type
    else {
        return Err(format!("SDS secret \"{}\" is not a TLS certificate", secret.name).into());
    };

    let cert_chain = data_source_to_string(
        tls_certificate.certificate_chain.as_ref(),
        "tls_certificate.certificate_chain",
    )?;
    let private_key = data_source_to_string(
        tls_certificate.private_key.as_ref(),
        "tls_certificate.private_key",
    )?;
    Ok((cert_chain, private_key))
}

fn data_source_to_string(
    data_source: Option<&envoy::config::core::v3::DataSource>,
    field_name: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let data_source = data_source.ok_or_else(|| format!("SDS {} is missing", field_name))?;
    match data_source.specifier.as_ref() {
        Some(envoy::config::core::v3::data_source::Specifier::InlineString(value)) => {
            Ok(value.clone())
        }
        Some(envoy::config::core::v3::data_source::Specifier::InlineBytes(value)) => {
            Ok(String::from_utf8(value.clone())?)
        }
        Some(envoy::config::core::v3::data_source::Specifier::Filename(path)) => {
            Ok(String::from_utf8(fs::read(path)?)?)
        }
        None => Err(format!("SDS {} has no data source specifier", field_name).into()),
    }
}

enum XdsStreamClient {
    Ads(
        envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient<
            Channel,
        >,
    ),
    Sds(envoy::service::secret::v3::secret_discovery_service_client::SecretDiscoveryServiceClient<Channel>),
}

impl XdsStreamClient {
    fn new(channel: Channel, api: XdsStreamApi) -> Self {
        match api {
            XdsStreamApi::Ads | XdsStreamApi::DeltaAds => Self::Ads(
                envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient::new(channel),
            ),
            XdsStreamApi::Sds | XdsStreamApi::DeltaSds => Self::Sds(
                envoy::service::secret::v3::secret_discovery_service_client::SecretDiscoveryServiceClient::new(channel),
            ),
        }
    }

    async fn stream_resources(
        &mut self,
        request: Request<ReceiverStream<envoy::service::discovery::v3::DiscoveryRequest>>,
    ) -> Result<
        Response<tonic::codec::Streaming<envoy::service::discovery::v3::DiscoveryResponse>>,
        Status,
    > {
        match self {
            Self::Ads(client) => client.stream_aggregated_resources(request).await,
            Self::Sds(client) => client.stream_secrets(request).await,
        }
    }

    async fn stream_delta_resources(
        &mut self,
        request: Request<ReceiverStream<envoy::service::discovery::v3::DeltaDiscoveryRequest>>,
    ) -> Result<
        Response<tonic::codec::Streaming<envoy::service::discovery::v3::DeltaDiscoveryResponse>>,
        Status,
    > {
        match self {
            Self::Ads(client) => client.delta_aggregated_resources(request).await,
            Self::Sds(client) => client.delta_secrets(request).await,
        }
    }
}

pub mod envoy {
    pub mod config {
        pub mod core {
            pub mod v3 {
                tonic::include_proto!("envoy.config.core.v3");
            }
        }
    }

    pub mod service {
        pub mod discovery {
            pub mod v3 {
                tonic::include_proto!("envoy.service.discovery.v3");
            }
        }

        pub mod secret {
            pub mod v3 {
                tonic::include_proto!("envoy.service.secret.v3");
            }
        }
    }

    pub mod extensions {
        pub mod transport_sockets {
            pub mod tls {
                pub mod v3 {
                    tonic::include_proto!("envoy.extensions.transport_sockets.tls.v3");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sds::envoy::config::core::v3::DataSource;
    use crate::sds::envoy::config::core::v3::data_source::Specifier;
    use crate::sds::envoy::extensions::transport_sockets::tls::v3::secret::Type;
    use crate::sds::envoy::extensions::transport_sockets::tls::v3::{Secret, TlsCertificate};

    #[test]
    fn test_normalize_endpoint_adds_http_scheme() {
        assert_eq!(
            normalize_endpoint("127.0.0.1:18000"),
            "http://127.0.0.1:18000"
        );
        assert_eq!(
            normalize_endpoint("https://sds.example.com"),
            "https://sds.example.com"
        );
    }

    #[test]
    fn test_extract_tls_certificate_inline_string() {
        let secret = Secret {
            name: "turn-cert".to_string(),
            r#type: Some(Type::TlsCertificate(TlsCertificate {
                certificate_chain: Some(DataSource {
                    specifier: Some(Specifier::InlineString("CERT".to_string())),
                }),
                private_key: Some(DataSource {
                    specifier: Some(Specifier::InlineString("KEY".to_string())),
                }),
            })),
        };

        let (cert, key) = extract_certificate_from_secret(&secret).unwrap();
        assert_eq!(cert, "CERT");
        assert_eq!(key, "KEY");
    }

    #[test]
    fn test_configured_or_hostname_prefers_non_empty_config() {
        assert_eq!(configured_or_hostname(Some("node-a")), "node-a");
        assert_eq!(configured_or_hostname(Some("  node-b  ")), "node-b");
    }
}
