use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let protoc_include = protoc_bin_vendored::include_path()?;

    println!("cargo:rerun-if-changed=proto/envoy/config/core/v3/base.proto");
    println!("cargo:rerun-if-changed=proto/envoy/extensions/transport_sockets/tls/v3/secret.proto");
    println!("cargo:rerun-if-changed=proto/envoy/service/discovery/v3/discovery.proto");
    println!("cargo:rerun-if-changed=proto/envoy/service/secret/v3/sds.proto");

    // tonic-build reads PROTOC when invoking prost-build. The vendored binary keeps
    // local builds independent from a system protoc installation.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                "proto/envoy/config/core/v3/base.proto",
                "proto/envoy/extensions/transport_sockets/tls/v3/secret.proto",
                "proto/envoy/service/discovery/v3/discovery.proto",
                "proto/envoy/service/secret/v3/sds.proto",
            ],
            &[Path::new("proto"), protoc_include.as_path()],
        )?;

    Ok(())
}
