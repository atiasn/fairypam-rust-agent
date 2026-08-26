fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "../../proto/fairypam/internal/v1/state.proto",
        "../../proto/fairypam/agent/v3/agent.proto",
        "../../proto/fairypam/local/v1/local.proto",
        "../../proto/fairypam/worker/v1/worker.proto",
        "../../proto/fairypam/guardian/v1/guardian.proto",
    ];
    let include = "../../proto";
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_transport(false)
        .compile_protos(&protos, &[include])?;
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    Ok(())
}
