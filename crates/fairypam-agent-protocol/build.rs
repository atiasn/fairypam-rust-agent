fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "../../proto/fairypam/agent/v1/agent.proto",
        "../../proto/fairypam/agent/v2/agent.proto",
    ];
    let include = "../../proto";
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure().compile_protos(&protos, &[include])?;
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    Ok(())
}
