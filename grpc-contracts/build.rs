fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/generated")
        .compile(
            &[
                format!("{}/identity.proto", proto_root),
                format!("{}/governance.proto", proto_root),
                format!("{}/compliance.proto", proto_root),
                format!("{}/risk.proto", proto_root),
                format!("{}/audit.proto", proto_root),
                format!("{}/trust.proto", proto_root),
                format!("{}/events.proto", proto_root),
            ],
            &[proto_root],
        )?;

    println!("cargo:rerun-if-changed={}/identity.proto", proto_root);
    println!("cargo:rerun-if-changed={}/governance.proto", proto_root);
    println!("cargo:rerun-if-changed={}/compliance.proto", proto_root);
    println!("cargo:rerun-if-changed={}/risk.proto", proto_root);
    println!("cargo:rerun-if-changed={}/audit.proto", proto_root);
    println!("cargo:rerun-if-changed={}/trust.proto", proto_root);
    println!("cargo:rerun-if-changed={}/events.proto", proto_root);

    Ok(())
}
