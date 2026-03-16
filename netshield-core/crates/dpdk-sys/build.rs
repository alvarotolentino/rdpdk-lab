fn main() {
    // Find DPDK via pkg-config — emits link flags automatically
    let dpdk = pkg_config::Config::new()
        .probe("libdpdk")
        .expect(
            "DPDK not found. Install dpdk-dev / libdpdk-dev and ensure \
             pkg-config can locate libdpdk. On Debian/Ubuntu: \
             apt-get install dpdk-dev libdpdk-dev libnuma-dev pkg-config",
        );

    // Compile C helper shims that wrap DPDK macros and static inlines
    let mut cc = cc::Build::new();
    cc.file("src/helpers.c");
    for path in &dpdk.include_paths {
        cc.include(path);
    }
    cc.compile("netshield_dpdk_helpers");
}
