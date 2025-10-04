fn main() {
    if cfg!(target_os = "windows") {
        // Change this to your actual SDK path
        println!("cargo:rustc-link-search=native=C:\\npcap-sdk\\Lib\\x64");
        println!("cargo:rustc-link-lib=wpcap");
    }
}
