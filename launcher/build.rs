fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../assets/icon.ico");
        res.set("ProductName", "NeoShell");
        res.set("FileDescription", "NeoShell - Cross-Platform SSH Manager");
        res.set("LegalCopyright", "Copyright 2026 NeoShell. All rights reserved.");
        res.compile().expect("Failed to compile Windows resources");
    }
}
