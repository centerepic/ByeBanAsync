use embed_manifest::{embed_manifest_file};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest_file("src/app.manifest").expect("unable to embed manifest file");
    }
}