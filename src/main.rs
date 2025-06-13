use std::io::Write;
use std::time::Instant;

use anyhow::{Context as _, Result};
use chrono::Local;
use clap::Parser;
use env_logger::Builder;

use roci::{self, build_image, creation_time, Entry, ImageConfiguration};

/// Build a roci image
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Output OCI image directory path
    #[arg(value_name = "PATH")]
    path: std::path::PathBuf,

    /// Optional tag for the image
    #[arg(short, long)]
    tag: Option<String>,

    /// Config file
    #[arg(
        short = 'f',
        long = "file",
        value_name = "FILE",
        default_value = "roci.toml"
    )]
    config_file: std::path::PathBuf,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    entries: Vec<Entry>,
    #[serde(flatten)]
    image: ImageConfiguration,
}

fn main() -> Result<()> {
    // setup env logger
    Builder::from_default_env()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();
    let args = Cli::parse();

    // parse config file
    let contents = std::fs::read_to_string(&args.config_file).context(format!(
        "Failed to read config file: {}",
        args.config_file.display()
    ))?;
    let config: ConfigFile = toml::from_str(&contents).context(format!(
        "Failed to parse config file: {}",
        args.config_file.display()
    ))?;

    let now = Instant::now();
    let _descriptor = build_image(
        config.entries,
        config.image,
        &args.path,
        args.tag.as_deref(),
        creation_time(),
    )
    .context(format!("Failed to build image at: {}", args.path.display()))?;

    let elapsed = now.elapsed();
    eprintln!("Finished in: {:.2?}", elapsed);
    Ok(())
}
