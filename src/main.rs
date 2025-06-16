use std::io::Write;
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow};
use chrono::Local;
use clap::Parser;
use console::style;
use env_logger::Builder;

use gnoci::{Entry, ImageBuilder, ImageConfiguration};
use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;

/// Small OCI image builder
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
        default_value = "gnoci.toml"
    )]
    config_file: std::path::PathBuf,

    /// Labels to apply to the image, as KEY=VALUE strings
    #[clap(long = "label", value_parser = label_parser)]
    label: Vec<(String, String)>,
}

fn label_parser(s: &str) -> Result<(String, String)> {
    let mut parts = s.splitn(2, '=');
    let key = parts
        .next()
        .ok_or_else(|| anyhow!(format!("Label `{}` missing key", s)))?
        .to_string();
    let value = parts
        .next()
        .ok_or_else(|| anyhow!(format!("Label `{}` missing value", s)))?
        .to_string();
    Ok((key, value))
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
    let logger = Builder::from_default_env()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().to_rfc3339(),
                record.level(),
                record.args()
            )
        })
        .build();
    let multi = MultiProgress::new();
    LogWrapper::new(multi.clone(), logger).try_init().unwrap();
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
    let _descriptor = ImageBuilder::new(config.entries, config.image, &args.path)
        .tag(args.tag.as_deref())
        .multi(&multi)
        .labels(args.label)
        .build()
        .context(format!("Failed to build image at: {}", args.path.display()))?;
    let elapsed = now.elapsed();
    eprintln!(
        "{:>10} in {elapsed:.2?}",
        style("Finished").for_stderr().bright().green()
    );
    Ok(())
}
