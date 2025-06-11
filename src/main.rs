use std::io::Write;
use std::time::Instant;

use chrono::Local;
use clap::Parser;
use env_logger::Builder;

use roci::{self, build_image, Entry, ImageConfiguration};

/// Build a roci image
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Output image path
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

fn creation_time() -> chrono::DateTime<chrono::Utc> {
    // Use the current time as the creation time, unless SOURCE_DATE_EPOCH is set
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(epoch) = epoch.parse::<i64>() {
            return chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0)
                .unwrap_or(chrono::Utc::now());
        }
    }
    chrono::Utc::now()
}

fn main() {
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
    let contents = std::fs::read_to_string(&args.config_file).unwrap();
    let config: ConfigFile = toml::from_str(&contents).unwrap();

    let now = Instant::now();
    let _descriptor = build_image(
        config.entries,
        config.image,
        args.path,
        args.tag.as_deref(),
        creation_time(),
    )
    .unwrap();

    let elapsed = now.elapsed();
    eprintln!("Finished in: {:.2?}", elapsed);
}
