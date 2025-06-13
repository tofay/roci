use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use ocidir::{
    OciDir,
    cap_std::fs::Dir,
    new_empty_manifest,
    oci_spec::image::{Arch, ConfigBuilder, Descriptor, ImageConfigurationBuilder, MediaType, Os},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
};
use tar::{EntryType, Header};

/// The path where relative libraries are stored in the image,
/// if we can't determine the library path from `ld.so`.
const LIBRARY_PATH: &str = "/lib";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub source: PathBuf,
    pub target: PathBuf,
    #[serde(default)]
    pub mode: Option<u32>,
    #[serde(default)]
    pub uid: Option<u64>,
    #[serde(default)]
    pub gid: Option<u64>,
}

/// Resolve the entries to include all dependencies.
/// This will analyze the entries using `lddtree` to find all libraries and interpreters,
/// and return a list of entries that includes the original entries and their dependencies.
fn resolve_entries(entries: &[Entry]) -> Result<Vec<Entry>> {
    let analyzer = lddtree::DependencyAnalyzer::new("/".into());
    // Store the dependencies in a HashMap to avoid duplicates - key is destination path
    let mut deps = HashMap::new();
    let shared_library_path = system_search_path()?;

    for entry in entries {
        // Add the entry itself
        deps.insert(entry.target.clone(), entry.clone());
        // Now work out the dependencies
        let tree = match analyzer.clone().analyze(&entry.source) {
            Ok(tree) => tree,
            Err(err) => {
                // Not all entries are ELFs, so we can ignore errors here
                log::trace!("failed to analyze {}: {}", entry.source.display(), err);
                continue;
            }
        };

        if let Some(interpreter) = &tree.interpreter {
            // The interpreter is a special case, we need to add it with its exact path
            let interpreter_path = PathBuf::from(interpreter);
            deps.insert(
                interpreter_path.clone(),
                Entry {
                    source: interpreter_path.clone(),
                    target: interpreter_path,
                    mode: None,
                    uid: None,
                    gid: None,
                },
            );
        }
        for (_, library) in tree.libraries {
            log::debug!(
                "Found library {} in {}",
                library.name,
                entry.source.display()
            );
            let library_path = library.realpath.clone().unwrap_or(library.path.clone());
            let dest_path = if library.name.contains("/") {
                library.path.clone()
            } else {
                let mut dest_path = shared_library_path.clone();
                dest_path.push(library.name);
                dest_path
            };

            deps.insert(
                dest_path.clone(),
                Entry {
                    source: library_path,
                    target: dest_path,
                    mode: None,
                    uid: None,
                    gid: None,
                },
            );
        }
    }

    // just return the values
    Ok(deps.drain().map(|(_k, v)| v).collect())
}

fn system_search_path() -> Result<PathBuf> {
    let output = Command::new("ld.so")
        .arg("--help")
        .output()
        .context("failed to run ld.so --help")?;
    if !output.status.success() {
        bail!("ld.so --help failed with status: {}", output.status);
    }
    let output_str = String::from_utf8_lossy(&output.stdout);
    Ok(output_str
        .lines()
        .find(|line| line.ends_with("(system search path)"))
        .and_then(|line| line.split_whitespace().next().map(PathBuf::from))
        .unwrap_or(PathBuf::from(LIBRARY_PATH)))
}

fn write_entries<'a>(
    builder: &mut tar::Builder<impl Write>,
    entries: impl IntoIterator<Item = &'a Entry>,
) -> Result<()> {
    for entry in entries {
        // Add xattrs if required
        const PAX_SCHILY_XATTR: &[u8; 13] = b"SCHILY.xattr.";

        let xattrs = xattr::list(&entry.source)?;
        let mut pax_header = tar::Header::new_gnu();
        let mut pax_data = Vec::new();

        for key in xattrs {
            let value = xattr::get(&entry.source, &key)?.unwrap_or_default();

            if !value.is_empty() {
                // each entry is "<len> <key>=<value>\n": https://www.ibm.com/docs/en/zos/2.3.0?topic=SSLTBW_2.3.0/com.ibm.zos.v2r3.bpxa500/paxex.html
                let data_len = PAX_SCHILY_XATTR.len() + key.as_bytes().len() + value.len() + 3;
                let mut len_len = 1;
                while data_len + len_len >= 10usize.pow(len_len.try_into()?) {
                    len_len += 1;
                }
                pax_data.write_all((data_len + len_len).to_string().as_bytes())?;
                pax_data.write_all(b" ")?;
                pax_data.write_all(PAX_SCHILY_XATTR)?;
                pax_data.write_all(key.as_bytes())?;
                pax_data.write_all(b"=")?;
                pax_data.write_all(&value)?;
                pax_data.write_all(b"\n")?;
            }
            if !pax_data.is_empty() {
                pax_header.set_size(pax_data.len() as u64);
                pax_header.set_entry_type(tar::EntryType::XHeader);
                pax_header.set_cksum();
                builder.append(&pax_header, &*pax_data)?;
            }
        }

        let mut header = Header::new_gnu();
        let metadata = fs::metadata(&entry.source)?;
        header.set_metadata_in_mode(&metadata, tar::HeaderMode::Deterministic);

        // make entry target relative to the root of the tar
        let target =
            PathBuf::from(".").join(entry.target.strip_prefix("/").unwrap_or(&entry.target));
        header.set_path(&target)?;
        if let Some(uid) = &entry.uid {
            header.set_uid(*uid);
        }
        if let Some(gid) = &entry.gid {
            header.set_gid(*gid);
        }
        if let Some(mode) = &entry.mode {
            header.set_mode(*mode);
        }
        let data = fs::read(&entry.source)?;
        header.set_size(data.len() as u64);
        log::debug!("Adding file: {} size: {}", target.display(), data.len(),);
        builder.append_data(&mut header, &target, &*data)?;
    }

    Ok(())
}

fn write_rpm_manifest<'a>(
    builder: &mut tar::Builder<impl Write>,
    entries: impl IntoIterator<Item = &'a Entry>,
) -> Result<()> {
    // Check if rpm is available
    if Command::new("rpm").arg("--version").output().is_err() {
        return Ok(());
    }

    // determine the owning packages of the files with
    // rpm --query --file --queryformat "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n" [file]
    // we should filter out "no owning package" lines, keeping only the ones with a valid package name
    let output = Command::new("rpm")
            .arg("--query")
            .arg("--file")
            .arg("--queryformat")
            .arg("%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n")
            .args(entries.into_iter().map(|e| e.source.as_os_str()))
            .output()?;

    // don't check for success as here as rpm returns 1 if no package is found
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout
        .lines()
        .filter(|line| !line.contains("no owning package"))
        .collect::<Vec<_>>();

    if !lines.is_empty() {
        let data = lines.join("\n").into_bytes();

        log::debug!("Writing RPM manifest with {} entries", lines.len());

        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::file());
        header.set_path("./var/lib/rpmmanifest/container-manifest-2")?;
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder.append(&header, &*data)?;
    }

    Ok(())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
/// Image configuration per <https://github.com/opencontainers/image-spec/blob/main/config.md#properties>
pub struct ImageConfiguration {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub exposed_ports: Vec<String>,
    #[serde(default = "default_env")]
    pub env: IndexMap<String, String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub workingdir: Option<String>,
    #[serde(default)]
    pub stopsignal: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

fn default_env() -> IndexMap<String, String> {
    let mut env = IndexMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin".to_string(),
    );
    env
}

impl ImageConfiguration {
    pub(crate) fn into_oci_config(
        self,
        creation_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<ocidir::oci_spec::image::ImageConfiguration> {
        let mut inner_builder = ConfigBuilder::default();

        if let Some(user) = self.user {
            inner_builder = inner_builder.user(user);
        }
        if !self.exposed_ports.is_empty() {
            inner_builder = inner_builder.exposed_ports(self.exposed_ports);
        }

        if !self.env.is_empty() {
            inner_builder = inner_builder.env(
                self.env
                    .into_iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>(),
            );
        }
        if !self.entrypoint.is_empty() {
            inner_builder = inner_builder.entrypoint(self.entrypoint);
        }
        if !self.cmd.is_empty() {
            inner_builder = inner_builder.cmd(self.cmd);
        }
        if !self.volumes.is_empty() {
            inner_builder = inner_builder.volumes(self.volumes);
        }
        if !self.labels.is_empty() {
            inner_builder = inner_builder.labels(self.labels);
        }
        if let Some(workingdir) = self.workingdir {
            inner_builder = inner_builder.working_dir(workingdir);
        }
        if let Some(stopsignal) = self.stopsignal {
            inner_builder = inner_builder.stop_signal(stopsignal);
        }
        let inner_config = inner_builder.build()?;

        let mut config_builder = ImageConfigurationBuilder::default()
            .architecture(Arch::Amd64)
            .os(Os::Linux)
            .config(inner_config)
            .created(creation_time.to_rfc3339());

        if let Some(author) = self.author {
            config_builder = config_builder.author(author);
        }

        Ok(config_builder.build()?)
    }
}

/// Build an OCI image from the given entries and configuration.
/// The entries are resolved to include all dependencies, and the image is written to the specified path.
pub fn build_image(
    entries: Vec<Entry>,
    config: ImageConfiguration,
    path: impl AsRef<Path>,
    tag: Option<&str>,
    creation_time: chrono::DateTime<chrono::Utc>,
) -> Result<Descriptor> {
    eprintln!("Resolving files");
    let resolved_entries = resolve_entries(&entries)?;

    log::debug!(
        "Resolved {} entries with {} dependencies",
        entries.len(),
        resolved_entries.len() - entries.len()
    );

    // make sure the path exists
    let path = path.as_ref();
    if !path.exists() {
        fs::create_dir_all(path)?;
    } else if !path.is_dir() {
        bail!("The specified path {} is not a directory", path.display());
    }
    let dir = Dir::open_ambient_dir(path, ocidir::cap_std::ambient_authority())?;
    let oci_dir = OciDir::ensure(&dir)?;

    let mut writer = oci_dir.create_layer(None)?;

    eprintln!("Building image layer");
    write_entries(&mut writer, &resolved_entries)?;
    write_rpm_manifest(&mut writer, &resolved_entries)?;
    let layer = writer.into_inner()?.complete()?;

    let mut config = config
        .into_oci_config(creation_time)
        .expect("failed to create OCI config");
    let mut manifest = new_empty_manifest()
        .media_type(MediaType::ImageManifest)
        .build()?;

    oci_dir.push_layer_full(
        &mut manifest,
        &mut config,
        layer,
        Option::<HashMap<String, String>>::None,
        "roci",
        creation_time,
    );
    eprintln!("Writing image manifest");
    Ok(oci_dir.insert_manifest_and_config(
        manifest,
        config,
        tag,
        ocidir::oci_spec::image::Platform::default(),
    )?)
}

/// Get the creation time for the image.
/// If the `SOURCE_DATE_EPOCH` environment variable is set, it will use that as the creation time.
pub fn creation_time() -> chrono::DateTime<chrono::Utc> {
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(epoch) = epoch.parse::<i64>() {
            return chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0)
                .unwrap_or(chrono::Utc::now());
        }
    }
    chrono::Utc::now()
}
