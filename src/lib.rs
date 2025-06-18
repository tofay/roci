#![deny(missing_docs)]

//! Small OCI image builder.
//!
//! Builds container images containing a given set of files, their dynamic
//! library dependencies, and OS package files for scanning tools to detect
//! the source of the files (RPM/deb based systems).
use anyhow::{Context, Result, bail};
use console::{Term, style};
use indexmap::IndexMap;
use indicatif::{ProgressBar, ProgressStyle};
use ocidir::{
    OciDir,
    cap_std::fs::Dir,
    new_empty_manifest,
    oci_spec::image::{Arch, ConfigBuilder, Descriptor, ImageConfigurationBuilder, MediaType, Os},
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File},
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
};
use tar::{EntryType, Header, HeaderMode};

/// The path where relative libraries are stored in the image,
/// if we can't determine the library path from `ld.so`.
const LIBRARY_PATH: &str = "/lib";

/// An entry representing a file to be included in the image.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Source path on the host.
    pub source: PathBuf,
    /// Target path inside the image.
    pub target: PathBuf,
    /// Optional file mode.
    #[serde(default)]
    pub mode: Option<u32>,
    /// Optional user ID.
    #[serde(default)]
    pub uid: Option<u64>,
    /// Optional group ID.
    #[serde(default)]
    pub gid: Option<u64>,
}

impl Entry {
    fn relative_target_path(&self) -> PathBuf {
        PathBuf::from(".").join(self.target.strip_prefix("/").unwrap_or(&self.target))
    }
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
            let dest_path = if library.name.contains('/') {
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

/// Image configuration per <https://github.com/opencontainers/image-spec/blob/main/config.md#properties>
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageConfiguration {
    /// User to run as.
    #[serde(default)]
    pub user: Option<String>,
    /// Ports to expose.
    #[serde(default)]
    pub exposed_ports: Vec<String>,
    /// Environment variables.
    #[serde(default = "default_env")]
    pub env: IndexMap<String, String>,
    /// Entrypoint command.
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Default command.
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Volumes to create.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Image labels.
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Working directory.
    #[serde(default)]
    pub workingdir: Option<String>,
    /// Stop signal.
    #[serde(default)]
    pub stopsignal: Option<String>,
    /// Author of the image.
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
    /// Convert to OCI image configuration, merging additional labels.
    pub(crate) fn into_oci_config(
        self,
        labels: Vec<(String, String)>,
        creation_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<ocidir::oci_spec::image::ImageConfiguration> {
        let mut inner_builder = ConfigBuilder::default();

        // Map the labels from the configuration and the additional labels
        let mut labels_map = self.labels;
        for (key, value) in labels {
            labels_map.insert(key, value);
        }
        if !labels_map.is_empty() {
            inner_builder = inner_builder.labels(labels_map);
        }

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

/// Builder for constructing an OCI image.
pub struct ImageBuilder<'a> {
    entries: Vec<Entry>,
    config: ImageConfiguration,
    path: PathBuf,
    labels: Vec<(String, String)>,
    tag: Option<&'a str>,
    creation_time: Option<chrono::DateTime<chrono::Utc>>,
    multi: Option<&'a indicatif::MultiProgress>,
}

impl<'a> ImageBuilder<'a> {
    /// Create a new `ImageBuilder`.
    pub fn new(entries: Vec<Entry>, config: ImageConfiguration, path: impl AsRef<Path>) -> Self {
        Self {
            entries,
            config,
            path: path.as_ref().to_path_buf(),
            tag: None,
            creation_time: None,
            multi: None,
            labels: Vec::new(),
        }
    }

    /// Set the image tag.
    pub fn tag(mut self, tag: Option<&'a str>) -> Self {
        self.tag = tag;
        self
    }

    /// Set the image creation time.
    pub fn creation_time(mut self, creation_time: chrono::DateTime<chrono::Utc>) -> Self {
        self.creation_time = Some(creation_time);
        self
    }

    /// Set the progress multi-bar.
    pub fn multi(mut self, multi: &'a indicatif::MultiProgress) -> Self {
        self.multi = Some(multi);
        self
    }

    /// Set additional image labels.
    pub fn labels(mut self, labels: Vec<(String, String)>) -> Self {
        self.labels = labels;
        self
    }

    /// Build the OCI image and return its descriptor.
    pub fn build(self) -> Result<Descriptor> {
        eprintln!(
            "{:>10} files",
            style("Resolving").for_stderr().bright().green()
        );
        let resolved_entries = resolve_entries(&self.entries)?;

        log::debug!(
            "Resolved {} entries with {} dependencies",
            self.entries.len(),
            resolved_entries.len() - self.entries.len()
        );

        eprintln!(
            "{:>10} image layer",
            style("Writing").for_stderr().bright().green()
        );

        // make sure the path exists
        let path = &self.path;
        if !path.exists() {
            fs::create_dir_all(path)?;
        } else if !path.is_dir() {
            bail!("The specified path {} is not a directory", path.display());
        }
        let dir = Dir::open_ambient_dir(path, ocidir::cap_std::ambient_authority())?;
        let oci_dir = OciDir::ensure(&dir)?;

        let mut layer_builder = oci_dir.create_layer(None)?;
        layer_builder.mode(HeaderMode::Deterministic);

        let mut builder = LayerBuilder::new();
        for entry in &resolved_entries {
            let entry = entry.clone();
            builder.0.insert(
                entry.relative_target_path(),
                Box::new(move |writer| write_entry(writer, &entry)),
            );
        }

        // Read /etc/os-release to detect package type.
        // if ID_LIKE is debian in /etc/os-release, we should write a dpkg manifest
        let os_release =
            fs::read_to_string("/etc/os-release").context("failed to read /etc/os-release")?;
        let is_debian_like = os_release
            .lines()
            .any(|line| line.starts_with("ID_LIKE=") && line.contains("debian"));

        if is_debian_like {
            builder.add_dpkg_files(&resolved_entries)?;
        } else {
            builder.write_rpm_manifest(&resolved_entries)?;
        }

        builder.add_file("/etc/os-release");

        builder.build(&mut layer_builder, self.multi)?;
        let layer = layer_builder.into_inner()?.complete()?;

        let creation_time = self.creation_time.unwrap_or_else(creation_time);

        let mut config = self
            .config
            .into_oci_config(self.labels, creation_time)
            .expect("failed to create OCI config");
        let mut manifest = new_empty_manifest()
            .media_type(MediaType::ImageManifest)
            .build()?;

        oci_dir.push_layer_full(
            &mut manifest,
            &mut config,
            layer,
            Option::<HashMap<String, String>>::None,
            "gnoci",
            creation_time,
        );
        eprintln!(
            "{:>10} image manifest",
            style("Writing").for_stderr().bright().green()
        );
        Ok(oci_dir.insert_manifest_and_config(
            manifest,
            config,
            self.tag,
            ocidir::oci_spec::image::Platform::default(),
        )?)
    }
}

/// Get the creation time for the image.
/// If the `SOURCE_DATE_EPOCH` environment variable is set, it will use that as the creation time.
#[must_use]
pub fn creation_time() -> chrono::DateTime<chrono::Utc> {
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(epoch) = epoch.parse::<i64>() {
            return chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0)
                .unwrap_or(chrono::Utc::now());
        }
    }
    chrono::Utc::now()
}

type FileFn<W> = Box<dyn Fn(&mut tar::Builder<W>) -> Result<()>>;

/// A builder for the image layer.
/// Used for collecting the files to be added to the image, and writing them
/// to the tar archive in the correct order, with directories.
struct LayerBuilder<W: Write>(BTreeMap<PathBuf, FileFn<W>>);

impl<W: Write> LayerBuilder<W> {
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Add an absolute file that exists on disk
    fn add_file(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref().to_owned();
        debug_assert!(path.is_absolute());
        let relative_path = Path::new(".").join(path.strip_prefix("/").unwrap());

        self.0.insert(
            relative_path.clone(),
            Box::new(move |writer| {
                writer.append_file(
                    &relative_path,
                    &mut File::open(&path)
                        .context(format!("failed to open file {}", path.display()))?,
                )?;
                Ok(())
            }),
        );
    }

    /// Write dpkg status files for the given files,
    /// in `/var/lib/dpkg/status.d/` format as used by Google Distroless containers.
    fn add_dpkg_files<'a>(&mut self, entries: impl IntoIterator<Item = &'a Entry>) -> Result<()> {
        // Check if dpkg is available
        if Command::new("dpkg").arg("--version").output().is_err() {
            return Ok(());
        }

        let mut found_debian_package = false;

        for package in entries
            .into_iter()
            .map(|entry| {
                let output = Command::new("dpkg")
                    .arg("-S")
                    .arg(&entry.source)
                    .output()
                    .context(format!(
                        "failed to run dpkg -S for {}",
                        entry.source.display()
                    ))?;

                if output.status.success() {
                    let package_info = String::from_utf8_lossy(&output.stdout);
                    let first_line = package_info.lines().next().unwrap();
                    if first_line.starts_with("diversion by ") {
                        Ok(None)
                    } else {
                        // Handle "<package>:(<arch>:) <file>" format
                        let package_arch = first_line
                            .split(' ')
                            .next()
                            .expect("package name not found")
                            .strip_suffix(":")
                            .expect("unexpected dpkg -S output");
                        Ok(Some(
                            package_arch
                                .split_once(':')
                                .map(|(package, _arch)| package.to_string())
                                .unwrap_or(package_arch.to_string()),
                        ))
                    }
                } else {
                    log::trace!("Failed to run dpkg -S for {}", entry.source.display());
                    Ok(None)
                }
            })
            .collect::<Result<HashSet<_>>>()?
            .into_iter()
            .flatten()
        {
            found_debian_package = true;
            // use `dpkg -s <package>` to get package status, and write to `/var/lib/dpkg.status.d/<package>`
            let output = Command::new("dpkg")
                .arg("-s")
                .arg(&package)
                .output()
                .context(format!("failed to run dpkg -s for package {package}"))?;
            if !output.status.success() {
                bail!("dpkg -s failed for {}", package);
            }

            self.0.insert(
                PathBuf::from(format!("./var/lib/dpkg/status.d/{package}")),
                Box::new(move |writer| {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::file());
                    header.set_path(format!("./var/lib/dpkg/status.d/{package}"))?;
                    header.set_size(output.stdout.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();
                    writer.append(&header, &*output.stdout)?;
                    Ok(())
                }),
            );
        }

        if found_debian_package {
            if Path::new("/etc/lsb-release").exists() {
                self.add_file("/etc/lsb-release");
            }

            if Path::new("/etc/debian_version").exists() {
                self.add_file("/etc/debian_version");
            }
        }

        Ok(())
    }

    /// Add an RPM manifest to the image.
    /// This copies the format of [AzureLinux](https://github.com/microsoft/azurelinux/blob/64ef81a5b9c855fceaa63006a3f42603386a2c7e/toolkit/docs/how_it_works/5_misc.md?plain=1#L154),
    /// which is already supported by Trivy/Syft/Qualys and more.
    fn write_rpm_manifest<'a>(
        &mut self,
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
            .filter(|line| !line.contains("not owned by"))
            .collect::<Vec<_>>();

        if !lines.is_empty() {
            let data = lines.join("\n").into_bytes();

            log::debug!("Adding RPM manifest with {} entries", lines.len());

            self.0.insert(
                PathBuf::from("./var/lib/rpmmanifest/container-manifest-2"),
                Box::new(move |writer| {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::file());
                    header.set_path("./var/lib/rpmmanifest/container-manifest-2")?;
                    header.set_size(data.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();
                    writer.append(&header, &*data)?;
                    Ok(())
                }),
            );
        }

        Ok(())
    }

    /// Actually build the tar archive with the collected files.
    /// This will ensure that directories are created before files are added,
    fn build(
        self,
        tar_builder: &mut tar::Builder<W>,
        multi: Option<&indicatif::MultiProgress>,
    ) -> Result<()> {
        let mut dirs_added = HashSet::new();

        let pb = ProgressBar::new(self.0.len() as u64)
            .with_style(
                ProgressStyle::with_template(
                    // note that bar size is fixed unlike cargo which is dynamic
                    // and also the truncation in cargo uses trailers (`...`)
                    if Term::stdout().size().1 > 80 {
                        "{prefix:>10.cyan.bold} [{bar:57}] {pos}/{len} {wide_msg}"
                    } else {
                        "{prefix:>10.cyan.bold} [{bar:57}] {pos}/{len}"
                    },
                )
                .unwrap()
                .progress_chars("=> "),
            )
            .with_prefix("Packaging");

        let pb = if let Some(multi) = multi {
            multi.add(pb)
        } else {
            pb
        };

        for (path, func) in self.0 {
            log::debug!("Adding {}", path.display());
            pb.set_message(format!("{}", path.display()));

            for ancestor in path
                .ancestors()
                .skip(1)
                .filter(|p| *p != Path::new(""))
                .collect::<Vec<_>>()
                .iter()
                .rev()
            {
                if !dirs_added.contains(*ancestor) {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Directory);
                    header.set_path(ancestor)?;
                    header.set_mode(0o755);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();
                    tar_builder.append(&header, &b""[..])?;
                    dirs_added.insert(ancestor.to_path_buf());
                }
            }

            func(tar_builder)?;
            pb.inc(1);
        }

        pb.finish_and_clear();
        Ok(())
    }
}

fn write_entry(builder: &mut tar::Builder<impl Write>, entry: &Entry) -> Result<()> {
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

    let target = entry.relative_target_path();
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

    Ok(())
}
