// This approach was to inject .note.package section into the binary, but it is not used currently, due to
// var/lib/rpmmanifest/container-manifest-2 being used instead, and being supported by trivy/syfy/qualys.

// #[derive(Debug, Serialize)]
// #[serde(rename_all = "camelCase")]
// struct PackageNote {
//     #[serde(rename = "type")]
//     ty: String,
//     os: String,
//     name: String,
//     version: String,
//     architecture: String,
// }

// static DISTRO_ID: Lazy<Option<String>> = Lazy::new(|| {
//     fs::read_to_string("/etc/os-release")
//         .map(|content| {
//             // Find the line that starts with "ID="
//             for line in content.lines() {
//                 if let Some(name) = line.strip_prefix("ID=") {
//                     return Some(name.trim_matches('"').to_string());
//                 }
//             }
//             None
//         })
//         .unwrap_or_default()
// });

// fn read_file(path: &Path) -> Result<Vec<u8>> {
//     let data = fs::read(path)?;

//     let file = object::File::parse(&*data).unwrap();
//     if file
//         .sections()
//         .any(|s| s.name().unwrap_or_default() == ".note.package")
//     {
//         eprintln!("Note section already present in {}", path.display());
//         return Ok(data);
//     }

//     if let Ok(note) = package_note(path) {
//         let note_data = serde_json::to_vec(&note).map_err(|_| Error::Unknown)?;
//         let note_file = NamedTempFile::new().unwrap();
//         let copied_elf = NamedTempFile::new().unwrap().into_temp_path();

//         // create the note section data
//         let mut out_file = File::create(&note_file).map_err(|_| Error::Unknown)?;
//         //file.write_stream(&mut out_file)
//         //    .map_err(|_| Error::Unknown)?;
//         out_file.write_all(&note_data).map_err(|_| Error::Unknown)?;
//         out_file.flush().map_err(|_| Error::Unknown)?;
//         drop(out_file);

//         // run objcopy to copy the note section into the original file
//         let status = Command::new("objcopy")
//             .arg("--add-section")
//             .arg(".note.package={}".replace("{}", note_file.path().to_str().unwrap()))
//             .arg("--set-section-flags")
//             .arg(".note.package=alloc,readonly")
//             .arg(path)
//             .arg(&copied_elf)
//             .status()
//             .map_err(|_| Error::Unknown)?;
//         if !status.success() {
//             panic!(
//                 "Failed to run objcopy: {}",
//                 String::from_utf8_lossy(&status.to_string().into_bytes())
//             );
//         }
//         // read the modified file back into memory
//         return fs::read(copied_elf).map_err(|_| Error::Unknown);
//     } else {
//         eprintln!("Failed to get package information for {}", path.display());
//     }

//     Ok(data)
// }

// fn distro_name() -> Result<String> {
//     let os_release_path = Path::new("/etc/os-release");
//     if !os_release_path.exists() {
//         return Err(Error::Unknown);
//     }

//     let content = fs::read_to_string(os_release_path)?;
//     for line in content.lines() {
//         if let Some(name) = line.strip_prefix("ID=") {
//             return Ok(name.trim_matches('"').to_string());
//         }
//     }

//     Err(Error::Unknown)
// }

// fn package_note(path: &Path) -> Result<PackageNote> {
//     if let Ok(output) = Command::new("dpkg").arg("-S").arg(path).output() {
//         if output.status.success() {
//             let package_info = String::from_utf8_lossy(&output.stdout);
//             let first_line = package_info.lines().next().unwrap();
//             let package = if first_line.starts_with("diversion by ") {
//                 // Handle "diversion by <package> from: <file>" format
//                 first_line.split(" ").nth(2).unwrap_or("")
//             } else {
//                 // Handle "<package>:(<arch>:) <file>" format
//                 first_line.split(":").next().unwrap_or("")
//             };

//             // run dpkg -W -f "${Version}:${Arch}" <package> to get the version and architecture
//             if let Ok(version_output) = Command::new("dpkg-query")
//                 .arg("-W")
//                 .arg("-f=${Version}:${Architecture}")
//                 .arg(package)
//                 .output()
//             {
//                 if version_output.status.success() {
//                     let version_info = String::from_utf8_lossy(&version_output.stdout)
//                         .trim()
//                         .to_string();
//                     if let Some((version, arch)) = version_info.split_once(':') {
//                         return Ok(PackageNote {
//                             ty: "deb".to_string(),
//                             os: DISTRO_ID.as_deref().unwrap_or("unknown").to_string(),
//                             name: package.to_string(),
//                             version: version.to_string(),
//                             architecture: arch.to_string(),
//                         });
//                     }
//                 }
//             }
//         }
//     } else if let Ok(output) = Command::new("rpm").arg("-qf").arg(path).output() {
//         if output.status.success() {
//             let package_info = String::from_utf8_lossy(&output.stdout);
//             let first_line = package_info.lines().next().unwrap();
//             let parts: Vec<&str> = first_line.split('-').collect();
//             if parts.len() >= 3 {
//                 let (name, version, arch) = (parts[0], parts[1], parts[2]);
//                 return Ok(PackageNote {
//                     ty: "rpm".to_string(),
//                     os: DISTRO_ID.as_deref().unwrap_or("unknown").to_string(),
//                     name: name.to_string(),
//                     version: version.to_string(),
//                     architecture: arch.to_string(),
//                 });
//             }
//         }
//     }

//     if !path.ends_with("ro") {
//         panic!("Failed to get package information for {}", path.display());
//     }

//     Err(Error::Unknown)
// }
