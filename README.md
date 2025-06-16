# roci

**roci** is a command-line tool for building OCI container images from a simple TOML configuration file.

## Features

- Build OCI images using a simple, declarative config file
- Fast and reproducible builds
- Images contain just the specified files and their dynamic library dependencies
- Automatic RPM manifest generation for Trivy/Syft integration (RPM-based distros only)

## Usage

```sh
$ roci --help
Small OCI image builder

Usage: roci [OPTIONS] <PATH>

Arguments:
  <PATH>  Output OCI image directory path

Options:
  -t, --tag <TAG>      Optional tag for the image
  -f, --file <FILE>    Config file [default: roci.toml]
      --label <LABEL>  Labels to apply to the image, as KEY=VALUE strings
  -h, --help           Print help
  -V, --version        Print version
```

### Example

```sh
roci -t v1 -f custom.toml ./output-dir
```

This builds an OCI image using `custom.toml` and writes it to the OCI image directory (which is created if it doesn't exist) `./output-dir` with the tag `v1`.

## Configuration

The config file (default: `roci.toml`) is written in TOML and supports the following structure:

```toml
# roci.toml
# Image configuration fields
cmd = ["/usr/bin/myapp"]
# ...other image configuration fields... 

[[entries]]
source = "bin/myapp"
target = "/usr/bin/myapp"
mode = 0o755       # optional
uid = 1001         # optional
gid = 1001         # optional
```

## RPM Manifest for Trivy/Syft

When building an image, **roci** will automatically generate an RPM manifest at  
`/var/lib/rpmmanifest/container-manifest-2` inside the image layer (if `rpm` is available on the host).  
This will list any packages that own files included in the image.  
This enables vulnerability and package scanning with tools like [Trivy](https://github.com/aquasecurity/trivy) and [Syft](https://github.com/anchore/syft), which can detect and report installed RPM packages based on this manifest.
