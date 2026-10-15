# x8A4 (read-only build)

x8A4 reads firmware nonce, generator, Cryptex seed, and IOAESAccelerator key
data on supported jailbroken Apple devices. It does not provide commands to
change NVRAM, kernel memory, APNonce state, files, or system settings.

## Read-only boundary

The CLI and library API expose no device-state mutation operation. The NVRAM
kernel-write routine, DeviceTree NVRAM property setter, NVRAM sync/delete-marker code, and
AppleMobileApNonce generate/clear calls have been removed. The CLI accepts only
the read options below; former mutation flags are not recognized. The library
link stub imports only `kbase` and `kread` from `libkrw`, and the build restricts
the exported ABI to the read-only x8A4 API.

The tool reads kernel memory to inspect values and needs root plus the
jailbreak-provided `libkrw` runtime. x8A4 calls only `kbase` and `kread`; the
external `libkrw` implementation and jailbreak plugin are supplied by the
jailbreak and are outside this source audit. The bundled `libxpf.a` and
`libchoma.a` are also prebuilt dependencies. The linker dead-strips unused
sections and exports only the x8A4 read API. GitHub Actions checks the linked
arm64 and arm64e binaries for kernel-write, filesystem-write, and device-state
mutation imports, and verifies the library exports match the allowlist.

Read results can contain sensitive values. In particular, `-k`, `-l`, and `-d`
print accelerator keys or nonce seed data to the terminal.

## Supported devices

- Full jailbreak with a working kernel read provider
- 64-bit arm64/arm64e devices, including A9 through A17 Pro
- iOS/iPadOS 14.0–18.7.x (Darwin 20–24)
- Run as root

Kernel offsets are resolved from the running kernel. If the bundled XPF resolver
cannot find `task.itk_space` or `allproc`, verified fallbacks are used only for
the iPhone 11 Pro iOS 18.1 kernel (T8030, Darwin 24.1.0, XNU `11215.42.1~1`,
kernel base `0xfffffff007004000`). The `itk_space` offset is `0x318`; `allproc`
is at `0xfffffff00a41c848` (`kernel base + 0x03418848`). Invalid XPF results,
including `0xffffffffffffffff`, are rejected. Other kernels fail closed rather
than using unverified offsets. Runtime Debian packages depend on the externally
supplied `libkrw0` 1.1.2 or newer.

## Build and release packages

The GitHub Actions workflow builds universal arm64/arm64e binaries and creates
rootless (`iphoneos-arm64`) and rootful (`iphoneos-arm`) Debian packages for
each version tag (`v*`). Tag builds attach the four x8A4 runtime/development
packages to the matching GitHub release. Pull requests and branch builds
compile and upload packages as workflow artifacts.

Local builds require Xcode with the iOS SDK, CMake 3.27 or later, and `ldid2`
(or `ldid`). Debian packages additionally require `dpkg-deb`.

```sh
cmake -S . -B build \
  -DCMAKE_OSX_SYSROOT="$(xcrun --sdk iphoneos --show-sdk-path)" \
  -DCMAKE_OSX_ARCHITECTURES="arm64;arm64e" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
  -DRELEASE=ON
cmake --build build --parallel
```

## Usage

| Short | Long | Read operation |
|---|---|---|
| `-h` | `--help` | Show help |
| `-v` | `--verbose` | Enable verbose logging for this process |
| `-a` | `--print-all` | Print all supported values |
| `-x` | `--get-cryptex-seed` | Read the current Cryptex1 seed |
| `-t` | `--get-cryptex-nonce` | Calculate the current Cryptex1 nonce |
| `-g` | `--get-apnonce-generator` | Read the current APNonce generator |
| `-n` | `--get-apnonce` | Calculate the current APNonce |
| `-k ID` | `--get-accel-key ID` | Read one IOAESAccelerator key |
| `-l` | `--get-accel-keys` | Read IOAESAccelerator keys |
| `-d` | `--get-nonce-seeds` | Read nonce seed domains/slots |

## Credits

| User | Project | Description |
|---|---|---|
| [0x7FF] | [dimentio] | Original project x8A4 is based on |
| [stek29] | [nvram] | Research on modern NVRAM access |
| [stek29] | [nonce entanglement] | Research on APNonce generation |

[0x7FF]: https://github.com/0x7FF
[stek29]: https://github.com/stek29
[dimentio]: https://github.com/0x7FF/dimentio
[nvram]: https://stek29.rocks/2018/06/26/nvram.html
[nonce entanglement]: https://x.com/stek29/status/1093252326587072513
