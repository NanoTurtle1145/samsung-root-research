# CVE-2026-43499 for Galaxy S24 Ultra (SM-S928U1)

Public-source, device-specific implementation for the US Samsung Galaxy S24
Ultra running firmware **S928U1UES6DZF2**.

## Supported target

```text
Model:        SM-S928U1
Codename:     e3q
Build / AP:   S928U1UES6DZF2 / S928USQS6DZF2
Kernel:       6.1.145-android14-11-33419968-abS928USQS6DZF2
Architecture: arm64, 4K pages
```

The target profile is firmware-specific. Constants must be established and
validated separately for every other build.

## Status

The complete public-source device flow was validated on 2026-08-11.

| Stage | Status |
| --- | --- |
| Runtime KASLR recovery | Validated |
| Pipe-page and `mm_struct` acquisition | Validated |
| Pselect task-bank handoff | Validated |
| Physical read and write checks | Validated |
| Temporary bootstrap root | Validated |
| Offline KernelSU staging | Validated |
| KernelSU control-channel check | Validated |

Final device state:

```text
KernelSU: loaded
Root UID: 0
Root context: u:r:ksu:s0
SELinux: Enforcing
```

## Contents

- S928U1 DZF2 target profile and runtime KASLR handling.
- Bounded task-bank selection and retry handling.
- Physical access verification and bootstrap-root service.
- App-readable readiness marker support.
- Size-constrained application payload build.
- Standalone preload and root-helper build targets.

## Build

Android NDK r29 with API 35 was used for the final build check.

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r29

make stable
make build/e3q-S928USQS6DZF2/cve-2026-43499-root
```

Outputs:

```text
build/e3q-S928USQS6DZF2/cve-2026-43499-app.stable.so
build/e3q-S928USQS6DZF2/cve-2026-43499-root
```

To build all development outputs:

```sh
make -j$(nproc)
```

## Documentation

- [Progress](docs/PROGRESS.md)
- [Device run history](docs/RUN_HISTORY.md)
- [Final device validation](docs/S928U1_DZF2_VALIDATION.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
