# libpefile

A feature-complete C++20 port of [pefile](https://github.com/erocarrera/pefile), a multi-platform Python module to parse and work with Portable Executable (PE) files. This repository also includes the companion test suite adapted from [pefile-tests](https://github.com/erocarrera/pefile-tests/).

## Status

The library has been fully tested, debugged, and is designed to match the original Python implementation's behavior as closely as possible.

## Dependencies

- **C++20** compatible compiler
- **libcrypto** (OpenSSL) — *Optional*

### Cryptographic Fallback Mechanism
The library primarily attempts to use `libcrypto` for hash calculations (MD5, SHA1, SHA256, SHA512). If `libcrypto` is unavailable at build/runtime, it gracefully falls back to invoking system CLI utilities (`md5sum`, `sha1sum`, `sha256sum`, `sha512sum`).

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See the [LICENSE](LICENSE) file for details.

### Test Data Exception
The test data located in the `tests/testdata/` directory originates from various third-party sources and binaries. Each file within `tests/testdata/` carries its own individual license. Please inspect the respective files or directories for their specific licensing terms.
