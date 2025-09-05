# FolderHash

FolderHash is a command line utility written in Rust that scans a directory
recursively and computes checksums for every file.  Results can be printed to
the console or stored in a list file.  Existing entries are skipped so the
operation can be resumed later.  The tool can also verify a directory against a
previously generated checksum list.

By default the program uses the SHA1 hash algorithm but the algorithm can be
changed using the `--hash` flag. Supported values include `sha1`, `sha256`,
`sha512`, `sha3`, `blake2b`, `blake3`, `md5`, `xxhash`, `xxh3`, `xxh128`,
`wyhash`, `t1ha1`, `t1ha2`, `k12`, `highway64`, `highway128`,
`highway256`, `rapidhash`, `crc32` and `crc64`.

The `gxhash` algorithm is available behind an optional Cargo feature because it
requires `aes` and `sse2` CPU intrinsics. Enable it during compilation with:

```
cargo build --features gxhash
```

After enabling the feature, `gxhash` can be selected with `--hash gxhash`.

## SIMD acceleration

FolderHash enables optional SIMD code paths for several hash algorithms. When
building on `x86_64` targets the code will use SSE2/AVX2 instructions if they
are supported by the CPU, while `aarch64` builds take advantage of NEON. The
optimized routines are provided by the underlying crates such as `blake2`,
`blake3`, `sha1`, `sha2`, and `xxhash` and are activated through Cargo feature
flags. The `xxh3` implementation dispatches at runtime to AVX2 or NEON when
available.

To build with SIMD support simply compile as usual:

```
cargo build --release
```

When cross compiling, additional target features can be supplied via
`RUSTFLAGS`:

```
RUSTFLAGS="-C target-feature=+avx2" cargo build --release
```

## Usage

Generate checksums and write them to a file:

```
folderhash --dir /path/to/dir --list hashes.txt
```

Verify files against an existing list:

```
folderhash --verify --dir /path/to/dir --list hashes.txt
```

Use `--progress` to display progress information and a summary of the total time
taken, and `--json` to read/write lists in JSON Lines format.

## License

This project is licensed under the terms of the MIT license.
