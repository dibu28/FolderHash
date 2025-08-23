# FolderHash

FolderHash is a command line utility written in Rust that scans a directory
recursively and computes checksums for every file.  Results can be printed to
the console or stored in a list file.  Existing entries are skipped so the
operation can be resumed later.  The tool can also verify a directory against a
previously generated checksum list.

By default the program uses the SHA1 hash algorithm but the algorithm can be
changed using the `--hash` flag.  Supported values include `sha1`, `sha256`,
`blake2b`, `blake3`, `xxhash`, `xxh3` and `xxh128`.

## Usage

Generate checksums and write them to a file:

```
folderhash --dir /path/to/dir --list hashes.txt
```

Verify files against an existing list:

```
folderhash --verify --dir /path/to/dir --list hashes.txt
```

Use `--progress` to display progress information and `--json` to read/write
lists in JSON Lines format.

## License

This project is licensed under the terms of the MIT license.
