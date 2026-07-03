# USAGE — `ed2k-tool` command reference

`ed2k-tool` is the command-line front-end for the ed2kengine library. All network commands use
a 15s default per-operation timeout and auto-rotate through the servers in `server.met`.

## `hash <file> [--aich] [--red]`

Compute the ed2k link for a local file.

- `--aich` — also compute the AICH root hash (base32) and embed it as `h=<root>` for corruption
  recovery during download.
- `--red` — use the RED (eD2k-hash-redefined) hash variant instead of classic blue.

```bash
ed2k-tool hash movie.avi --aich
# ed2k://|file|movie.avi|<size>|<md4>|h=<aich-base32>|/
```

## `serverlist <server.met>`

Parse a `server.met` file and print the server table (IP, port, max users, name).

## `parse <ed2k-link>`

Parse an `ed2k://` link and print its fields. Recognizes file, server, and server-list links.

```bash
ed2k-tool parse "ed2k://|file|ubuntu.iso|12345678|<md4>|/"
# file: name=ubuntu.iso size=12345678 hash=<md4> aich=- sources=0
```

## `login <server.met> [--ip:x.x.x.x] [--port:n]`

Login to a server (rotates through `server.met` until one accepts). Prints the assigned client
ID, whether it is a HighID, and server flags.

- `--ip` / `--port` — pin a specific server instead of rotating.

A HighID means you are publicly reachable; a LowID means the server will relay via callback
(`OP_CALLBACKREQUEST`) — the engine handles both transparently.

## `search <server.met> <keyword>`

Login, run a keyword search, print results (`hash  size  name`). The first matching server is
used.

## `sources <server.met> <ed2k-link>`

Login, ask the server for sources of the given file link, print them
(`IP  id=0x...  port=...  HighID/LowID`).

## `download <ed2k-link> [--out:PATH] [--server:server.met]`

Download a file. Multi-source: the engine gathers sources from the server and downloads from
all of them concurrently (raccoon), with per-part MD4 verification and AICH corruption recovery.

- `--out:PATH` — output file path (default: the link's filename, or `download.bin`).
- `--server:server.met` — server list to login through. Omit to use the internal fallback list.

Download writes a sparse `PartFile` and a sidecar `<file>.part.met`. If the download is
interrupted, re-running the same command resumes: already-MD4-verified parts are trusted from
`.part.met` and skipped (no re-hash); partial parts are re-downloaded whole.

```bash
ed2k-tool download "ed2k://|file|ubuntu.iso|...|/" --out:ubuntu.iso --server:server.met
# downloaded ubuntu.iso
```

## Exit codes

- `0` — success.
- `1` — runtime error (login failed, no sources, download error, corrupt block). Message on stdout.
- `2` — usage error (wrong arguments).

## Environment

- `ED2K_LIVE=1` — enable live tests (see README). Not used by the CLI.
