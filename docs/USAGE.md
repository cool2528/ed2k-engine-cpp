# USAGE — `ed2k-tool` command reference

[简体中文](USAGE.zh-CN.md)

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

## `update-serverlist <url> <dest>`

Download a server list from an HTTP or HTTPS URL to `dest`. HTTPS verifies the certificate chain
and URL hostname, with no option to disable verification. Redirects are limited to five hops and
share one overall 15-second deadline with connection, TLS handshake, and response transfer.

The destination is replaced atomically only after the complete response has been written and
durably synchronized; failures do not publish a partial body.

```bash
ed2k-tool update-serverlist https://example.org/server.met server.met
```

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

## `publish <dir> [--server:server.met] [--ip:x.x.x.x] [--port:n]`

Scan a local share directory, build the known-file index in memory, login to a server, and publish
the files with `OP_OFFERFILES`.

- `--server:server.met` — server list to login through. Omit to use the internal fallback list.
- `--ip` / `--port` — pin a specific server instead of rotating.

```bash
ed2k-tool publish D:\share --server:server.met
# published 3 files
```

## `comment <ed2k-link> --rating:n --comment:text [--peer:ip:port]`

Encode or send a file rating/comment (`OP_FILEDESC`). Ratings are `0..5`.

Without `--peer`, the command validates the link and prints the exact payload bytes, which is useful
for protocol inspection:

```bash
ed2k-tool comment "ed2k://|file|shared.bin|1|00112233445566778899aabbccddeeff|/" --rating:5 --comment:verified
# file=00112233445566778899aabbccddeeff rating=5 comment=verified payload=05080000007665726966696564
```

With `--peer`, the command connects to the peer, performs the C2C handshake, sets the requested file
context, and sends `OP_FILEDESC` over the eMule protocol.

## `kad-bootstrap <nodes.dat>`

Load a KAD `nodes.dat`, create a local Kad2 UDP node, and bootstrap against the listed contacts.
Prints the loaded seed count, learned routing-table count, and bound UDP port.

```bash
ed2k-tool kad-bootstrap nodes.dat
# kad contacts: loaded=42 routing=17 udp_port=4672
```

## `kad-search <nodes.dat> <keyword>`

Bootstrap from `nodes.dat`, derive the Kad keyword target, and search the Kad network. Results are
printed as `kad-answer-id  size  name`.

```bash
ed2k-tool kad-search nodes.dat ubuntu
```

## `kad-find-sources <nodes.dat> <ed2k-link>`

Bootstrap from `nodes.dat` and ask Kad for sources of the file hash in the link. Direct HighID
sources are printed with IP, TCP/UDP ports, source type, and Kad answer ID.

```bash
ed2k-tool kad-find-sources nodes.dat "ed2k://|file|ubuntu.iso|...|/"
```

## `kad-publish <nodes.dat> <dir> [--port:n]`

Scan a local share directory and publish source + keyword records to the closest Kad contacts.
The indexer adds the publisher IP from the UDP sender endpoint, matching aMule Kad source publish
behavior.

- `--port:n` — TCP peer port advertised in `TAG_SOURCEPORT` (default: `4662`).

```bash
ed2k-tool kad-publish nodes.dat D:\share --port:4662
# kad published files=3 packets=12
```

## `download <ed2k-link> [--out:PATH] [--server:server.met]`

Download a file. Multi-source: the engine gathers sources from the server and downloads from
all of them concurrently (raccoon), with per-part MD4 verification and AICH corruption recovery.

- `--out:PATH` — output file path (default: the link's filename, or `download.bin`).
- `--server:server.met` — server list to login through. Omit to use the internal fallback list.

Download writes a sparse `PartFile` and an aMule-compatible sidecar. Normal output paths use
`<file>.part.met`; output paths that already end in `.part` use the sibling `<file>.part.met`
name (`001.part` -> `001.part.met`) so aMule temp files can be handed in or out. If the
download is interrupted, re-running the same command resumes: already-MD4-verified parts are
trusted from `.part.met` and skipped (no re-hash); partial parts are re-downloaded whole.

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
- `ED2K_SOURCE=ip:port` — live-test local aMule peer for direct download / SourceExchange checks.
- `ED2K_KAD_NODES=PATH` — live-test Kad bootstrap seed file for `LiveKad.*`.
- `ED2K_UPLOAD_FILE=PATH` and optional `ED2K_UPLOAD_PORT=n` — live upload-session harness: the test
  listens and waits for a real peer to request the file.
