# Knots Fork Observer — Historical Snapshot

Frozen public archive of the BLAKE2b Bitcoin Knots fork observation captured on
2026-09-22 at 18:24:47 Gulf Standard Time.

Dashboard: <https://lukecoin.zndtoshi.com>

Source repository: <https://github.com/zndtoshi/ForkMonitor>

The archive contains 201 observed blocks from heights 973,440 through 973,630,
including eight recorded branch points, nine maturity-rule disagreements, miner
labels, and the 62-peer software-version snapshot visible at capture time. The
interactive whole-history view remains zoomable and pannable.

## Network activity

There is none. This version is a Render static site:

- no peer connections;
- no DNS-seed discovery;
- no block downloads;
- no mempool.guide polling;
- no server process, database, or persistent disk;
- no periodic browser polling.

The immutable production data is stored in `dist/snapshot.json`. The browser
loads it once and performs all chart rendering locally.

The small `Dockerfile` is an archive-only migration fallback for the existing
Render service. It can only serve the files in `dist/`; it contains no observer
code and opens no peer connections. The final Blueprint uses static hosting and
does not run the container.

## Render deployment

`render.yaml` defines a static site that publishes `dist/`. Future commits can
redeploy the archived interface, but the chain data will not change unless
`dist/snapshot.json` is deliberately replaced.

This archive does **not** determine which chain is Bitcoin, validate proof of
work, execute scripts, verify merkle roots, or select a winning chain. It shows
the peer-observed history retained by the former passive observer.
