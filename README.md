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
- no active observer process, database access, or persistent disk;
- no periodic browser polling.

The immutable production data is stored in `dist/snapshot.json`. The browser
loads it once and performs all chart rendering locally.

The complete monitor implementation remains in `observer.py`. Archive mode is
the safe default and serves the snapshot without initializing the database,
resolving seeds, starting peer workers, polling mempool.guide, or downloading
blocks. The `Dockerfile` also sets `OBSERVER_ARCHIVE_MODE=1`. The final Render
Blueprint uses static hosting and does not run the container at all.

## Restarting the live monitor later

Set `OBSERVER_ARCHIVE_MODE=0`, restore a writable state directory, and deploy
the Docker service configuration. This re-enables the existing discovery,
peer, block-download, database, and API code; nothing needs to be recreated.

## Render deployment

`render.yaml` defines a static site that publishes `dist/`. Future commits can
redeploy the archived interface, but the chain data will not change unless
`dist/snapshot.json` is deliberately replaced.

This archive does **not** determine which chain is Bitcoin, validate proof of
work, execute scripts, verify merkle roots, or select a winning chain. It shows
the peer-observed history retained by the former passive observer.
