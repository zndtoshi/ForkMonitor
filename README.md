# ForkMonitor — live fork watch and historical archive

Dashboard: <https://lukecoin.zndtoshi.com>
Source: <https://github.com/zndtoshi/ForkMonitor>

## New rule: 180-day rolling coinbase maturity

The primary graph watches the approach to block **979,919**, then competing
BLAKE2b descendants under Knots 29.4.3's **25,920-block** reward maturity rule.
Coverage ends for new rewards when their mining block's **parent median time
past** reaches **1 September 2027, 00:00 UTC**. Rewards covered before that
cutoff must still complete their full wait afterward. Earlier historical
6,480-block consensus rules remain applicable through spending height 979,919.

The live observer collects blocks starting at 979,199, with eleven earlier
headers for timestamp context. It does not load September's frozen data into
its live database. Live state uses `/var/data/knots-fork-observer-180d`; the
original state directory and archived JSON are preserved.

It connects to at most four BLAKE2b-capable peers. Block discovery follows P2P
inventory announcements; mempool.guide supplies height-to-hash backfill hints,
while raw block payloads come from peers. Late parent downloads recheck stored
descendants. Coinbase checks use branch ancestry and the mining-parent median
timestamp. Missing known ancestry is shown as pending. Peer version labels are
self-reported hints, not proof that the peer enforces a rule.

The split counter counts stored parents with multiple observed children across
all retained blocks. It does not equate every branch point with a consensus
failure. The live graph contains up to 1,200 recent blocks, and its zoomable
history view up to 12,000 recent blocks. The persistent total does not reset
when an older split leaves either view.

## Historical rule: 45-day maturity, 21–22 September 2026

Rule introduced at block **973,440 on 21 September 2026**. The archive ends on
**22 September 2026 at 18:24:47 Gulf Standard Time (UTC+4)**.

**8 recorded chain splits**, **9 maturity-rule disagreement blocks**, **201
observed blocks**, and the original 62-peer snapshot are preserved. The graph
is below the live monitor, with a prominent split count and a standalone view
at `/archive.html`. Its full-history zoom and pan controls remain available.

`dist/snapshot.json` is unchanged. SHA-256:
`7e6dfdd091e2b587f6f747ad2f1410c015baa6c11ea6667beffc796aebd08188`

## Hosting and operation

The existing free Render static site serves `dist/` at the public dashboard.
`render.yaml` retains static hosting. The page polls the existing Docker
service at `https://knots-fork-observer.onrender.com`; the observer permits
cross-origin reads from the dashboard's explicit public origins. It does not
send credentials. If the backend is suspended, the live panel says unavailable
and the frozen archive remains usable.

`render.live.yaml` documents the existing Docker service and its retained
10 GB disk. It is a deployment reference, not an instruction to create another
service or automatically resume paid compute. Configure the existing service:

- `OBSERVER_ARCHIVE_MODE=0`
- `OBSERVER_STATE_DIR=/var/data/knots-fork-observer-180d`
- `OBSERVER_MAX_PEERS=4`
- Dockerfile at repository root; health path `/api/health`.

The Dockerfile retains archive mode as the safe default. Enabling live mode is
explicit. Never reuse the old database directory: the new database tracks
coinbases by `(txid, block_hash)` and retains input IDs for late rechecks.
The static frontend and live Docker service are deployed separately.

Local preview (only while actively testing):

```sh
OBSERVER_ARCHIVE_MODE=0 OBSERVER_STATE_DIR=/path/to/scratch-state python3 observer.py
```

Stop the local process after verification. The old local user service should
remain disabled; production collection belongs on Render.

## Verification

```sh
python3 -m unittest -v test_observer
```

Regression coverage includes activation, exact maturity depth, old-rule release,
expiry at mining-parent MTP, post-expiry rewards, pre-expiry rewards remaining
locked, sibling-branch coinbases, incomplete ancestry, persistent split counts,
closed SQLite connections, interrupted peer requests and frozen-data integrity.

This is a passive observer. It does **not** validate proof of work, transaction
scripts, merkle roots or all UTXO spends, and does not choose a canonical chain.
“No observed conflict” never means that the block is fully consensus-valid.
