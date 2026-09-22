# Knots Fork Observer

Local passive observer for the BLAKE2b Bitcoin peer network. It stores raw peer blocks without consensus validation and compares only the legacy 100-block coinbase maturity with Knots' temporary 6,480-block maturity rule.

Dashboard: <http://127.0.0.1:8787>

Persistent state and raw blocks are stored under `~/.local/state/knots-fork-observer/`.

The observer does **not** determine which chain is Bitcoin, validate proof of work, execute scripts, verify merkle roots, or select a winning chain. It retains peer-observed competing descendants so both branches can be displayed.

## Render deployment

The included `render.yaml` deploys a Docker web service in Render's Singapore region with a 10 GB persistent disk. Render supplies `PORT`; the container listens on `0.0.0.0` and stores its database, log, and raw blocks beneath `/var/data/knots-fork-observer`.

1. Push this directory to a GitHub repository.
2. In Render, choose **New → Blueprint** and connect that repository.
3. Review the proposed `knots-fork-observer` Starter service and persistent disk, then apply it.
4. Wait for `/api/health` to pass and open the generated `onrender.com` URL.
5. Under the service's **Settings → Custom Domains**, add `lukecoin.zndtoshi.com`.
6. Add the DNS record Render displays at the DNS provider for `zndtoshi.com`; normally this is a `CNAME` for host `lukecoin` pointing to the generated Render hostname.

Do not deploy this without its persistent disk: Render instances have an ephemeral root filesystem and a restart would otherwise discard the block archive and SQLite database.

Supported environment variables:

- `PORT`: HTTP port supplied by Render.
- `OBSERVER_HOST`: bind address; the image defaults to `0.0.0.0`.
- `OBSERVER_STATE_DIR`: persistent data directory.
- `OBSERVER_MAX_PEERS`: maximum peer connections, default `8`.
