#!/usr/bin/env python3
"""Passive Bitcoin Knots fork observer.

This program records peer-announced BLAKE2b blocks without performing proof of
work, transaction-script, merkle-root, or chain-selection validation. It only
parses enough structure to link a block to its parent and compare the legacy
100-block coinbase-maturity rule with Knots' temporary 6,480-block rule.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import random
import socket
import sqlite3
import struct
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "dist"
STATE_DIR = Path(
    os.environ.get("OBSERVER_STATE_DIR", str(Path.home() / ".local/state/knots-fork-observer"))
).expanduser()
BLOCK_DIR = STATE_DIR / "blocks"
DB_PATH = STATE_DIR / "observer.sqlite3"
LOG_PATH = STATE_DIR / "observer.log"

LISTEN_HOST = os.environ.get("OBSERVER_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("PORT", os.environ.get("OBSERVER_PORT", "8787")))
P2P_PORT = 8333
MAGIC = bytes.fromhex("f9beb4d9")
PROTOCOL_VERSION = 70016
NODE_NETWORK = 1
NODE_WITNESS = 1 << 3
NODE_BLAKE2B = 1 << 28
SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B
MSG_BLOCK = 2

ACTIVATION_HEIGHT = 973_440
RELEASE_HEIGHT = 979_920
LEGACY_MATURITY = 100
LONG_MATURITY = RELEASE_HEIGHT - ACTIVATION_HEIGHT
MAX_PEERS = int(os.environ.get("OBSERVER_MAX_PEERS", "8"))

SEEDS = (
    "x10000009.dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
    "x10000009.seed.bitcoin.haf.ovh",
)

stop_event = threading.Event()
download_queue: queue.Queue[tuple[str, int | None, str]] = queue.Queue()
queued_hashes: set[str] = set()
queue_lock = threading.Lock()


def log(message: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}"
    print(line, flush=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def init_db() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BLOCK_DIR.mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                hash TEXT PRIMARY KEY,
                prev_hash TEXT,
                height INTEGER,
                timestamp INTEGER,
                received_at INTEGER NOT NULL,
                peer TEXT,
                size INTEGER NOT NULL DEFAULT 0,
                legacy_maturity_ok INTEGER,
                long_maturity_ok INTEGER,
                maturity_note TEXT NOT NULL DEFAULT '',
                raw_path TEXT
            );
            CREATE INDEX IF NOT EXISTS blocks_height_idx ON blocks(height);
            CREATE INDEX IF NOT EXISTS blocks_prev_idx ON blocks(prev_hash);

            CREATE TABLE IF NOT EXISTS coinbases (
                txid TEXT PRIMARY KEY,
                height INTEGER NOT NULL,
                block_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS announcements (
                block_hash TEXT NOT NULL,
                peer TEXT NOT NULL,
                seen_at INTEGER NOT NULL,
                PRIMARY KEY(block_hash, peer)
            );

            CREATE TABLE IF NOT EXISTS peers (
                address TEXT PRIMARY KEY,
                connected INTEGER NOT NULL DEFAULT 0,
                services INTEGER,
                user_agent TEXT,
                start_height INTEGER,
                last_seen INTEGER,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )


def sha256d(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def compact_size(number: int) -> bytes:
    if number < 253:
        return bytes((number,))
    if number <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", number)
    if number <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", number)
    return b"\xff" + struct.pack("<Q", number)


def read_compact(payload: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(payload):
        raise ValueError("compact-size exceeds payload")
    first = payload[offset]
    offset += 1
    if first < 253:
        return first, offset
    if first == 253:
        if offset + 2 > len(payload):
            raise ValueError("short compact-size")
        return struct.unpack_from("<H", payload, offset)[0], offset + 2
    if first == 254:
        if offset + 4 > len(payload):
            raise ValueError("short compact-size")
        return struct.unpack_from("<I", payload, offset)[0], offset + 4
    if offset + 8 > len(payload):
        raise ValueError("short compact-size")
    return struct.unpack_from("<Q", payload, offset)[0], offset + 8


def varstr(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return compact_size(len(encoded)) + encoded


def net_addr(ip: str = "0.0.0.0", port: int = P2P_PORT) -> bytes:
    mapped = b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(ip)
    return struct.pack("<Q", SERVICES) + mapped + struct.pack(">H", port)


def make_message(command: str, payload: bytes = b"") -> bytes:
    encoded_command = command.encode("ascii").ljust(12, b"\x00")
    return MAGIC + encoded_command + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def version_payload() -> bytes:
    return (
        struct.pack("<iQq", PROTOCOL_VERSION, SERVICES, int(time.time()))
        + net_addr()
        + net_addr()
        + struct.pack("<Q", random.getrandbits(64))
        + varstr("/KnotsForkObserver:0.1/")
        + struct.pack("<i?", ACTIVATION_HEIGHT, False)
    )


def parse_version(payload: bytes) -> tuple[int, str, int]:
    if len(payload) < 80:
        return 0, "", 0
    services = struct.unpack_from("<Q", payload, 4)[0]
    user_length, offset = read_compact(payload, 80)
    user_agent = payload[offset : offset + user_length].decode("utf-8", "replace")
    offset += user_length
    start_height = struct.unpack_from("<i", payload, offset)[0] if offset + 4 <= len(payload) else 0
    return services, user_agent, start_height


def recv_exact(sock: socket.socket, amount: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < amount:
        chunk = sock.recv(amount - len(chunks))
        if not chunk:
            raise ConnectionError("peer closed connection")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_message(sock: socket.socket) -> tuple[str, bytes]:
    header = recv_exact(sock, 24)
    if header[:4] != MAGIC:
        raise ValueError("unexpected network magic")
    command = header[4:16].rstrip(b"\x00").decode("ascii", "replace")
    length = struct.unpack_from("<I", header, 16)[0]
    if length > 64 * 1024 * 1024:
        raise ValueError(f"oversized peer payload: {length}")
    expected_checksum = header[20:24]
    payload = recv_exact(sock, length)
    if sha256d(payload)[:4] != expected_checksum:
        raise ValueError("P2P framing checksum mismatch")
    return command, payload


def parse_inv(payload: bytes) -> list[tuple[int, str]]:
    count, offset = read_compact(payload, 0)
    inventory: list[tuple[int, str]] = []
    for _ in range(min(count, 50_000)):
        if offset + 36 > len(payload):
            break
        kind = struct.unpack_from("<I", payload, offset)[0]
        block_hash = payload[offset + 4 : offset + 36][::-1].hex()
        inventory.append((kind, block_hash))
        offset += 36
    return inventory


def parse_header(payload: bytes) -> dict[str, int | str]:
    if len(payload) < 80:
        raise ValueError("block shorter than base header")
    version = struct.unpack_from("<I", payload, 0)[0]
    is_v2 = bool(version & 0x80000000)
    header_size = 164 if is_v2 else 80
    if len(payload) < header_size:
        raise ValueError("block shorter than declared header")
    previous = payload[4:36][::-1].hex()
    wire_time = struct.unpack_from("<I", payload, 68)[0]
    if is_v2:
        time_offset = struct.unpack_from("<I", payload, 104)[0]
        flags = payload[110]
        height = struct.unpack_from("<i", payload, 128)[0]
        timestamp = (wire_time + time_offset) & 0xFFFFFFFF if flags & 4 else wire_time
    else:
        height = -1
        timestamp = wire_time
    return {
        "version": version,
        "is_v2": int(is_v2),
        "header_size": header_size,
        "prev_hash": previous,
        "height": height,
        "timestamp": timestamp,
    }


def parse_transaction(payload: bytes, offset: int) -> tuple[int, str, list[str], bool]:
    start = offset
    if offset + 4 > len(payload):
        raise ValueError("short transaction version")
    version_bytes = payload[offset : offset + 4]
    offset += 4
    segwit = offset + 2 <= len(payload) and payload[offset] == 0 and payload[offset + 1] != 0
    if segwit:
        offset += 2

    input_count, offset = read_compact(payload, offset)
    stripped = bytearray(version_bytes)
    stripped.extend(compact_size(input_count))
    input_hashes: list[str] = []
    coinbase = False
    for input_index in range(input_count):
        input_start = offset
        if offset + 36 > len(payload):
            raise ValueError("short transaction input")
        previous_raw = payload[offset : offset + 32]
        previous_txid = previous_raw[::-1].hex()
        previous_vout = struct.unpack_from("<I", payload, offset + 32)[0]
        offset += 36
        script_length, offset = read_compact(payload, offset)
        offset += script_length
        if offset + 4 > len(payload):
            raise ValueError("short transaction sequence")
        offset += 4
        stripped.extend(payload[input_start:offset])
        if input_index == 0 and previous_raw == b"\x00" * 32 and previous_vout == 0xFFFFFFFF:
            coinbase = True
        elif previous_raw != b"\x00" * 32:
            input_hashes.append(previous_txid)

    output_count, offset = read_compact(payload, offset)
    stripped.extend(compact_size(output_count))
    for _ in range(output_count):
        output_start = offset
        if offset + 8 > len(payload):
            raise ValueError("short transaction output")
        offset += 8
        script_length, offset = read_compact(payload, offset)
        offset += script_length
        stripped.extend(payload[output_start:offset])

    if segwit:
        for _ in range(input_count):
            item_count, offset = read_compact(payload, offset)
            for _ in range(item_count):
                item_length, offset = read_compact(payload, offset)
                offset += item_length

    if offset + 4 > len(payload):
        raise ValueError("short transaction locktime")
    locktime = payload[offset : offset + 4]
    offset += 4
    stripped.extend(locktime)

    if not segwit:
        raw_tx = payload[start:offset]
        txid = sha256d(raw_tx)[::-1].hex()
    else:
        txid = sha256d(bytes(stripped))[::-1].hex()
    return offset, txid, input_hashes, coinbase


def inspect_block(block_hash: str, payload: bytes) -> tuple[dict[str, int | str], str, list[str]]:
    header = parse_header(payload)
    offset = int(header["header_size"])
    tx_count, offset = read_compact(payload, offset)
    coinbase_txid = ""
    spent_txids: list[str] = []
    for tx_index in range(tx_count):
        offset, txid, inputs, is_coinbase = parse_transaction(payload, offset)
        if tx_index == 0 and is_coinbase:
            coinbase_txid = txid
        spent_txids.extend(inputs)
    return header, coinbase_txid, spent_txids


def maturity_labels(height: int, spent_txids: list[str]) -> tuple[int, int, str]:
    legacy_ok = True
    long_ok = True
    notes: list[str] = []
    if height < 0:
        return 1, 1, "Header height unavailable"
    with db() as connection:
        for txid in spent_txids:
            row = connection.execute("SELECT height FROM coinbases WHERE txid = ?", (txid,)).fetchone()
            if row is None:
                continue
            coinbase_height = int(row["height"])
            age = height - coinbase_height
            if age < LEGACY_MATURITY:
                legacy_ok = False
                long_ok = False
                notes.append(f"coinbase {coinbase_height} spent at age {age}: rejected by both maturity rules")
            elif ACTIVATION_HEIGHT <= coinbase_height and height < RELEASE_HEIGHT and age < LONG_MATURITY:
                long_ok = False
                notes.append(f"coinbase {coinbase_height} spent at age {age}: legacy accepts, long maturity rejects")
    return int(legacy_ok), int(long_ok), "; ".join(notes)


def record_announcement(block_hash: str, peer: str) -> None:
    now = int(time.time())
    with db() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO announcements(block_hash, peer, seen_at) VALUES(?, ?, ?)",
            (block_hash, peer, now),
        )


def already_downloaded(block_hash: str) -> bool:
    with db() as connection:
        row = connection.execute("SELECT raw_path FROM blocks WHERE hash = ?", (block_hash,)).fetchone()
        return bool(row and row["raw_path"])


def enqueue_block(block_hash: str, height: int | None, source: str) -> None:
    if already_downloaded(block_hash):
        return
    with queue_lock:
        if block_hash in queued_hashes:
            return
        queued_hashes.add(block_hash)
    download_queue.put((block_hash, height, source))


def store_block(block_hash: str, expected_height: int | None, peer: str, payload: bytes) -> None:
    try:
        header, coinbase_txid, spent_txids = inspect_block(block_hash, payload)
        height = int(header["height"])
        if height < 0 and expected_height is not None:
            height = expected_height
        legacy_ok, long_ok, note = maturity_labels(height, spent_txids)
        raw_path = BLOCK_DIR / f"{block_hash}.blk"
        raw_path.write_bytes(payload)
        with db() as connection:
            connection.execute(
                """
                INSERT INTO blocks(hash, prev_hash, height, timestamp, received_at, peer, size,
                                   legacy_maturity_ok, long_maturity_ok, maturity_note, raw_path)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hash) DO UPDATE SET
                    prev_hash=excluded.prev_hash,
                    height=excluded.height,
                    timestamp=excluded.timestamp,
                    received_at=excluded.received_at,
                    peer=excluded.peer,
                    size=excluded.size,
                    legacy_maturity_ok=excluded.legacy_maturity_ok,
                    long_maturity_ok=excluded.long_maturity_ok,
                    maturity_note=excluded.maturity_note,
                    raw_path=excluded.raw_path
                """,
                (
                    block_hash,
                    str(header["prev_hash"]),
                    height,
                    int(header["timestamp"]),
                    int(time.time()),
                    peer,
                    len(payload),
                    legacy_ok,
                    long_ok,
                    note,
                    str(raw_path),
                ),
            )
            if coinbase_txid:
                connection.execute(
                    "INSERT OR REPLACE INTO coinbases(txid, height, block_hash) VALUES(?, ?, ?)",
                    (coinbase_txid, height, block_hash),
                )
        if legacy_ok != long_ok:
            log(f"RULE SPLIT observed at height {height}: {block_hash} — {note}")
        else:
            log(f"stored peer block height={height} hash={block_hash[:16]}… bytes={len(payload)} peer={peer}")
    except Exception as error:
        log(f"could not parse block {block_hash[:16]}… from {peer}: {error}")
    finally:
        with queue_lock:
            queued_hashes.discard(block_hash)


def update_peer(address: str, **values: Any) -> None:
    allowed = {"connected", "services", "user_agent", "start_height", "last_seen", "last_error"}
    values = {key: value for key, value in values.items() if key in allowed}
    if not values:
        return
    columns = ", ".join(f"{key} = ?" for key in values)
    params = list(values.values()) + [address]
    with db() as connection:
        connection.execute("INSERT OR IGNORE INTO peers(address) VALUES(?)", (address,))
        connection.execute(f"UPDATE peers SET {columns} WHERE address = ?", params)


def request_block(sock: socket.socket, block_hash: str) -> None:
    inventory = compact_size(1) + struct.pack("<I", MSG_BLOCK) + bytes.fromhex(block_hash)[::-1]
    sock.sendall(make_message("getdata", inventory))


class PeerWorker(threading.Thread):
    def __init__(self, ip: str):
        super().__init__(name=f"peer-{ip}", daemon=True)
        self.ip = ip
        self.address = f"{ip}:{P2P_PORT}"

    def next_request(self) -> tuple[str, int | None, str] | None:
        try:
            return download_queue.get_nowait()
        except queue.Empty:
            return None

    def run(self) -> None:
        delay = 5
        while not stop_event.is_set():
            update_peer(self.address, connected=0, last_error="connecting")
            try:
                self.session()
                delay = 5
            except Exception as error:
                update_peer(
                    self.address,
                    connected=0,
                    last_seen=int(time.time()),
                    last_error=str(error)[:240],
                )
                log(f"peer {self.address} disconnected: {error}")
            stop_event.wait(delay)
            delay = min(delay * 2, 120)

    def session(self) -> None:
        pending: tuple[str, int | None, str] | None = None
        with socket.create_connection((self.ip, P2P_PORT), timeout=8) as sock:
            sock.settimeout(2)
            sock.sendall(make_message("version", version_payload()))
            handshaken = False
            update_peer(self.address, connected=1, last_seen=int(time.time()), last_error="")
            log(f"connected peer {self.address}")
            while not stop_event.is_set():
                if handshaken and pending is None:
                    pending = self.next_request()
                    if pending:
                        request_block(sock, pending[0])
                try:
                    command, payload = recv_message(sock)
                except socket.timeout:
                    continue
                update_peer(self.address, connected=1, last_seen=int(time.time()))
                if command == "version":
                    services, user_agent, start_height = parse_version(payload)
                    update_peer(
                        self.address,
                        services=services,
                        user_agent=user_agent,
                        start_height=start_height,
                    )
                    sock.sendall(make_message("verack"))
                elif command == "verack":
                    handshaken = True
                    sock.sendall(make_message("sendheaders"))
                    sock.sendall(make_message("getaddr"))
                elif command == "ping":
                    sock.sendall(make_message("pong", payload))
                elif command == "inv":
                    for kind, announced_hash in parse_inv(payload):
                        if kind & 0x3FFFFFFF != MSG_BLOCK:
                            continue
                        record_announcement(announced_hash, self.address)
                        enqueue_block(announced_hash, None, "inv")
                elif command == "block":
                    if pending is None:
                        log(f"unsolicited block payload from {self.address} ignored (no announced hash correlation)")
                        continue
                    store_block(pending[0], pending[1], self.address, payload)
                    download_queue.task_done()
                    pending = None
                elif command == "notfound" and pending is not None:
                    with queue_lock:
                        queued_hashes.discard(pending[0])
                    download_queue.task_done()
                    pending = None


def fetch_text(url: str, timeout: int = 10) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "KnotsForkObserver/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8").strip()


def bootstrap_backfill() -> None:
    while not stop_event.is_set():
        try:
            tip = int(fetch_text("https://mempool.guide/api/blocks/tip/height"))
            with db() as connection:
                connection.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('guide_tip', ?)", (str(tip),))
                connection.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('guide_tip_time', ?)", (str(int(time.time())),))
            start = ACTIVATION_HEIGHT
            for height in range(start, tip + 1):
                if stop_event.is_set():
                    return
                with db() as connection:
                    row = connection.execute("SELECT raw_path FROM blocks WHERE height = ? AND raw_path IS NOT NULL", (height,)).fetchone()
                if row:
                    continue
                block_hash = fetch_text(f"https://mempool.guide/api/block-height/{height}")
                enqueue_block(block_hash, height, "mempool.guide index")
                time.sleep(0.05)
            time.sleep(15)
        except (OSError, ValueError, urllib.error.URLError) as error:
            log(f"mempool.guide indexing error: {error}")
            stop_event.wait(30)


def discover_peers() -> list[str]:
    addresses: list[str] = []
    for seed in SEEDS:
        try:
            results = socket.getaddrinfo(seed, P2P_PORT, socket.AF_INET, socket.SOCK_STREAM)
            for result in results:
                address = result[4][0]
                if address not in addresses:
                    addresses.append(address)
        except OSError as error:
            log(f"DNS seed {seed} failed: {error}")
    random.shuffle(addresses)
    return addresses[:MAX_PEERS]


def branch_data(connection: sqlite3.Connection) -> dict[str, Any]:
    rows = connection.execute(
        """
        SELECT hash, prev_hash, height, timestamp, received_at, peer, size,
               legacy_maturity_ok, long_maturity_ok, maturity_note
        FROM blocks
        WHERE height >= ?
        ORDER BY height DESC, received_at DESC
        LIMIT 240
        """,
        (ACTIVATION_HEIGHT,),
    ).fetchall()
    blocks = [dict(row) for row in rows]
    hashes = {row["hash"] for row in blocks}
    parents = {row["prev_hash"] for row in blocks}
    tips = [row for row in blocks if row["hash"] not in parents]
    children: dict[str, list[str]] = defaultdict(list)
    for row in blocks:
        children[row["prev_hash"]].append(row["hash"])
    forks = [
        {"parent": parent, "children": child_hashes}
        for parent, child_hashes in children.items()
        if len(child_hashes) > 1
    ]
    return {"blocks": blocks, "tips": tips[:12], "forks": forks, "known_hashes": len(hashes)}


def status_payload() -> dict[str, Any]:
    with db() as connection:
        peer_rows = connection.execute(
            "SELECT address, connected, services, user_agent, start_height, last_seen, last_error FROM peers ORDER BY connected DESC, last_seen DESC"
        ).fetchall()
        counts = connection.execute(
            """
            SELECT COUNT(*) AS blocks,
                   COALESCE(SUM(size), 0) AS bytes,
                   MAX(height) AS max_height,
                   SUM(CASE WHEN legacy_maturity_ok != long_maturity_ok THEN 1 ELSE 0 END) AS rule_splits
            FROM blocks
            """
        ).fetchone()
        announcements = connection.execute("SELECT COUNT(*) AS count FROM announcements").fetchone()["count"]
        meta = {row["key"]: row["value"] for row in connection.execute("SELECT key, value FROM meta")}
        branches = branch_data(connection)
    peers = [dict(row) for row in peer_rows]
    return {
        "observer": {
            "mode": "passive-unvalidated",
            "started": int(PROCESS_STARTED),
            "activation_height": ACTIVATION_HEIGHT,
            "release_height": RELEASE_HEIGHT,
            "legacy_maturity": LEGACY_MATURITY,
            "long_maturity": LONG_MATURITY,
            "guide_tip": int(meta.get("guide_tip", 0)),
            "guide_tip_time": int(meta.get("guide_tip_time", 0)),
        },
        "counts": {
            "blocks": int(counts["blocks"] or 0),
            "bytes": int(counts["bytes"] or 0),
            "max_height": int(counts["max_height"] or 0),
            "rule_splits": int(counts["rule_splits"] or 0),
            "announcements": int(announcements or 0),
            "connected_peers": sum(1 for peer in peers if peer["connected"]),
        },
        "peers": peers,
        "chain": branches,
        "updated_at": int(time.time()),
    }


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, format_string: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/api/status":
            payload = json.dumps(status_payload(), separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/health":
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        super().do_GET()


PROCESS_STARTED = time.time()


def main() -> None:
    init_db()
    peers = discover_peers()
    log(f"starting passive observer with {len(peers)} peer candidates")
    threading.Thread(target=bootstrap_backfill, name="backfill", daemon=True).start()
    for address in peers:
        PeerWorker(address).start()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), DashboardHandler)
    log(f"dashboard listening on http://{LISTEN_HOST}:{LISTEN_PORT}")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.server_close()


if __name__ == "__main__":
    main()
