#!/usr/bin/env python3
"""Passive Bitcoin Knots fork observer.

This program records peer-announced BLAKE2b blocks without performing proof of
work, transaction-script, merkle-root, or chain-selection validation. It only
parses enough structure to link a block to its parent and compare the earlier maturity rules with the rolling 25,920-block rule.
The immutable September capture is served separately from live state.
"""

from __future__ import annotations

from contextlib import contextmanager

import hashlib
import ipaddress
import json
import os
import queue
import random
import re
import socket
import sqlite3
import struct
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from collections import defaultdict
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "dist"
STATE_DIR = Path(
    os.environ.get("OBSERVER_STATE_DIR", str(Path.home() / ".local/state/knots-fork-observer-180d"))
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

HISTORICAL_START = 973_440
HISTORICAL_RELEASE = 979_920
ACTIVATION_HEIGHT = 979_919
# Collect context before activation, without importing the frozen archive.
START_HEIGHT = ACTIVATION_HEIGHT - 720
RELEASE_HEIGHT = None  # Rolling coverage ends by parent MTP, never a fixed height.
RDTS_EXPIRY = 1_819_756_800  # 2027-09-01 00:00 UTC
LEGACY_MATURITY = 100
LONG_MATURITY = 25_920
NEW_RULE_KNOTS_VERSION = (29, 4, 3)
MAX_PEERS = max(1, min(8, int(os.environ.get("OBSERVER_MAX_PEERS", "8"))))
ARCHIVE_MODE = os.environ.get("OBSERVER_ARCHIVE_MODE", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}

SEEDS = (
    "x10000009.dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
    "x10000009.seed.bitcoin.haf.ovh",
)

stop_event = threading.Event()
download_queue: queue.Queue[tuple[str, int | None, str]] = queue.Queue(maxsize=2048)
queued_hashes: set[str] = set()
queue_lock = threading.Lock()
peer_workers_lock = threading.Lock()
peer_workers: dict[str, "PeerWorker"] = {}


class UnsupportedPeer(ConnectionError):
    """The remote peer does not advertise the BLAKE2b network service."""


def log(message: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}"
    print(line, flush=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BLOCK_DIR.mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
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
                miner_tag TEXT NOT NULL DEFAULT '',
                raw_path TEXT
            );
            CREATE INDEX IF NOT EXISTS blocks_height_idx ON blocks(height);
            CREATE INDEX IF NOT EXISTS blocks_prev_idx ON blocks(prev_hash);

            CREATE TABLE IF NOT EXISTS coinbases (
                txid TEXT NOT NULL,
                height INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                PRIMARY KEY(txid, block_hash)
            );
            CREATE TABLE IF NOT EXISTS block_inputs (
                block_hash TEXT NOT NULL,
                txid TEXT NOT NULL,
                PRIMARY KEY(block_hash, txid)
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
        columns = {row[1] for row in connection.execute("PRAGMA table_info(blocks)")}
        if "miner_tag" not in columns:
            connection.execute("ALTER TABLE blocks ADD COLUMN miner_tag TEXT NOT NULL DEFAULT ''")


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


def parse_addr(payload: bytes) -> list[tuple[str, int, int]]:
    """Parse public IP peers from the legacy P2P addr message."""
    count, offset = read_compact(payload, 0)
    if count > 1000:
        raise ValueError(f"oversized addr message: {count} entries")
    addresses: list[tuple[str, int, int]] = []
    for _ in range(count):
        if offset + 30 > len(payload):
            break
        services = struct.unpack_from("<Q", payload, offset + 4)[0]
        raw_ip = payload[offset + 12 : offset + 28]
        port = struct.unpack_from(">H", payload, offset + 28)[0]
        offset += 30
        parsed_ip = ipaddress.ip_address(raw_ip)
        if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped:
            parsed_ip = parsed_ip.ipv4_mapped
        if parsed_ip.is_global and 0 < port < 65536:
            addresses.append((str(parsed_ip), port, services))
    return addresses


def peer_rule_set(user_agent: str | None) -> str:
    """Classify a peer by the full Knots version in its version message."""
    if not user_agent:
        return "unknown"

    # Self-reported versions suggest support; they do not prove enforcement.
    # The rolling rule ships in 29.4.3, not 29.4.2.
    if "/Knots:" in user_agent:
        version = re.search(r"/Satoshi:(\d+)\.(\d+)\.(\d+)", user_agent)
        if not version:
            return "unknown"
        parsed_version = tuple(int(part) for part in version.groups())
        return "new" if parsed_version >= NEW_RULE_KNOTS_VERSION else "legacy"
    return "unknown"


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
    if length > 8 * 1024 * 1024:
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


def coinbase_identifier(script: bytes) -> str:
    """Extract human-readable pool identification from a coinbase scriptSig."""
    if not script:
        return ""
    push_length = script[0]
    if 1 <= push_length <= 75 and 1 + push_length <= len(script):
        script = script[1 + push_length :]
    decoded = script.decode("utf-8", "ignore")
    cleaned = "".join(
        character if character.isprintable() and unicodedata.category(character)[0] != "C" else " "
        for character in decoded
    )
    cleaned = " ".join(cleaned.split()).strip(" \x00")
    pipe_tags = [match.strip() for match in re.findall(r"\|([^|]{3,80})\|", cleaned)]
    slash_tags = [match.strip() for match in re.findall(r"/([^/]{3,80})/", cleaned)]
    if pipe_tags:
        cleaned = " | ".join(pipe_tags)
    elif slash_tags:
        cleaned = " / ".join(slash_tags)
    words: list[str] = []
    for word in cleaned.strip(" |/^~").split():
        if word.startswith("|") and len(word) <= 4:
            continue
        if words and words[-1].casefold() == word.casefold():
            continue
        words.append(word)
    return " ".join(words)[:120]


def parse_transaction(payload: bytes, offset: int) -> tuple[int, str, list[str], bool, str]:
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
    miner_tag = ""
    for input_index in range(input_count):
        input_start = offset
        if offset + 36 > len(payload):
            raise ValueError("short transaction input")
        previous_raw = payload[offset : offset + 32]
        previous_txid = previous_raw[::-1].hex()
        previous_vout = struct.unpack_from("<I", payload, offset + 32)[0]
        offset += 36
        script_length, offset = read_compact(payload, offset)
        input_script = payload[offset : offset + script_length]
        offset += script_length
        if offset + 4 > len(payload):
            raise ValueError("short transaction sequence")
        offset += 4
        stripped.extend(payload[input_start:offset])
        if input_index == 0 and previous_raw == b"\x00" * 32 and previous_vout == 0xFFFFFFFF:
            coinbase = True
            miner_tag = coinbase_identifier(input_script)
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
    return offset, txid, input_hashes, coinbase, miner_tag


def inspect_block(block_hash: str, payload: bytes) -> tuple[dict[str, int | str], str, str, list[str]]:
    header = parse_header(payload)
    offset = int(header["header_size"])
    tx_count, offset = read_compact(payload, offset)
    coinbase_txid = ""
    miner_tag = ""
    spent_txids: list[str] = []
    for tx_index in range(tx_count):
        offset, txid, inputs, is_coinbase, transaction_miner_tag = parse_transaction(payload, offset)
        if tx_index == 0 and is_coinbase:
            coinbase_txid = txid
            miner_tag = transaction_miner_tag
        spent_txids.extend(inputs)
    return header, coinbase_txid, miner_tag, spent_txids


def maturity_labels(height: int, spent_txids: list[str], parent_hash: str = "") -> tuple[int | None, int | None, str]:
    """Compare observed coinbase spends on this branch, never a full validation.

    Unknown txids may be ordinary inputs or unobserved coinbases. Never infer
    global validity from absence of a conflict in this partial block archive.
    """
    if height < 0:
        return None, None, "Header height unavailable"
    previous_ok, rolling_ok = True, True
    notes = []
    with db() as connection:
        candidates = []
        for txid in set(spent_txids):
            candidates.extend(connection.execute(
                "SELECT txid,height,block_hash FROM coinbases WHERE txid=?", (txid,)).fetchall())
        if not candidates:
            return 1, 1, "No observed coinbase-maturity conflict (partial observation)"
        lowest = min(int(row["height"]) for row in candidates) - 11
        ancestry = connection.execute("""
            WITH RECURSIVE ancestors AS (
                SELECT hash,prev_hash,height,timestamp FROM blocks WHERE hash=?
                UNION ALL
                SELECT b.hash,b.prev_hash,b.height,b.timestamp FROM blocks b
                JOIN ancestors a ON b.hash=a.prev_hash
                WHERE b.height=a.height-1 AND b.height>=?
            ) SELECT * FROM ancestors
        """, (parent_hash, lowest)).fetchall()
        by_hash = {row["hash"]: row for row in ancestry}
        ancestry_min = min((row["height"] for row in ancestry), default=height)
        unknown = False
        for coin in candidates:
            mined_height = int(coin["height"])
            mined = by_hash.get(coin["block_hash"])
            if not mined:
                # A known reward on a sibling branch is not an ancestor spend.
                if ancestry_min > mined_height:
                    unknown = True
                continue
            age = height - mined_height
            previous_required = (6480 if HISTORICAL_START <= mined_height
                                 and height < HISTORICAL_RELEASE else LEGACY_MATURITY)
            required = previous_required
            if height >= ACTIVATION_HEIGHT and mined_height >= ACTIVATION_HEIGHT:
                timestamps = []
                cursor = by_hash.get(mined["prev_hash"])
                for _ in range(11):
                    if cursor is None:
                        break
                    timestamps.append(cursor["timestamp"])
                    cursor = by_hash.get(cursor["prev_hash"])
                if len(timestamps) < 11:
                    unknown = True
                    continue
                mining_parent_mtp = sorted(timestamps)[len(timestamps)//2]
                if mining_parent_mtp < RDTS_EXPIRY:
                    required = LONG_MATURITY
            previous_ok = previous_ok and age >= previous_required
            rolling_ok = rolling_ok and age >= required
            if age < required or age < previous_required:
                notes.append(f"coinbase #{mined_height} spent at depth {age}: previous needs {previous_required}, rolling needs {required}")
        if unknown:
            notes.append("Some coinbase ancestry or mining-parent timestamps are missing; check pending")
    return (int(previous_ok) if not unknown or not previous_ok else None,
            int(rolling_ok) if not unknown or not rolling_ok else None,
            "; ".join(notes) or "No observed coinbase-maturity conflict (partial observation)")


def recheck_descendants(parent_hash: str) -> None:
    """Late parent downloads must correct earlier incomplete classifications."""
    pending = [parent_hash]
    seen = set()
    while pending:
        parent = pending.pop()
        if parent in seen:
            continue
        seen.add(parent)
        with db() as connection:
            children = connection.execute("SELECT hash,height,prev_hash FROM blocks WHERE prev_hash=?", (parent,)).fetchall()
        for child in children:
            with db() as connection:
                inputs = [row[0] for row in connection.execute("SELECT txid FROM block_inputs WHERE block_hash=?", (child["hash"],))]
            previous, rolling, note = maturity_labels(child["height"], inputs, child["prev_hash"])
            with db() as connection:
                connection.execute("UPDATE blocks SET legacy_maturity_ok=?,long_maturity_ok=?,maturity_note=? WHERE hash=?",
                                   (previous, rolling, note, child["hash"]))
            pending.append(child["hash"])


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
        try:
            download_queue.put_nowait((block_hash, height, source))
        except queue.Full:
            return  # The bounded backfill scan retries missing heights later.
        queued_hashes.add(block_hash)


def store_block(block_hash: str, expected_height: int | None, peer: str, payload: bytes) -> None:
    try:
        header, coinbase_txid, miner_tag, spent_txids = inspect_block(block_hash, payload)
        height = int(header["height"])
        if height < 0 and expected_height is not None:
            height = expected_height
        if height < START_HEIGHT - 11:
            return
        legacy_ok, long_ok, note = maturity_labels(height, spent_txids, str(header["prev_hash"]))
        if not re.fullmatch(r"[0-9a-f]{64}", block_hash):
            raise ValueError("invalid announced block hash")
        if expected_height is not None and height != expected_height:
            raise ValueError("block height disagrees with requested height")
        raw_path = BLOCK_DIR / f"{block_hash}.blk"
        raw_path.write_bytes(payload)
        with db() as connection:
            connection.execute(
                """
                INSERT INTO blocks(hash, prev_hash, height, timestamp, received_at, peer, size,
                                   legacy_maturity_ok, long_maturity_ok, maturity_note, miner_tag, raw_path)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    miner_tag=excluded.miner_tag,
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
                    miner_tag,
                    str(raw_path),
                ),
            )
            if coinbase_txid:
                connection.execute(
                    "INSERT OR REPLACE INTO coinbases(txid, height, block_hash) VALUES(?, ?, ?)",
                    (coinbase_txid, height, block_hash),
                )
            connection.executemany("INSERT OR IGNORE INTO block_inputs(block_hash,txid) VALUES(?,?)",
                                   ((block_hash, txid) for txid in set(spent_txids)))
        if height > START_HEIGHT - 11:
            enqueue_block(str(header["prev_hash"]), height - 1, "missing parent")
        recheck_descendants(block_hash)
        if legacy_ok is not None and long_ok is not None and legacy_ok != long_ok:
            log(f"RULE SPLIT observed at height {height}: {block_hash} — {note}")
        else:
            log(f"stored peer block height={height} hash={block_hash[:16]}… bytes={len(payload)} peer={peer}")
    except Exception as error:
        log(f"could not parse block {block_hash[:16]}… from {peer}: {error}")
    finally:
        with queue_lock:
            queued_hashes.discard(block_hash)


def backfill_miner_tags() -> None:
    with db() as connection:
        version_row = connection.execute(
            "SELECT value FROM meta WHERE key = 'miner_tag_parser_version'"
        ).fetchone()
        refresh_all = version_row is None or version_row["value"] != "2"
        rows = connection.execute(
            "SELECT hash, raw_path FROM blocks WHERE raw_path IS NOT NULL"
            if refresh_all
            else "SELECT hash, raw_path FROM blocks WHERE miner_tag = '' AND raw_path IS NOT NULL"
        ).fetchall()
    updated = 0
    for row in rows:
        try:
            raw_path = Path(row["raw_path"])
            if not raw_path.is_file():
                continue
            _, _, miner_tag, _ = inspect_block(row["hash"], raw_path.read_bytes())
            with db() as connection:
                connection.execute("UPDATE blocks SET miner_tag = ? WHERE hash = ?", (miner_tag, row["hash"]))
            updated += 1
        except Exception as error:
            log(f"could not backfill miner tag for {row['hash'][:16]}…: {error}")
    if updated:
        log(f"backfilled coinbase miner tags for {updated} stored blocks")
    with db() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('miner_tag_parser_version', '2')"
        )


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
    def __init__(self, ip: str, port: int = P2P_PORT):
        super().__init__(name=f"peer-{ip}-{port}", daemon=True)
        self.ip = ip
        self.port = port
        self.address = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

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
            except UnsupportedPeer as error:
                update_peer(
                    self.address,
                    connected=0,
                    last_seen=int(time.time()),
                    last_error=str(error)[:240],
                )
                log(f"ignored non-BLAKE2b peer {self.address}: {error}")
                with peer_workers_lock:
                    peer_workers.pop(self.address, None)
                return
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
        try:
            self._session()
        finally:
            pending = getattr(self, "pending_request", None)
            if pending:
                with queue_lock:
                    queued_hashes.discard(pending[0])
                download_queue.task_done()
                self.pending_request = None

    def _session(self) -> None:
        pending = None
        requested_at = 0.0
        with socket.create_connection((self.ip, self.port), timeout=8) as sock:
            sock.settimeout(2)
            sock.sendall(make_message("version", version_payload()))
            handshaken = False
            while not stop_event.is_set():
                if handshaken and pending is None:
                    pending = self.next_request()
                    if pending:
                        self.pending_request = pending
                        requested_at = time.monotonic()
                        request_block(sock, pending[0])
                if pending and time.monotonic() - requested_at > 30:
                    raise TimeoutError("peer block response timed out")
                try:
                    command, payload = recv_message(sock)
                except socket.timeout:
                    continue
                update_peer(self.address, last_seen=int(time.time()))
                if command == "version":
                    services, user_agent, start_height = parse_version(payload)
                    if not services & NODE_BLAKE2B:
                        raise UnsupportedPeer(
                            f"handshake services {services:#x} do not include NODE_BLAKE2B"
                        )
                    update_peer(
                        self.address,
                        connected=1,
                        services=services,
                        user_agent=user_agent,
                        start_height=start_height,
                        last_seen=int(time.time()),
                        last_error="",
                    )
                    log(f"connected BLAKE2b peer {self.address}")
                    sock.sendall(make_message("verack"))
                elif command == "verack":
                    handshaken = True
                    sock.sendall(make_message("getaddr"))
                elif command == "ping":
                    sock.sendall(make_message("pong", payload))
                elif command == "addr":
                    added = sum(1 for ip, port, services in parse_addr(payload) if start_peer(ip, port, services))
                    if added:
                        log(f"learned {added} additional BLAKE2b peers from {self.address}")
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
                    self.pending_request = None
                elif command == "notfound" and pending is not None:
                    with queue_lock:
                        queued_hashes.discard(pending[0])
                    download_queue.task_done()
                    pending = None
                    self.pending_request = None


def start_peer(ip: str, port: int = P2P_PORT, services: int = 0) -> bool:
    """Start one unique public BLAKE2b peer, up to the configured cap."""
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not parsed_ip.is_global or not 0 < port < 65536:
        return False
    if services and not services & NODE_BLAKE2B:
        return False
    address = f"[{parsed_ip}]:{port}" if parsed_ip.version == 6 else f"{parsed_ip}:{port}"
    with peer_workers_lock:
        if address in peer_workers or len(peer_workers) >= MAX_PEERS:
            return False
        worker = PeerWorker(str(parsed_ip), port)
        peer_workers[address] = worker
        worker.start()
    return True


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
            start = START_HEIGHT - 11
            for height in range(start, tip + 1):
                if stop_event.is_set():
                    return
                with db() as connection:
                    row = connection.execute("SELECT raw_path FROM blocks WHERE height = ? AND raw_path IS NOT NULL", (height,)).fetchone()
                if row:
                    continue
                block_hash = fetch_text(f"https://mempool.guide/api/block-height/{height}")
                enqueue_block(block_hash, height, "mempool.guide index")
                stop_event.wait(0.05)
            with peer_workers_lock:
                need_peers = len(peer_workers) < MAX_PEERS
            if need_peers:
                for address in discover_peers():
                    start_peer(address)
            stop_event.wait(15)
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


def branch_data(connection: sqlite3.Connection, history: bool = False) -> dict[str, Any]:
    rows = connection.execute(
        """
        SELECT hash, prev_hash, height, timestamp, received_at, peer, size,
               legacy_maturity_ok, long_maturity_ok, maturity_note, miner_tag
        FROM blocks
        WHERE height >= ?
        ORDER BY height DESC, received_at DESC
        LIMIT ?
        """,
        (START_HEIGHT, 12000 if history else 1200),
    ).fetchall()
    blocks = [dict(row) for row in rows]
    hashes = {row["hash"] for row in blocks}
    # Preserve known conflicts before the recent rendering window. Otherwise a
    # descendant would incorrectly turn green as its rejecting ancestor ages out.
    for block in blocks:
        if block["prev_hash"] in hashes:
            continue
        inherited = connection.execute("""
            WITH RECURSIVE ancestors AS (
                SELECT hash,prev_hash,height,legacy_maturity_ok,long_maturity_ok
                FROM blocks WHERE hash=?
                UNION ALL
                SELECT b.hash,b.prev_hash,b.height,b.legacy_maturity_ok,b.long_maturity_ok
                FROM blocks b JOIN ancestors a ON b.hash=a.prev_hash
                WHERE b.height=a.height-1
            ) SELECT MIN(legacy_maturity_ok),MIN(long_maturity_ok),
                     SUM(legacy_maturity_ok IS NULL),SUM(long_maturity_ok IS NULL)
              FROM ancestors
        """, (block["prev_hash"],)).fetchone()
        block["prefix_legacy_ok"] = (False if inherited[0] == 0 else None if inherited[2] else True)
        block["prefix_long_ok"] = (False if inherited[1] == 0 else None if inherited[3] else True)
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
            """
            SELECT address, connected, services, user_agent, start_height, last_seen, last_error
            FROM peers
            WHERE connected = 1
            ORDER BY last_seen DESC
            """
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
        fork_count = connection.execute("SELECT COUNT(*) FROM (SELECT prev_hash FROM blocks WHERE height>=? GROUP BY prev_hash HAVING COUNT(*)>1)", (START_HEIGHT,)).fetchone()[0]
        announcements = connection.execute("SELECT COUNT(*) AS count FROM announcements").fetchone()["count"]
        meta = {row["key"]: row["value"] for row in connection.execute("SELECT key, value FROM meta")}
        branches = branch_data(connection)
    peers = [dict(row) for row in peer_rows]
    for peer in peers:
        peer["rule_set"] = peer_rule_set(peer.get("user_agent"))
    connected_peers = peers
    return {
        "observer": {
            "mode": "passive-unvalidated",
            "started": int(PROCESS_STARTED),
            "activation_height": ACTIVATION_HEIGHT,
            "release_height": RELEASE_HEIGHT,
            "start_height": START_HEIGHT,
            "coinbase_expiry_time": RDTS_EXPIRY,
            "rule_name": "180-day rolling coinbase maturity",
            "partial_validation": True,
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
            "recorded_splits": int(fork_count),
            "announcements": int(announcements or 0),
            "connected_peers": len(connected_peers),
            "new_rule_peers": sum(1 for peer in connected_peers if peer["rule_set"] == "new"),
            "legacy_rule_peers": sum(1 for peer in connected_peers if peer["rule_set"] == "legacy"),
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

    def end_headers(self) -> None:
        # The immutable static frontend can consume this public live API without
        # moving its custom domain or sharing any credentials.
        origin = self.headers.get("Origin", "")
        if self.path.startswith("/api/") and origin in {
            "https://lukecoin.zndtoshi.com",
            "https://knots-fork-observer-archive.onrender.com",
        }:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        super().end_headers()

    def do_GET(self) -> None:
        if self.path == "/api/status":
            if ARCHIVE_MODE:
                payload = (STATIC_DIR / "snapshot.json").read_bytes()
            else:
                payload = json.dumps(status_payload(), separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "public, max-age=300" if ARCHIVE_MODE else "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/health":
            payload = (
                b'{"ok":true,"mode":"historical-snapshot","network_activity":false}'
                if ARCHIVE_MODE
                else b'{"ok":true,"mode":"passive-unvalidated","network_activity":true}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/history":
            if ARCHIVE_MODE:
                payload = (STATIC_DIR / "snapshot.json").read_bytes()
            else:
                result = status_payload()
                with db() as connection:
                    result["chain"] = branch_data(connection, history=True)
                payload = json.dumps(result, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/":
            self.path = "/index.html"
        super().do_GET()


PROCESS_STARTED = time.time()


def main() -> None:
    if ARCHIVE_MODE:
        server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), DashboardHandler)
        print(
            f"historical snapshot listening on http://{LISTEN_HOST}:{LISTEN_PORT}; "
            "peer connections and downloads are disabled",
            flush=True,
        )
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return

    init_db()
    # Connection state is process-local; persisted 1 values from a previous
    # Render instance must not be reported as online after a restart.
    with db() as connection:
        connection.execute("UPDATE peers SET connected = 0")
    backfill_miner_tags()
    peers = discover_peers()
    log(f"starting passive observer with {len(peers)} DNS peer candidates and a {MAX_PEERS}-peer discovery cap")
    threading.Thread(target=bootstrap_backfill, name="backfill", daemon=True).start()
    for address in peers:
        start_peer(address)
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
