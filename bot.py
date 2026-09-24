#!/usr/bin/env python3
"""UNICRED mining bot.

Watches the chain, feeds jobs to hash engines (./miner_cpu locally, or ./miner on GPU boxes over SSH),
keeps the best proof found for the current race, and submits `mine()` the moment that proof beats the
target the contract will apply in the next block. The private key never leaves this machine: engines only
see the 184-byte message template (which contains the public miner address).

  .venv/bin/python bot.py --backend "ssh -p 41234 root@ssh4.vast.ai" [--backend ...] [--dry-run]
"""
import argparse
import collections
import http.client
import json
import math
import os
import queue
import re
import secrets
import ssl
import shlex
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

from Crypto.Hash import keccak
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account

try:  # flashblocks feed (optional): brotli-compressed JSON over a WebSocket, one message per 200 ms sub-block
    import brotli
    import websocket
except ImportError:
    brotli = websocket = None
FLASH_WS = "wss://mainnet-flashblocks.unichain.org/ws"

# ------------------------------------------------------------------ constants (verified against the contract)
CONTRACT = "0xf60de24F228dc7Ca6fF025958d2eE3A956ED88E5"
CHAIN_ID = 130
DOMAIN = bytes.fromhex("d38d03374ffe0ab0595a37e26339a924c9bf9d87e54292dabb07b3bddb3cc04e")
MULTICALL = "0xcA11bde05977b3631167028862bE2a173976CA11"
DEFAULT_RPCS = ["https://mainnet.unichain.org", "https://unichain.drpc.org", "https://unichain-rpc.publicnode.com"]
MAX_SUPPLY, EPOCH_SIZE, EPOCHS = 4444, 404, 11
U256 = 2**256 - 1
MAX_TARGET = U256 >> 24  # floorBits = 24 (constructor arg; MAX_TARGET() on chain)
MIN_TARGET = U256 >> 128
STREAK_MAX, STREAK_COOL = 16, 10
FAILSAFE_EVERY, FAILSAFE_MAX = 300, 20
ANCHOR_WINDOW = 250
PRICE_BASE = PRICE_STEP = 2 * 10**15
GWEI = 10**9


def k256(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def sel(sig: str) -> bytes:
    return k256(sig.encode())[:4]


def word(b: bytes) -> bytes:
    return b.rjust(32, b"\0")


MINED_TOPIC = "0x" + k256(b"Mined(uint256,address,bytes32,uint256,uint256)").hex()
ERRORS = {sel(s).hex(): s.split("(")[0] for s in [
    "NotStarted()", "SoldOut()", "OneMintPerBlock()", "BadAnchor()", "BadProof()", "PriceMoved(uint256)",
    "Underpaid(uint256)", "ReentrancyGuardReentrantCall()"]}


# ------------------------------------------------------------------ difficulty model (mirrors Unicred.sol + Difficulty.sol)
def cooled(streak, since):
    off = since // STREAK_COOL
    s = streak - off if streak > off else 0
    return min(s, STREAK_MAX)


def _double(t, mx):
    return mx if t > mx // 2 else t * 2


def clamp(t, mx):
    return mx if t > mx else (MIN_TARGET if t < MIN_TARGET else t)


def failsafe(t, idle, mx):
    h = min(idle // FAILSAFE_EVERY, FAILSAFE_MAX)
    i = 0
    while i < h and t < mx:
        t = _double(t, mx)
        i += 1
    return clamp(t, mx)


def epoch_of(i):
    e = (i - 1) // EPOCH_SIZE
    return EPOCHS - 1 if e >= EPOCHS else e


def epoch_floor(i):
    return MAX_TARGET >> epoch_of(min(i, MAX_SUPPLY))


def price_of(i):
    return PRICE_BASE + PRICE_STEP * epoch_of(i)


def base_target(s, ts):
    return failsafe(s["target"], ts - s["lastMintTime"], epoch_floor(s["minted"] + 1))


def target_for(s, ts):
    """Exact target the contract applies to `s['who']` in a block with timestamp ts (state as in snapshot s)."""
    steps = cooled(s["fieldStreak"], ts - s["lastMintTime"]) + cooled(s["streakOf"], ts - s["lastMintOf"])
    steps = min(steps, STREAK_MAX)
    t = base_target(s, ts) >> steps
    return 1 if t == 0 else t


B0, T0 = 59469375, 1790217734  # Unichain block -> timestamp anchor (1 s blocks, checked over 30k blocks)


def ts_of(block):
    return T0 + (block - B0)


def bits(t):
    return 256 - math.log2(max(1, t))


# ------------------------------------------------------------------ logging
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
_log_f = open(os.path.join(LOG_DIR, "bot.log"), "a", buffering=1)
_log_mu = threading.Lock()


def log(msg):
    line = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d} " + msg
    with _log_mu:
        print(line, flush=True)
        _log_f.write(line + "\n")


# ------------------------------------------------------------------ JSON-RPC over keep-alive connections
class RpcError(Exception):
    pass


HEADERS = {"content-type": "application/json", "user-agent": "Mozilla/5.0 (unicred-bot)", "connection": "keep-alive"}


class Endpoint:
    def __init__(self, url, proxy, tag="latest"):
        u = urllib.parse.urlparse(url)
        self.url, self.host, self.port, self.path = url, u.hostname, u.port or 443, u.path or "/"
        self.proxy = proxy
        self.tag = tag  # block tag this endpoint's poller reads ("pending" = flashblock state, where supported)
        self.pool = queue.LifoQueue()
        self.fails = 0
        self.direct_until = 0.0

    def _conn(self, timeout, fresh=False):
        try:
            if fresh:
                raise queue.Empty
            c = self.pool.get_nowait()
            c.timeout = timeout
            if c.sock:
                c.sock.settimeout(timeout)
            return c
        except queue.Empty:
            if self.proxy and time.time() >= self.direct_until:
                c = http.client.HTTPSConnection(self.proxy[0], self.proxy[1], timeout=timeout)
                c.set_tunnel(self.host, self.port)
                c._via_proxy = True
            else:
                c = http.client.HTTPSConnection(self.host, self.port, timeout=timeout)
            return c

    def _go_direct(self, e):
        if time.time() >= self.direct_until:
            log(f"[rpc] {self.host}: proxy failed ({str(e)[:60]}); connecting directly for 60 s")
        self.direct_until = time.time() + 60
        while True:  # drop pooled proxy connections
            try:
                self.pool.get_nowait().close()
            except queue.Empty:
                break

    def call(self, method, params, timeout=8.0):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        for attempt in (0, 1):
            c = self._conn(timeout, fresh=attempt > 0)
            reused = getattr(c, "_used", False)
            try:
                c.request("POST", self.path, body, HEADERS)
                r = c.getresponse()
                data = r.read()
                if r.status != 200:
                    raise RpcError(f"{self.host} http {r.status}")
                j = json.loads(data)
            except (ConnectionError, http.client.HTTPException, ssl.SSLError) as e:
                c.close()
                if reused and attempt == 0:
                    continue  # the server dropped an idle keep-alive connection: retry once on a fresh one
                if getattr(c, "_via_proxy", False) and attempt == 0 and isinstance(e, ConnectionRefusedError):
                    self._go_direct(e)
                    continue
                self.fails += 1
                raise
            except OSError as e:
                c.close()
                # "Tunnel connection failed" and friends: the local proxy is up but can't reach the RPC
                if getattr(c, "_via_proxy", False) and attempt == 0 and not isinstance(e, TimeoutError):
                    self._go_direct(e)
                    continue
                self.fails += 1
                raise
            except Exception:
                c.close()
                self.fails += 1
                raise
            c._used = True
            self.pool.put(c)
            if "error" in j:
                raise RpcError(j["error"])
            self.fails = 0
            return j["result"]


class Rpc:
    def __init__(self, urls, proxy, pending_urls=(), send_urls=()):
        self.eps = [Endpoint(u, proxy) for u in urls] + [Endpoint(u, proxy, "pending") for u in pending_urls]
        self.send_eps = [Endpoint(u, proxy) for u in send_urls]  # eth_sendRawTransaction only (e.g. the sequencer)
        self.good = 0

    def send_raw(self, raw_hex, timeout=6.0):
        """Broadcast a signed tx to every endpoint at once; return (txhash, errors) as soon as one accepts it."""
        eps = self.eps + self.send_eps
        q = queue.Queue()

        def one(ep):
            try:
                q.put((ep, ep.call("eth_sendRawTransaction", [raw_hex], timeout)))
            except Exception as e:
                q.put((ep, e))

        for ep in eps:
            threading.Thread(target=one, args=(ep,), daemon=True).start()
        errs = []
        deadline = time.time() + timeout + 1
        for _ in eps:
            try:
                ep, r = q.get(timeout=max(0.05, deadline - time.time()))
            except queue.Empty:
                break
            if isinstance(r, str):
                return r, errs
            msg = str(r)
            errs.append(f"{ep.host}: {msg[:80]}")
            if "already known" in msg.lower():
                return "known", errs
        return None, errs

    def call(self, method, params, timeout=8.0):
        err = None
        for k in range(len(self.eps)):
            i = (self.good + k) % len(self.eps)
            try:
                res = self.eps[i].call(method, params, timeout)
                self.good = i
                return res
            except RpcError as e:
                # a JSON-RPC error (revert etc.) is an answer, not an endpoint failure
                if isinstance(e.args[0], dict):
                    raise
                err = e
            except Exception as e:
                err = e
        raise err

    def first(self, method, params, timeout=4.0, accept=lambda r: r is not None):
        """Ask every endpoint at once; return the first answer `accept` likes, else None."""
        q = queue.Queue()

        def one(ep):
            try:
                q.put(ep.call(method, params, timeout))
            except Exception as e:
                q.put(e)

        for ep in self.eps:
            threading.Thread(target=one, args=(ep,), daemon=True).start()
        deadline = time.time() + timeout + 0.5
        for _ in self.eps:
            try:
                r = q.get(timeout=max(0.05, deadline - time.time()))
            except queue.Empty:
                break
            if not isinstance(r, Exception) and accept(r):
                return r
        return None

    def broadcast(self, method, params, timeout=6.0):
        """Same call to every endpoint in parallel; returns list of (url, result|exception)."""
        out = [None] * len(self.eps)

        def one(i):
            try:
                out[i] = (self.eps[i].url, self.eps[i].call(method, params, timeout))
            except Exception as e:
                out[i] = (self.eps[i].url, e)

        ts = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(len(self.eps))]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout + 1)
        return [o for o in out if o]


def detect_proxy(arg):
    if arg == "none":
        return None
    if arg and arg != "auto":
        u = urllib.parse.urlparse(arg)
        return (u.hostname, u.port or 80)
    p = urllib.request.getproxies().get("https") or urllib.request.getproxies().get("http")
    if not p:
        return None
    u = urllib.parse.urlparse(p if "://" in p else "http://" + p)
    return (u.hostname, u.port or 80)


# ------------------------------------------------------------------ chain snapshot (one Multicall3 eth_call = one consistent block)
def _c(fn):
    return sel(fn)


SNAP_FIELDS = [
    ("minted", CONTRACT, _c("totalMinted()"), "uint256"),
    ("prev", CONTRACT, _c("prevWork()"), "bytes32"),
    ("target", CONTRACT, _c("target()"), "uint256"),
    ("lastMintTime", CONTRACT, _c("lastMintTime()"), "uint256"),
    ("lastMintBlock", CONTRACT, _c("lastMintBlock()"), "uint256"),
    ("fieldStreak", CONTRACT, _c("fieldStreak()"), "uint256"),
    ("startTime", CONTRACT, _c("startTime()"), "uint256"),
    ("block", MULTICALL, _c("getBlockNumber()"), "uint256"),
    ("ts", MULTICALL, _c("getCurrentBlockTimestamp()"), "uint256"),
    ("lastBlockHash", MULTICALL, _c("getLastBlockHash()"), "bytes32"),
    ("basefee", MULTICALL, _c("getBasefee()"), "uint256"),
]
SEL_AGG3 = sel("aggregate3((address,bool,bytes)[])")


def snapshot_calldata(who):
    calls = [(a, True, s) for _, a, s, _ in SNAP_FIELDS]
    whow = word(bytes.fromhex(who[2:]))
    calls += [(CONTRACT, True, _c("streakOf(address)") + whow), (CONTRACT, True, _c("lastMintOf(address)") + whow),
              (CONTRACT, True, _c("targetFor(address)") + whow), (MULTICALL, True, _c("getEthBalance(address)") + whow)]
    return "0x" + (SEL_AGG3 + abi_encode(["(address,bool,bytes)[]"], [calls])).hex()


def parse_snapshot(ret, who):
    res = abi_decode(["(bool,bytes)[]"], bytes.fromhex(ret[2:]))[0]
    s = {"who": who}
    names = [f[0] for f in SNAP_FIELDS] + ["streakOf", "lastMintOf", "targetFor", "balance"]
    types = [f[3] for f in SNAP_FIELDS] + ["uint256"] * 4
    for (ok, data), n, t in zip(res, names, types):
        if not ok:
            raise RpcError(f"multicall part {n} failed")
        v = abi_decode([t], data)[0]
        s[n] = v if t == "uint256" else bytes(v)
    s["got_at"] = time.time()
    s["ts_chain"] = s["ts"]
    s["ts"] = ts_of(s["block"])  # never trust a node's pending-block timestamp
    return s


def fetch_snapshot(rpc_or_ep, who, block="latest"):
    return parse_snapshot(rpc_or_ep.call("eth_call", [{"to": MULTICALL, "data": snapshot_calldata(who)}, block]), who)


# ------------------------------------------------------------------ engines
class Backend:
    def __init__(self, idx, cmd, on_line):
        self.idx, self.cmd, self.on_line = idx, cmd, on_line
        self.proc = None
        self.mu = threading.Lock()
        self.rate = 0.0
        self.ready = False
        self.info = ""
        self.last_job = None
        self.stop = False
        self.errf = open(os.path.join(LOG_DIR, f"backend{idx}.err"), "a", buffering=1)
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        backoff = 2
        while not self.stop:
            t0 = time.time()
            try:
                self.proc = subprocess.Popen(self.cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=self.errf, text=True, bufsize=1)
            except Exception as e:
                log(f"[b{self.idx}] spawn failed: {e}")
                time.sleep(backoff)
                continue
            with self.mu:
                if self.last_job:
                    self._write(self.last_job)
            for line in self.proc.stdout:
                self.on_line(self, line.strip())
            rc = self.proc.wait()
            self.ready, self.rate = False, 0.0
            if self.stop:
                break
            if time.time() - t0 > 60:
                backoff = 2
            log(f"[b{self.idx}] engine exited (rc={rc}); restarting in {backoff}s  (see logs/backend{self.idx}.err)")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)

    def _write(self, line):
        try:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
        except Exception:
            pass

    def send(self, line, remember=False):
        with self.mu:
            if remember:
                self.last_job = line
            if self.proc and self.proc.poll() is None:
                self._write(line)

    def quit(self):
        self.stop = True
        self.send("QUIT")


def normalize_backend(cmd):
    """`ssh -p 41234 root@host` -> run the engine remotely (no tty, keepalives, no prompts)."""
    parts = shlex.split(cmd)
    if parts and parts[0] == "ssh":
        opts = ["-T", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"]
        rest = [os.path.expanduser(x) if x.startswith("~") else x for x in parts[1:]]
        # drop -L port forwards that vast.ai's copy button adds
        clean, i = [], 0
        while i < len(rest):
            if rest[i] == "-L" and i + 1 < len(rest):
                i += 2
                continue
            clean.append(rest[i])
            i += 1
        # the host is the first arg that isn't an option or an option's value
        has_cmd, i, host_i = False, 0, None
        takes_val = set("bcDEeFIiJLlmOoPpQRSWw")
        while i < len(clean):
            a = clean[i]
            if a.startswith("-") and len(a) == 2 and a[1] in takes_val:
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            host_i = i
            has_cmd = i + 1 < len(clean)
            break
        if host_i is None:
            return cmd
        remote = clean[host_i + 1:] if has_cmd else ["/root/rig/miner"]
        return " ".join(shlex.quote(x) for x in ["ssh"] + opts + clean[:host_i + 1] + remote)
    return cmd


# ------------------------------------------------------------------ the bot
class Bot:
    def __init__(self, a):
        self.a = a
        self.proxy = detect_proxy(a.proxy)
        self.rpc = Rpc(a.rpc or DEFAULT_RPCS, self.proxy, a.pending_rpc or (), a.send_rpc or ())
        self.me = open(os.path.expanduser(a.address_file)).read().strip()
        self.key = None
        if not a.dry_run:
            self.key = open(os.path.expanduser(a.key_file)).read().strip()
            if Account.from_key(self.key).address.lower() != self.me.lower():
                sys.exit("key file does not match address file")
        self.snap = None
        self.snap_mu = threading.Lock()
        self.snap_gen = 0
        self.hits = queue.Queue()
        self.job = None
        self.job_seq = 0
        self.sent = self.wins = self.reverts = 0
        self.tx_nonce = None
        self.inflight = {}
        self.backends = [Backend(i, normalize_backend(c), self.on_line) for i, c in enumerate(a.backend)]
        self.stop = threading.Event()
        self.last_status = 0
        self.low_balance_warned = 0
        self.best_seen = {}
        # flashblocks: a mint shows up here ~0.2 s after inclusion, 0.7-1.5 s before the sealed block reaches our polls
        self.job_mu = threading.RLock()
        self.fb_ts = 0          # timestamp of the block the sequencer is building now
        self.fb_block = 0
        self.fb_gen = 0
        self.fb_msgs = 0
        self.fb_jobs = 0
        self.max_latest = 0
        self.send_mu = threading.Lock()  # one tx at a time: the account nonce is tracked locally
        self.staked = set()
        # time.monotonic() minus block number when each new block was first seen. Blocks come on a steady 1 s clock,
        # so the minimum over recent blocks is the earliest we can see a block; early sends are timed off it
        # (monotonic, so a wall-clock step can't shift them)
        self.sightings = collections.deque(maxlen=120)

    # -- engines
    def on_line(self, b, line):
        if not line:
            return
        p = line.split()
        if p[0] == "HIT" and len(p) >= 4:
            self.hits.put((int(p[1]), int(p[2], 16), int(p[3], 16), b.idx))
        elif p[0] == "RATE":
            b.rate = float(p[1])
        elif p[0] == "READY":
            b.ready = True
            b.info = " ".join(p[1:])
            log(f"[b{b.idx}] READY {b.info}")
        elif p[0] == "SELFTEST":
            log(f"[b{b.idx}] {line}")
        else:
            log(f"[b{b.idx}] {line}")

    def broadcast_job(self, line):
        for b in self.backends:
            b.send(line, remember=True)

    # -- chain watch: every endpoint polls; the freshest block wins
    def poller(self, ep):
        errs = 0
        while not self.stop.is_set():
            t0 = time.time()
            try:
                s = fetch_snapshot(ep, self.me, ep.tag)
                seen_at = time.monotonic()
                s["src"] = ep.host + ("/pending" if ep.tag == "pending" else "")
                s["pending"] = ep.tag == "pending"
                with self.snap_mu:
                    if not s["pending"]:
                        self.max_latest = max(self.max_latest, s["block"])
                    # a pending (flashblock) view may run at most one block past the newest sealed block seen
                    sane = not s["pending"] or not self.max_latest or s["block"] <= self.max_latest + 2
                    if sane and (self.snap is None or s["block"] > self.snap["block"] or (
                            s["block"] == self.snap["block"] and s["prev"] != self.snap["prev"])):
                        if not s["pending"] and (self.snap is None or s["block"] > self.snap["block"]):
                            self.sightings.append(seen_at - s["block"])
                        self.snap = s
                        self.snap_gen += 1
                errs = 0
            except Exception as e:
                errs += 1
                if errs in (1, 10) or errs % 100 == 0:
                    log(f"[rpc] {ep.host}: {str(e)[:120]} (x{errs})")
                time.sleep(min(5, 0.5 * errs))
            dt = time.time() - t0
            time.sleep(max(0.0, self.a.poll - dt))

    # -- flashblocks feed
    def flash_watcher(self):
        backoff = 1
        while not self.stop.is_set():
            ws = None
            try:
                ws = websocket.create_connection(FLASH_WS, timeout=10, enable_multithread=True)
                log(f"[flash] connected to {FLASH_WS}")
                backoff = 1
                while not self.stop.is_set():
                    raw = ws.recv()
                    if isinstance(raw, str):
                        raw = raw.encode()
                    try:
                        msg = json.loads(brotli.decompress(raw))
                    except Exception:
                        msg = json.loads(raw)
                    self.on_flash(msg)
            except Exception as e:
                if not self.stop.is_set():
                    log(f"[flash] {type(e).__name__}: {str(e)[:100]}; reconnecting in {backoff}s")
            finally:
                try:
                    ws and ws.close()
                except Exception:
                    pass
            time.sleep(backoff)
            backoff = min(backoff * 2, 15)

    def on_flash(self, msg):
        self.fb_msgs += 1
        meta = msg.get("metadata") or {}
        bn = int(meta.get("block_number") or 0)
        base = msg.get("base")
        if base and bn:
            self.fb_block, self.fb_ts = bn, int(base["timestamp"], 16)
            self.fb_gen += 1
        for rc in (meta.get("receipts") or {}).values():
            r = next(iter(rc.values())) if isinstance(rc, dict) and len(rc) == 1 and "logs" not in rc else rc
            for lg in (r.get("logs") or []) if isinstance(r, dict) else []:
                tp = lg.get("topics") or []
                if (lg.get("address") or "").lower() == CONTRACT.lower() and tp and tp[0] == MINED_TOPIC:
                    self.on_flash_mint(int(tp[1], 16), bytes.fromhex(lg["data"][2:66]), bn)

    def on_flash_mint(self, mid, work, bn):
        with self.snap_mu:
            s = self.snap
        if not s:
            return
        with self.job_mu:
            j = self.job
            if j and (j["minted"] >= mid or j["prev"] == work):
                return
            if mid <= s["minted"]:
                return  # the sealed state already has it; the main loop handles that
            j = self.new_job(s, prev=work, minted=mid, fb_block=bn)
            self.fb_jobs += 1
        log(f"[flash] #{mid} mined in block {bn} (flashblock) -> job {j['id']} out before the block is sealed")

    # -- jobs
    def new_job(self, s, prev=None, minted=None, fb_block=0, force=False):
        anchor = s["block"] - 1  # getLastBlockHash() = blockhash(block.number - 1)
        anchor_hash = s["lastBlockHash"]
        prev = prev or s["prev"]
        with self.job_mu:
            cur = self.job
            if not force and cur and cur["prev"] == prev and cur["minted"] == (minted or s["minted"]):
                return cur  # the flashblock feed already opened this race
        challenge = k256(anchor_hash + prev)
        nonce_high = secrets.token_bytes(24)
        msg184 = DOMAIN + word(CHAIN_ID.to_bytes(32, "big")) + word(bytes.fromhex(CONTRACT[2:])) + challenge + \
            word(bytes.fromhex(self.me[2:])) + nonce_high
        assert len(msg184) == 184
        with self.job_mu:
            self.job_seq += 1
            j = dict(id=self.job_seq, prev=prev, anchor=anchor, anchor_hash=anchor_hash, msg184=msg184, nonce_high=nonce_high,
                     best=None, best_low=None, submitted=False, t0=time.time(), minted=minted or s["minted"], thr=None,
                     retry_after=0, fb_block=fb_block)
            if fb_block and not self.a.test_thr_bits:
                # fresh race seen in a flashblock: the snapshot is still pre-mint, so assume the hardest target
                # (field streak back at the cap), doubled once for a possible retarget, then the usual slack
                t = (base_target(s, s["ts"] + 1) * 2 >> STREAK_MAX) << self.a.cap_steps
                j["thr"] = min((1 << 64) - 1, (min(t, U256) >> 192) + 1)
            else:
                j["thr"] = self.loose_thr(s)
            self.job = j
            self.broadcast_job(f"JOB {j['id']} {msg184.hex()} {j['thr']:016x}")
        return j

    def loose_thr(self, s):
        if self.a.test_thr_bits:
            return (1 << (64 - self.a.test_thr_bits)) - 1
        t = target_for(s, s["ts"] + 1) << self.a.cap_steps
        return min((1 << 64) - 1, (min(t, U256) >> 192) + 1)

    def on_hit(self, jid, low, top, bidx):
        j = self.job
        if not j or jid != j["id"]:
            return
        dig = k256(j["msg184"] + low.to_bytes(8, "big"))
        d = int.from_bytes(dig, "big")
        if (d >> 192) != top:
            log(f"[b{bidx}] BAD HIT: engine top64 {top:016x} != cpu {d >> 192:016x} (nonce low {low:016x})")
            return
        if j["best"] is None or d < j["best"]:
            j["best"], j["best_low"] = d, low
            nt = min(j["thr"], (d >> 192))
            if nt < j["thr"]:
                j["thr"] = nt
                for b in self.backends:
                    b.send(f"THR {j['id']} {nt:016x}")
            if self.a.dry_run and self.a.verify_hits:
                threading.Thread(target=self.verify_on_chain, args=(dict(j), low, d), daemon=True).start()

    def nonce_full(self, j, low):
        return int.from_bytes(j["nonce_high"] + low.to_bytes(8, "big"), "big")

    def verify_on_chain(self, j, low, d):
        n = self.nonce_full(j, low)
        data = "0x" + (sel("digestOf(bytes32,bytes32,address,uint256)") + j["anchor_hash"] + j["prev"] +
                       word(bytes.fromhex(self.me[2:])) + n.to_bytes(32, "big")).hex()
        try:
            got = int(self.rpc.call("eth_call", [{"to": CONTRACT, "data": data}, "latest"]), 16)
            log(f"[verify] job {j['id']} digestOf on chain {'==' if got == d else '!='} local  ({bits(d):.1f} bits)")
        except Exception as e:
            log(f"[verify] eth_call failed: {e}")

    # -- submission
    def calldata_mine(self, j, low, price):
        return "0x" + (sel("mine(uint256,uint256,uint256)") + abi_encode(["uint256", "uint256", "uint256"],
                                                                      [j["anchor"], self.nonce_full(j, low), price])).hex()

    def maybe_submit(self, s):
        j = self.job
        if not j or j["best"] is None or j["submitted"] or j["prev"] != s["prev"]:
            return
        if j.get("tries", 0) >= 2:
            return
        if s["block"] < j["retry_after"]:
            return
        if s["block"] + 1 - j["anchor"] > ANCHOR_WINDOW - 2:
            return
        # a pending (flashblock) snapshot is the block being built: a tx sent now lands in it or later
        ts_next = s["ts"] if s.get("pending") else s["ts"] + 1
        if self.fb_block > s["block"] and self.fb_ts > ts_next:
            # the sequencer is already building a later block: a tx sent now can't land before it,
            # and the target only eases with time, so judge the proof at that block's timestamp
            ts_next = self.fb_ts
        T = target_for(s, ts_next)
        if j["best"] >= T:
            return
        price = price_of(s["minted"] + 1)
        j["submitted"] = True
        j["tries"] = j.get("tries", 0) + 1
        age = time.time() - j["t0"]
        log(f"FOUND job {j['id']}: digest {bits(j['best']):.2f} bits < target {bits(T):.2f} bits at ts {ts_next} "
            f"(race {ts_next - s['lastMintTime']}s, job age {age:.1f}s) -> #{s['minted'] + 1} for {price / 1e18} ETH")
        if self.a.dry_run:
            threading.Thread(target=self.dry_submit, args=(dict(j), s, price), daemon=True).start()
        else:
            threading.Thread(target=self.submit, args=(dict(j), s, price), daemon=True).start()

    def first_sight_phase(self):
        """Earliest recent sighting as monotonic time minus block number, or None until there are enough samples."""
        sv = list(self.sightings)
        return min(sv) if len(sv) >= 30 else None

    def maybe_presend(self, s):
        """A proof that turns valid only at block B (the target eases in 10 s steps) goes out as B opens, timed off
        the clock instead of after we happen to see block B-1: our sightings trail the chain by up to a second, and
        in a step race the first tx into block B wins. Sent too early it lands in B-1 and reverts, and maybe_submit
        then retries once after that block."""
        if self.a.presend is None:
            return
        j = self.job
        if not j or j["submitted"] or j["prev"] != s["prev"] or j.get("tries", 0) >= 2:
            return
        if s.get("pending") or s["block"] < j["retry_after"] or self.fb_block > s["block"]:
            return
        if self.a.presend_test and self.a.dry_run and j["best"] is None:
            # timing test: a made-up proof that turns valid at the next target step at least 2 blocks out
            for k in range(2, 15):
                t1, t2 = target_for(s, s["ts"] + k - 1), target_for(s, s["ts"] + k)
                if t2 > t1:
                    j["best"], j["best_low"] = t1 + (t2 - t1) // 2, 0
                    break
        if j["best"] is None or j["best"] < target_for(s, s["ts"] + 1):
            return  # nothing yet, or valid in the very next block: maybe_submit sends that now
        B = next((s["block"] + k for k in (2, 3) if j["best"] < target_for(s, s["ts"] + k)), None)
        if B is None or B - j["anchor"] > ANCHOR_WINDOW - 2:
            return
        P = self.first_sight_phase()
        if P is None:
            return
        lead = time.monotonic() - (B - 1 + P)  # seconds since the earliest moment we could have seen block B-1
        if lead < self.a.presend:
            return
        price = price_of(s["minted"] + 1)
        j["submitted"] = True
        j["tries"] = j.get("tries", 0) + 1
        log(f"FOUND job {j['id']}: digest {bits(j['best']):.2f} bits < target {bits(target_for(s, ts_of(B))):.2f} bits "
            f"from block {B} (race {ts_of(B) - s['lastMintTime']}s) | EARLY send {lead:+.2f}s after block {B - 1} could "
            f"first be seen (we have {s['block']}) -> #{s['minted'] + 1} for {price / 1e18} ETH")
        if self.a.dry_run:
            threading.Thread(target=self.dry_submit, args=(dict(j), s, price, ts_of(B)), daemon=True).start()
        else:
            threading.Thread(target=self.submit, args=(dict(j), s, price), daemon=True).start()

    def fee_fields(self, s):
        tip = int(self.a.tip_gwei * GWEI)
        return dict(maxPriorityFeePerGas=tip, maxFeePerGas=max(s["basefee"] * 3 + tip, tip + 1))

    def dry_submit(self, j, s, price, at_ts=None):
        data = self.calldata_mine(j, j["best_low"], price)
        call = {"from": self.me, "to": CONTRACT, "data": data, "value": hex(price), "gas": hex(self.a.gas_limit)}
        params = [call, "latest", {self.me: {"balance": hex(10**18)}}]
        if at_ts:
            params.append({"time": hex(at_ts)})  # an early send: judge it at the timestamp of the block it aims for
        where = f"ts {at_ts}" if at_ts else "latest"
        try:
            self.rpc.call("eth_call", params)
            log(f"WOULD-SUBMIT job {j['id']}: eth_call mine() SUCCEEDS at {where} (dry run, nothing sent)")
        except RpcError as e:
            log(f"WOULD-SUBMIT job {j['id']}: eth_call mine() reverts at {where}: {self.decode_err(e)} (dry run)")

    def decode_err(self, e):
        info = e.args[0] if e.args else e
        if isinstance(info, dict):
            data = info.get("data") or ""
            if isinstance(data, dict):
                data = data.get("data", "")
            if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
                return ERRORS.get(data[2:10], data[:10])
            return str(info.get("message"))[:120]
        return str(info)[:160]

    def sync_nonce(self, at_least=0):
        """Account nonce = max over every endpoint's 'latest' count (a lagging node can report 0), never going back."""
        res = self.rpc.broadcast("eth_getTransactionCount", [self.me, "latest"], timeout=4.0)
        seen = [int(r, 16) for _, r in res if isinstance(r, str)]
        self.tx_nonce = max(seen + [at_least, self.tx_nonce or 0])

    def send_tx(self, data, value, gas, s, label):
        """Sign + broadcast one tx from the hot wallet; returns the tx hash or None. Serialised: nonces are local."""
        with self.send_mu:
            if self.tx_nonce is None:
                self.sync_nonce()
            for attempt in range(3):
                tx = dict(chainId=CHAIN_ID, nonce=self.tx_nonce, to=CONTRACT, value=value, gas=gas, data=data, type=2,
                          **self.fee_fields(s))
                signed = Account.sign_transaction(tx, self.key)
                raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
                local = "0x" + bytes(signed.hash).hex()
                t0 = time.time()
                txh, errs = self.rpc.send_raw("0x" + bytes(raw).hex())
                ms = (time.time() - t0) * 1000
                if txh:  # a node returned the hash, or already had this exact tx
                    self.tx_nonce += 1
                    log(f"{label} SENT {local} nonce {tx['nonce']} tip {self.a.tip_gwei} gwei in {ms:.0f} ms")
                    return local
                joined = " | ".join(errs)
                nexts = [int(x) for x in re.findall(r"next nonce (\d+)", joined)]
                if nexts:
                    # our own copy may already have landed through a faster node
                    try:
                        if self.rpc.first("eth_getTransactionReceipt", [local], timeout=3.0):
                            self.tx_nonce = tx["nonce"] + 1
                            log(f"{label} SENT {local} nonce {tx['nonce']} (already mined) in {ms:.0f} ms")
                            return local
                    except Exception:
                        pass
                    if max(nexts) > tx["nonce"]:
                        log(f"{label}: nonce {tx['nonce']} is stale (chain says next {max(nexts)}); re-signing now")
                        self.tx_nonce = max(nexts)
                        continue
                log(f"{label} SEND FAILED ({ms:.0f} ms): {joined}")
                if "nonce" in joined.lower():
                    self.sync_nonce()
                return None
            return None

    def submit(self, j, s, price):
        need = price + self.a.gas_limit * (s["basefee"] * 3 + int(self.a.tip_gwei * GWEI))
        if s["balance"] < need:
            log(f"NOT SENT: balance {s['balance'] / 1e18:.6f} ETH < {need / 1e18:.6f} needed. Fund {self.me} on Unichain.")
            return
        txh = self.send_tx(self.calldata_mine(j, j["best_low"], price), price, self.a.gas_limit, s, "MINE")
        if not txh:
            if self.job and self.job["id"] == j["id"]:
                self.job["retry_after"] = s["block"] + 1
                self.job["submitted"] = False
            return
        self.sent += 1
        self.watch_receipt(txh, j)

    # -- staking: every unicorn won goes straight into the longest term (30 days, 4x rent weight)
    def stake(self, ids):
        ids = [i for i in ids if i not in self.staked]
        if not ids or self.a.stake_term < 0:
            return
        data = "0x" + (sel("stake(uint256[],uint256)") + abi_encode(["uint256[]", "uint256"], [ids, self.a.stake_term])).hex()
        for attempt in range(5):
            with self.snap_mu:
                s = self.snap
            ok = self.rpc.first("eth_call", [{"from": self.me, "to": CONTRACT, "data": data}, "latest"],
                                accept=lambda r: isinstance(r, str))
            if ok is None:
                log(f"STAKE {ids}: no node says it would succeed yet; retry {attempt + 1}/5 in 3 s")
                time.sleep(3)
                continue
            txh = self.send_tx(data, 0, 80_000 + 90_000 * len(ids), s, f"STAKE {ids}")
            if not txh:
                time.sleep(2)
                continue
            t0 = time.time()
            while time.time() - t0 < 45:
                rc = self.rpc.first("eth_getTransactionReceipt", [txh])
                if rc:
                    if int(rc["status"], 16) == 1:
                        self.staked.update(ids)
                        log(f"*** STAKED {ids} for {['7 days (1x)', '14 days (2x)', '30 days (4x)'][self.a.stake_term]} "
                            f"in block {int(rc['blockNumber'], 16)}  tx {txh} ***")
                        return
                    log(f"STAKE {ids} reverted in block {int(rc['blockNumber'], 16)}; retrying")
                    break
                time.sleep(0.5)
            time.sleep(2)
        log(f"STAKE {ids}: gave up after 5 attempts; stake them from the site")

    def watch_receipt(self, txh, j):
        t0 = time.time()
        while time.time() - t0 < 45:
            rc = self.rpc.first("eth_getTransactionReceipt", [txh])
            if rc:
                blk = int(rc["blockNumber"], 16)
                if int(rc["status"], 16) == 1:
                    ids = [int(l["topics"][1], 16) for l in rc["logs"] if l["topics"] and l["topics"][0] == MINED_TOPIC]
                    self.wins += 1
                    log(f"*** WON UNICRED #{ids[0] if ids else '?'} in block {blk}  tx {txh}  (wins {self.wins}) ***")
                    if ids and self.a.stake_term >= 0:
                        threading.Thread(target=self.stake, args=(ids,), daemon=True).start()
                    if self.a.max_wins and self.wins >= self.a.max_wins:
                        log(f"reached --max-wins {self.a.max_wins}; stopping")
                        self.stop.set()
                else:
                    self.reverts += 1
                    log(f"REVERTED in block {blk} (someone minted first in that block, or the race moved on)  tx {txh}")
                    if self.job and self.job["id"] == j["id"]:
                        self.job["submitted"] = False
                        self.job["retry_after"] = blk + 1
                return
            time.sleep(0.4)
        log(f"no receipt after 45 s for {txh}; resyncing nonce")
        with self.send_mu:
            res = self.rpc.broadcast("eth_getTransactionCount", [self.me, "latest"], timeout=4.0)
            seen = [int(r, 16) for _, r in res if isinstance(r, str)]
            self.tx_nonce = max(seen) if seen else None
        if self.job and self.job["id"] == j["id"]:
            self.job["submitted"] = False

    # -- main loop
    def status(self, s):
        j = self.job
        rate = sum(b.rate for b in self.backends)
        ready = sum(1 for b in self.backends if b.ready)
        T = target_for(s, s["ts"] + 1)
        best = f"{bits(j['best']):.1f}" if j and j["best"] else "-"
        exp_s = (2**256 / T) / rate if rate else float("inf")
        P, sv = self.first_sight_phase(), sorted(list(self.sightings)[-30:])
        lag = f" | sight lag p50 {sv[len(sv) // 2] - P:.2f}s" if P is not None else ""
        log(f"#{s['minted']} race {int(time.time() - s['lastMintTime'])}s | target {bits(T):.1f} bits | best {best} bits | "
            f"{rate / 1e9:.3f} GH/s ({ready}/{len(self.backends)} engines) | exp {exp_s:,.0f}s at this target | "
            f"sent {self.sent} won {self.wins} rev {self.reverts} | bal {s['balance'] / 1e18:.5f} | blk {s['block']} via {s['src']}"
            f"{lag}{' | DRY RUN' if self.a.dry_run else ''}")

    def run(self):
        log(f"miner address {self.me} | proxy {self.proxy} | {'DRY RUN (nothing is sent)' if self.a.dry_run else 'LIVE'}"
            f" | tip {self.a.tip_gwei} gwei | gas {self.a.gas_limit}")
        for ep in self.rpc.eps:
            threading.Thread(target=self.poller, args=(ep,), daemon=True).start()

        def warmer():
            while not self.stop.is_set():
                for ep in self.rpc.send_eps:
                    try:
                        ep.call("eth_sendRawTransaction", ["0x00"], timeout=4.0)
                    except Exception:
                        pass
                time.sleep(8)
        threading.Thread(target=warmer, daemon=True).start()
        threading.Thread(target=self.sync_nonce, daemon=True).start()
        if self.a.flash:
            if websocket is None or brotli is None:
                log("[flash] websocket-client/brotli not installed; polling only")
            else:
                threading.Thread(target=self.flash_watcher, daemon=True).start()
        pend = [ep.host for ep in self.rpc.eps if ep.tag == "pending"]
        log(f"polling {len(self.rpc.eps)} RPCs every {self.a.poll}s ({'pending state via ' + ', '.join(pend) if pend else 'latest only'})"
            f" | txs also to {', '.join(ep.host for ep in self.rpc.send_eps) or '-'}"
            f" | stake wins: {['7d 1x', '14d 2x', '30d 4x'][self.a.stake_term] if self.a.stake_term >= 0 else 'off'}")
        startup_ids = [int(x) for x in self.a.stake_ids.split(",") if x.strip()]
        if startup_ids and not self.a.dry_run:
            def stake_later():
                while not self.snap and not self.stop.is_set():
                    time.sleep(0.2)
                self.stake(startup_ids)
            threading.Thread(target=stake_later, daemon=True).start()
        seen_gen = 0
        seen_fb = 0
        try:
            while not self.stop.is_set():
                got_hit = False
                try:
                    while True:
                        self.on_hit(*self.hits.get(timeout=0.02))
                        got_hit = True
                except queue.Empty:
                    pass
                with self.snap_mu:
                    s, g = self.snap, self.snap_gen
                if not s:
                    continue
                if (got_hit or self.fb_gen != seen_fb) and g == seen_gen and s["startTime"] and s["minted"] < MAX_SUPPLY:
                    seen_fb = self.fb_gen
                    self.maybe_submit(s)
                if g != seen_gen:
                    seen_gen = g
                    if s["startTime"] == 0:
                        if time.time() - self.last_status > 5:
                            log("mining has not started yet")
                            self.last_status = time.time()
                        continue
                    if s["minted"] >= MAX_SUPPLY:
                        log("SOLD OUT")
                        break
                    j = self.job
                    behind = bool(j and j.get("fb_block") and s["minted"] < j["minted"])
                    if behind and s["block"] > j["fb_block"] + 3:
                        log(f"[flash] #{j['minted']} from the flashblock never reached block {j['fb_block']}; back to the sealed state")
                        behind = False
                    if behind:
                        pass  # the sealed state hasn't caught up with the race we already started from a flashblock
                    elif (not j or j["prev"] != s["prev"] or s["block"] - j["anchor"] > self.a.anchor_refresh):
                        old = j
                        j = self.new_job(s, force=bool(old and old["prev"] == s["prev"]))
                        why = "start" if not old else ("new race" if old["prev"] != s["prev"] else "anchor refresh")
                        if old and old["prev"] != s["prev"]:
                            b = f"{bits(old['best']):.1f}" if old["best"] else "-"
                            log(f"#{s['minted']} mined (race {s['lastMintTime'] - (self.snap_prev_mint_time or s['lastMintTime'])}s)"
                                f" | my best was {b} bits | job {j['id']} out {time.time() - s['lastMintTime']:.2f}s after that block's"
                                f" timestamp (via {s['src']})")
                        else:
                            log(f"job {j['id']} ({why}) anchor {j['anchor']} thr {j['thr']:016x}")
                        self.snap_prev_mint_time = s["lastMintTime"]
                    else:
                        # the target eases every 10 s: loosen the engines' threshold with it (never above the best found)
                        if not self.a.test_thr_bits and j["best"] is None and not behind and s["prev"] == j["prev"]:
                            nt = self.loose_thr(s)
                            if nt > j["thr"]:
                                j["thr"] = nt
                                for b in self.backends:
                                    b.send(f"THR {j['id']} {nt:016x}")
                    self.maybe_submit(s)
                if s["startTime"] and s["minted"] < MAX_SUPPLY:
                    self.maybe_presend(s)
                if time.time() - self.last_status > self.a.status_every:
                    self.last_status = time.time()
                    self.status(s)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            for b in self.backends:
                b.quit()
            log("bye")

    snap_prev_mint_time = None


# ------------------------------------------------------------------ model self-test against the chain
def model_selftest(a):
    from concurrent.futures import ThreadPoolExecutor
    rpc = Rpc(a.rpc or DEFAULT_RPCS, detect_proxy(a.proxy))
    me = open(os.path.expanduser(a.address_file)).read().strip()
    latest = int(rpc.call("eth_blockNumber", []), 16)
    logs = rpc.call("eth_getLogs", [{"address": CONTRACT, "fromBlock": hex(latest - 90), "toBlock": hex(latest), "topics": [MINED_TOPIC]}])
    miners = []
    for l in reversed(logs):
        m = "0x" + l["topics"][2][-40:]
        if m not in miners:
            miners.append(m)
    whos = [me] + miners[:3]  # the latest winners carry live personal streaks
    mint_blocks = [int(l["blockNumber"], 16) for l in logs[-3:]]
    blocks = sorted({b + d for b in mint_blocks for d in (0, 1, 10, 11)} | {latest - 2})
    jobs = [(b, w) for b in blocks if b <= latest - 1 for w in whos]

    def one(bw):
        b, who = bw
        for _ in range(3):
            try:
                s = fetch_snapshot(rpc, who, hex(b))
                return b, who, target_for(s, s["ts"]), s["targetFor"], cooled(s["streakOf"], s["ts"] - s["lastMintOf"]), \
                    cooled(s["fieldStreak"], s["ts"] - s["lastMintTime"])
            except Exception as e:
                err = e
        return b, who, None, str(err)[:80], 0, 0

    ok = bad = skip = 0
    with ThreadPoolExecutor(12) as ex:
        for b, who, mine, chain, ms, fs in ex.map(one, jobs):
            if mine is None:
                skip += 1
                print(f"skip block {b} {who[:10]}: {chain}")
            elif mine == chain:
                ok += 1
                if ms:
                    print(f"  ok block {b} {who[:10]} field {fs} + personal {ms} steps -> {bits(mine):.2f} bits")
            else:
                bad += 1
                print(f"MISMATCH block {b} who {who}: model {bits(mine):.4f} chain {bits(chain):.4f}")
    print(f"model vs targetFor(): {ok} match, {bad} mismatch, {skip} skipped ({len(blocks)} blocks x {len(whos)} addresses)")
    return bad == 0 and ok > 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", action="append", default=[], help='engine command, repeatable: "./miner_cpu" or "ssh -p PORT root@HOST"')
    ap.add_argument("--dry-run", action="store_true", help="never send; verify hits with digestOf() and eth_call mine() instead")
    ap.add_argument("--verify-hits", action="store_true", help="(dry run) check every new best against digestOf() on chain")
    ap.add_argument("--test-thr-bits", type=int, default=0, help="force a loose engine threshold of 2^-N (pipeline tests)")
    ap.add_argument("--cap-steps", type=int, default=6, help="report proofs up to this many difficulty steps above the target")
    ap.add_argument("--tip-gwei", type=float, default=0.75, help="priority fee (gwei); competitors: median 0.01, p80 0.5, max 1.0")
    ap.add_argument("--gas-limit", type=int, default=450_000)
    ap.add_argument("--max-wins", type=int, default=0)
    ap.add_argument("--poll", type=float, default=0.3, help="seconds between state polls per RPC")
    ap.add_argument("--anchor-refresh", type=int, default=200, help="new anchor after this many blocks")
    ap.add_argument("--status-every", type=float, default=3.0)
    ap.add_argument("--rpc", action="append", help="RPC URL (repeatable); default: Unichain public RPCs")
    ap.add_argument("--proxy", default="auto", help="auto (system proxy) | none | http://host:port")
    ap.add_argument("--key-file", default="~/.unicred/hot.key")
    ap.add_argument("--address-file", default="~/.unicred/hot.addr")
    ap.add_argument("--model-test", action="store_true", help="check the local target model against targetFor() on chain and exit")
    ap.add_argument("--flash", action="store_true", help="also use the flashblocks WebSocket feed (off by default)")
    ap.add_argument("--pending-rpc", action="append", help="RPC polled at the 'pending' (flashblock) tag, e.g. Alchemy (repeatable)")
    ap.add_argument("--send-rpc", action="append", default=["https://mainnet-sequencer.unichain.org"],
                    help="extra endpoints used only for eth_sendRawTransaction (default: the Unichain sequencer)")
    ap.add_argument("--stake-term", type=int, default=-1, choices=[-1, 0, 1, 2],
                    help="stake every unicorn won: 0=7d 1x, 1=14d 2x, 2=30d 4x, -1=don't stake (default). "
                         "Staking locks the unicorn for the whole term, with no early exit")
    ap.add_argument("--stake-ids", default="", help="comma-separated ids to stake at startup (already owned)")
    ap.add_argument("--presend", type=float, default=None,
                    help="off by default. Send a proof that turns valid at block B this many seconds after the earliest "
                         "moment block B-1 could be seen, instead of after actually seeing it. Depends on your latency: "
                         "calibrate it (see README) before relying on it")
    ap.add_argument("--presend-test", action="store_true", help="(dry run) fake a proof each race to test early-send timing")
    a = ap.parse_args()
    if a.model_test:
        sys.exit(0 if model_selftest(a) else 1)
    if not a.backend:
        ap.error("at least one --backend")
    Bot(a).run()


if __name__ == "__main__":
    main()
