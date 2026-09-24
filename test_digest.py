# Test (a): keccak_core.h (via ./test_core) == pycryptodome keccak of the full 192-byte msg == contract digestOf() on chain.
import os, json, subprocess, http.client
from Crypto.Hash import keccak
C = "f60de24f228dc7ca6ff025958d2ee3a956ed88e5"
DOMAIN = bytes.fromhex("d38d03374ffe0ab0595a37e26339a924c9bf9d87e54292dabb07b3bddb3cc04e")
def k256(b): h = keccak.new(digest_bits=256); h.update(b); return h.digest()
def w(x): return x.rjust(32, b"\0")
conn = http.client.HTTPSConnection("mainnet.unichain.org", 443, timeout=20)
def eth_call(data):
    conn.request("POST", "/", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": "0x" + C, "data": data}, "latest"]}),
                 {"content-type": "application/json", "user-agent": "Mozilla/5.0"})
    return json.loads(conn.getresponse().read())["result"]
sel = k256(b"digestOf(bytes32,bytes32,address,uint256)")[:4]
ok = 0
for trial in range(5):
    anchor, prev, miner, nonce_high = os.urandom(32), os.urandom(32), os.urandom(20), os.urandom(24)
    challenge = k256(anchor + prev)
    msg184 = DOMAIN + w((130).to_bytes(2, "big")) + w(bytes.fromhex(C)) + challenge + w(miner) + nonce_high
    assert len(msg184) == 184
    lows = [int.from_bytes(os.urandom(8), "big") for _ in range(3)]
    out = subprocess.run(["./test_core", msg184.hex()] + [f"{n:016x}" for n in lows], capture_output=True, text=True).stdout.split("\n")
    for n, line in zip(lows, out):
        top_c, dig_c = line.split()
        full = msg184 + n.to_bytes(8, "big")
        dig_py = k256(full).hex()
        nonce = int.from_bytes(nonce_high + n.to_bytes(8, "big"), "big")
        data = "0x" + (sel + anchor + prev + w(miner) + nonce.to_bytes(32, "big")).hex()
        dig_chain = eth_call(data)[2:]
        good = dig_c == dig_py == dig_chain and top_c == dig_py[:16]
        ok += good
        if not good: print("MISMATCH", n, dig_c, dig_py, dig_chain, top_c)
print(f"digest checks passed: {ok}/15")
