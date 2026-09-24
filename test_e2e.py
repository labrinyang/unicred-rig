# End-to-end: live chain state -> job exactly as bot.py builds it -> ./miner_cpu over the line protocol -> HIT ->
# eth_call mine() with the calldata bot.py would send. State overrides make the target easy (target=MAX, field streak 0)
# and pin prevWork, so a CPU-found proof must pass every check in mine(); a control call without the override must BadProof.
import subprocess, time, sys
import bot as B

rpc = B.Rpc(B.DEFAULT_RPCS, B.detect_proxy("auto"))
me = open(B.os.path.expanduser("~/.unicred/hot.addr")).read().strip()
s = B.fetch_snapshot(rpc, me)
anchor, ah = s["block"] - 1, s["lastBlockHash"]
blk = rpc.call("eth_getBlockByNumber", [hex(anchor), False])
print("anchor hash matches eth_getBlockByNumber:", blk["hash"] == "0x" + ah.hex())

class A: test_thr_bits = 0; cap_steps = 6
bb = B.Bot.__new__(B.Bot); bb.a = A(); bb.me = me; bb.job_seq = 0; bb.backends = []
j = bb.new_job(s)
floor = B.epoch_floor(s["minted"] + 1)
thr = floor >> 192
eng = subprocess.Popen(["./miner_cpu"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
eng.stdin.write(f"JOB {j['id']} {j['msg184'].hex()} {thr:016x}\n"); eng.stdin.flush()
t0 = time.time(); hit = None
for line in eng.stdout:
    p = line.split()
    if p[0] == "HIT":
        low, top = int(p[2], 16), int(p[3], 16)
        d = int.from_bytes(B.k256(j["msg184"] + low.to_bytes(8, "big")), "big")
        if d < floor: hit = (low, d); break
eng.stdin.write("QUIT\n"); eng.stdin.flush(); eng.wait()
print(f"CPU engine found a proof below the epoch floor in {time.time()-t0:.1f}s: {B.bits(hit[1]):.2f} bits (floor {B.bits(floor):.2f})")
price = B.price_of(s["minted"] + 1)
data = bb.calldata_mine(j, hit[0], price)
call = {"from": me, "to": B.CONTRACT, "data": data, "value": hex(price), "gas": hex(450000)}
slot = lambda n: "0x" + n.to_bytes(32, "big").hex()
easy = {me: {"balance": hex(10**18)}, B.CONTRACT: {"stateDiff": {
    slot(13): "0x" + j["prev"].hex(), slot(14): slot(B.MAX_TARGET), slot(17): slot(0), slot(18): slot(0)}}}
try:
    r = rpc.call("eth_call", [call, "latest", easy]); print("eth_call mine() with easy-target override: SUCCESS", r)
except B.RpcError as e:
    print("eth_call mine() with override REVERTED:", bb.decode_err(e) if hasattr(bb, "decode_err") else e); sys.exit(1)
real = {me: {"balance": hex(10**18)}, B.CONTRACT: {"stateDiff": {slot(13): "0x" + j["prev"].hex(), slot(17): slot(0)}}}
try:
    rpc.call("eth_call", [call, "latest", real]); print("control without easy target: unexpectedly succeeded")
except B.RpcError as e:
    print("control (real target):", B.Bot.decode_err(bb, e))
wrong_price = {"from": me, "to": B.CONTRACT, "data": bb.calldata_mine(j, hit[0], price - 1), "value": hex(price), "gas": hex(450000)}
try:
    rpc.call("eth_call", [wrong_price, "latest", easy]); print("maxPrice control: unexpectedly succeeded")
except B.RpcError as e:
    print("control (maxPrice = price-1):", B.Bot.decode_err(bb, e))
