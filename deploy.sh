#!/usr/bin/env bash
# Deploy the hash engine to a GPU box and benchmark it.
#   ./deploy.sh "ssh -p 41234 root@ssh4.vast.ai"      (paste the provider's SSH command; -L forwards are dropped)
# Copies miner.cu + keccak_core.h to /root/rig, builds with nvcc (native arch, else PTX the driver JITs), runs --bench.
set -euo pipefail
cd "$(dirname "$0")"
[ $# -ge 1 ] || { echo "usage: $0 \"ssh -p PORT root@HOST\""; exit 2; }

# strip "-L a:b:c" port forwards and a trailing remote command, keep options + host
read -r -a P <<< "$1"
SSH=(ssh -T -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=10 -o LogLevel=ERROR)
i=1
while [ $i -lt ${#P[@]} ]; do
  a="${P[$i]}"
  case "$a" in
    -L) i=$((i + 2)); continue ;;
    -[bcDEeFIiJlmOoPpQRSWw]) SSH+=("$a" "${P[$((i + 1))]}"); i=$((i + 2)); continue ;;
    -*) SSH+=("$a"); i=$((i + 1)); continue ;;
    *) SSH+=("$a"); break ;;
  esac
done
echo ">> ${SSH[*]}"

"${SSH[@]}" 'mkdir -p /root/rig && touch ~/.no_auto_tmux'
tar czf - miner.cu keccak_core.h | "${SSH[@]}" 'tar xzf - -C /root/rig'
echo ">> sources copied to /root/rig"

"${SSH[@]}" 'bash -s' <<'REMOTE'
set -u
cd /root/rig
echo "== GPUs"
nvidia-smi --query-gpu=index,name,driver_version,compute_cap,power.limit --format=csv,noheader || { echo "!! nvidia-smi failed"; exit 1; }
nvidia-smi | grep -m1 "CUDA Version" || true

find_nvcc() {
  command -v nvcc 2>/dev/null && return
  ls -d /usr/local/cuda*/bin/nvcc 2>/dev/null | sort -V | tail -1
}
NVCC=$(find_nvcc || true)
if [ -z "$NVCC" ]; then
  echo "== nvcc not found; installing from the NVIDIA apt repo"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  if ! apt-cache policy 2>/dev/null | grep -q developer.download.nvidia.com; then
    . /etc/os-release
    V=$(echo "$VERSION_ID" | tr -d .)
    (command -v wget >/dev/null || apt-get install -y -qq wget >/dev/null 2>&1)
    wget -q "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu${V}/x86_64/cuda-keyring_1.1-1_all.deb" -O /tmp/ck.deb \
      && dpkg -i /tmp/ck.deb >/dev/null && apt-get update -qq >/dev/null 2>&1
  fi
  for v in 12-9 12-8 13-0 12-6 12-4; do
    if apt-get install -y -qq "cuda-nvcc-$v" "cuda-cudart-dev-$v" >/dev/null 2>&1; then echo "installed cuda-nvcc-$v"; break; fi
  done
  NVCC=$(find_nvcc || true)
  [ -n "$NVCC" ] || { echo "!! could not install nvcc; use an image with the CUDA toolkit (e.g. nvidia/cuda:12.8.1-devel-ubuntu22.04)"; exit 1; }
fi
echo "== nvcc: $NVCC ($("$NVCC" --version | grep -o 'release [0-9.]*'))"

build() { "$NVCC" -O3 -std=c++17 "$@" -o miner.new miner.cu -lpthread -Xptxas -v > build.log 2>&1 && mv miner.new miner; }
CC=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -1 | tr -d .)
PATHUSED=""
if build -arch=native; then PATHUSED="native (-arch=native)";
elif build -gencode "arch=compute_${CC},code=sm_${CC}"; then PATHUSED="sm_${CC} SASS";
else
  for ptx in 120 100 90 89 86 80 75; do
    if [ "$ptx" -le "$CC" ] && build -gencode "arch=compute_${ptx},code=compute_${ptx}"; then
      PATHUSED="PTX compute_${ptx} (driver JIT-compiles it for sm_${CC}; first launch may take a few seconds)"; break
    fi
  done
fi
if [ -z "$PATHUSED" ]; then echo "!! build failed:"; tail -30 build.log; exit 1; fi
echo "== built: $PATHUSED"
grep -m2 -E "registers|spill" build.log || true
echo "== bench"
./miner --bench 5
REMOTE
echo ">> done. Start the bot with:  .venv/bin/python bot.py --backend \"$1\"   (add --dry-run first)"
