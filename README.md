# unicred-rig

A GPU miner for [UNICRED](https://unicred.fun) on Unichain, with CUDA and Apple Metal backends, CPU fallback, and a Python controller for proof validation and transaction submission.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
mkdir -p ~/.unicred
chmod 700 ~/.unicred
```

Store the wallet private key in `~/.unicred/hot.key` and its address in `~/.unicred/hot.addr`, then run `chmod 600 ~/.unicred/hot.key`. Live mining requires funds on Unichain for minting and gas.

## Run locally

Build for your GPU:

NVIDIA (CUDA Toolkit):

```sh
nvcc -O3 -std=c++17 -arch=native -o miner miner.cu -lpthread
```

Apple silicon (macOS 11+ and Xcode Command Line Tools):

```sh
clang++ -O3 -std=c++17 -fobjc-arc -mmacosx-version-min=11.0 -framework Foundation -framework Metal -o miner miner_metal.mm
```

Then run:

```sh
DRY=1 ./run.sh ./miner  # validate without sending transactions
./run.sh ./miner        # live mining
```

Set `BOT_ARGS` for additional options; see `.venv/bin/python bot.py --help`.
For offline checks without a wallet, run `.venv/bin/python test_engine.py --engine ./miner`.

### SSH (optional)

To use a remote NVIDIA GPU host, replace `GPU_HOST` below:

```sh
./deploy.sh "ssh root@GPU_HOST"
DRY=1 ./run.sh "ssh root@GPU_HOST"  # validate without sending transactions
./run.sh "ssh root@GPU_HOST"        # live mining
```

Pass multiple SSH commands to use multiple hosts.

Unofficial project; not affiliated with UNICRED.
