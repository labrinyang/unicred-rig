# unicred-rig

A multi-GPU miner for [UNICRED](https://unicred.fun) on Unichain, with a CUDA hash engine, CPU fallback, and a Python controller for proof validation and transaction submission.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
mkdir -p ~/.unicred
chmod 700 ~/.unicred
```

Store the wallet private key in `~/.unicred/hot.key` and its address in `~/.unicred/hot.addr`, then run `chmod 600 ~/.unicred/hot.key`. Live mining requires funds on Unichain for minting and gas.

## Run (SSH)

Replace `GPU_HOST` with your GPU host:

```sh
./deploy.sh "ssh root@GPU_HOST"
DRY=1 ./run.sh "ssh root@GPU_HOST"  # validate without sending transactions
./run.sh "ssh root@GPU_HOST"        # live mining
```

Pass multiple SSH commands to use multiple hosts. Set `BOT_ARGS` for additional options; see `.venv/bin/python bot.py --help`.

### Local (optional)

With an NVIDIA GPU and CUDA Toolkit installed, build and run the engine locally:

```sh
nvcc -O3 -std=c++17 -arch=native -o miner miner.cu -lpthread
DRY=1 ./run.sh ./miner  # validate without sending transactions
./run.sh ./miner        # live mining
```

Unofficial project; not affiliated with UNICRED.
