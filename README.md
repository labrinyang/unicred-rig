# unicred-rig

A GPU miner for [UNICRED](https://unicred.fun) on Unichain, supporting NVIDIA CUDA and Apple Metal.

## Quick start

Requires Git, Python 3.10+, and either:

- **Apple silicon:** macOS 11+ and Xcode Command Line Tools (`xcode-select --install`).
- **NVIDIA on Linux:** an NVIDIA driver and the CUDA Toolkit (`nvcc` available).

```sh
git clone https://github.com/labrinyang/unicred-rig.git && cd unicred-rig && ./run.sh
```

The launcher installs Python dependencies, detects your GPU, builds the miner, and guides wallet setup. Later runs reuse the setup: `./run.sh`.

## Wallet setup

1. Choose **Create a dedicated mining wallet**, or **Import a private key**. To import, export a dedicated account's private key from your wallet app and paste it into the hidden prompt. The address is derived automatically; recovery phrases are not accepted.
2. Send ETH to the displayed address on **Unichain mainnet (chain ID 130)** for minting and gas. See [wallet and network setup](https://developers.uniswap.org/docs/unichain/getting-started/setting-up-a-wallet).
3. Press Enter to start live mining. Stop with Ctrl-C.

The private key stays in `~/.unicred/hot.key`, readable only by your user. Back up this file securely; it controls the wallet. Existing wallets are reused.

## Other modes

```sh
./run.sh --dry-run  # validate without sending transactions; only an address is needed
./run.sh --test     # offline GPU/protocol checks; no wallet needed
./run.sh --setup    # configure the wallet without mining
```

Pass bot options directly, e.g. `./run.sh --max-wins 5`. See `./run.sh --help`. `DRY=1` and `BOT_ARGS` remain supported.

For a remote NVIDIA GPU (optional), replace `GPU_HOST`:

```sh
./deploy.sh "ssh root@GPU_HOST"
./run.sh "ssh root@GPU_HOST"
```

Unofficial project; not affiliated with UNICRED.
