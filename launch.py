"""Prepare the local environment, select an engine, and guide first-run wallet setup."""
import hashlib
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent


class SetupError(Exception):
    pass


def bootstrap():
    if sys.version_info < (3, 10):
        raise SetupError("Python 3.10 or newer is required.")
    environment = ROOT / ".venv"
    python = environment / "bin/python"
    stamp = environment / ".requirements.sha256"
    digest = hashlib.sha256((ROOT / "requirements.txt").read_bytes()).hexdigest()
    if not python.exists():
        print("Creating Python environment...", flush=True)
        subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
    if not stamp.exists() or stamp.read_text() != digest:
        print("Installing Python dependencies...", flush=True)
        subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
                        "-r", str(ROOT / "requirements.txt")], check=True)
        stamp.write_text(digest)
    if Path(sys.prefix).resolve() != environment.resolve():
        os.execv(str(python), [str(python), str(ROOT / "launch.py"), *sys.argv[1:]])


def cuda_compiler():
    compiler = shutil.which("nvcc")
    if compiler:
        return compiler
    path = Path("/usr/local/cuda/bin/nvcc")
    return str(path) if path.is_file() and os.access(path, os.X_OK) else None


def select_engine(requested):
    if requested != "auto":
        return requested
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return "metal"
    if cuda_compiler():
        return "cuda"
    raise SetupError("No supported GPU toolchain found. Use Apple silicon with Xcode Command Line Tools, "
                     "or an NVIDIA GPU with CUDA Toolkit. For CPU testing: ./run.sh --engine cpu --test")


def build_spec(engine):
    sources = ["miner.cu", "keccak_core.h"]
    if engine == "metal":
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise SetupError("The Metal backend requires Apple silicon and macOS 11 or newer.")
        compiler = shutil.which("clang++")
        if not compiler:
            raise SetupError("Install Xcode Command Line Tools with xcode-select --install, then retry.")
        sources += ["miner_metal.mm", "metal_backend.h", "keccak_metal.h"]
        flags = ["-O3", "-std=c++17", "-fobjc-arc", "-mmacosx-version-min=11.0",
                 "-framework", "Foundation", "-framework", "Metal", "miner_metal.mm"]
    elif engine == "cuda":
        compiler = cuda_compiler()
        if not compiler:
            raise SetupError("Install the NVIDIA driver and CUDA Toolkit, then put nvcc on PATH.")
        flags = ["-O3", "-std=c++17", "-arch=native", "miner.cu", "-lpthread"]
    else:
        compiler = shutil.which("clang++") or shutil.which("g++")
        if not compiler:
            raise SetupError("Install a C++17 compiler (clang++ or g++) for the CPU backend.")
        flags = ["-O3", "-std=c++17", "-x", "c++", "miner.cu", "-lpthread"]
    return [compiler, *flags], sources


def check_engine(binary):
    result = subprocess.run([str(binary)], input="QUIT\n", text=True, capture_output=True, timeout=90)
    if result.returncode or "SELFTEST OK" not in result.stdout or "READY " not in result.stdout:
        raise SetupError("Engine selftest failed:\n" + result.stdout + result.stderr)


def build_engine(engine):
    command, sources = build_spec(engine)
    directory = ROOT / ".build"
    directory.mkdir(exist_ok=True)
    binary = directory / ("miner-" + engine)
    stamp = directory / (engine + ".sha256")
    digest = hashlib.sha256(shlex.join(command).encode())
    for source in sources:
        digest.update((ROOT / source).read_bytes())
    signature = digest.hexdigest()
    if not binary.exists() or not stamp.exists() or stamp.read_text() != signature:
        print(f"Building {engine} engine...", flush=True)
        fd, temporary = tempfile.mkstemp(prefix=engine + "-", dir=directory)
        os.close(fd)
        try:
            subprocess.run([*command, "-o", temporary], cwd=ROOT, check=True)
            check_engine(temporary)
            os.replace(temporary, binary)
            stamp.write_text(signature)
        finally:
            Path(temporary).unlink(missing_ok=True)
    else:
        check_engine(binary)
    print(f"{engine.capitalize()} engine ready.", flush=True)
    return shlex.quote(str(binary))


def parse_args(argv):
    import bot

    parser = bot.argument_parser()
    parser.description = "Set up and run UNICRED locally. First run guides wallet setup; later runs reuse it."
    parser.add_argument("--engine", choices=("auto", "metal", "cuda", "cpu"), default="auto",
                        help="local engine (default: auto-detect Metal or CUDA)")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--setup", action="store_true", help="configure the wallet without mining")
    modes.add_argument("--test", action="store_true", help="build and test offline, without a wallet or RPC")
    parser.add_argument("backends", nargs="*", metavar="BACKEND", help="optional local or SSH engine commands")
    extra = shlex.split(os.environ.get("BOT_ARGS", ""))
    if os.environ.get("DRY"):
        extra += ["--dry-run", "--verify-hits"]
    args = parser.parse_args([*extra, *argv])
    args.backend += args.backends
    if args.dry_run:
        args.verify_hits = True
    if args.model_test and (args.test or args.setup):
        parser.error("--model-test cannot be combined with --test or --setup")
    return args


def run(args):
    import bot
    from wallet import ensure_wallet

    if not args.backend and not args.setup and not args.model_test:
        args.backend = [build_engine(select_engine(args.engine))]
    if args.test:
        for backend in args.backend:
            subprocess.run([sys.executable, str(ROOT / "test_engine.py"), "--engine",
                            bot.normalize_backend(backend)], cwd=ROOT, check=True)
        return 0

    address, configured = ensure_wallet(args.key_file, args.address_file, args.dry_run or args.model_test)
    print(f"Wallet: {address}")
    if configured and not args.dry_run and not args.model_test:
        print("Fund this address with ETH on Unichain mainnet (chain ID 130) for minting and gas.\n"
              "Network setup: https://developers.uniswap.org/docs/unichain/getting-started/setting-up-a-wallet")
    if args.setup:
        print("Wallet ready. Start with ./run.sh, or validate with ./run.sh --dry-run.")
        return 0
    if args.model_test:
        return 0 if bot.model_selftest(args) else 1
    if configured and not args.dry_run:
        input("Press Enter after funding to start live mining, or Ctrl-C to exit: ")
    print("Starting dry run (no transactions)." if args.dry_run else "Starting live mining (spends ETH on minting and gas).",
          flush=True)
    bot.Bot(args).run()
    return 0


def main():
    bootstrap()
    from wallet import WalletError

    try:
        return run(parse_args(sys.argv[1:]))
    except WalletError as error:
        raise SetupError(str(error)) from None


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SetupError, OSError, subprocess.SubprocessError) as error:
        print(f"Setup failed: {error}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nStopped.", file=sys.stderr)
        sys.exit(130)
