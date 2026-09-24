"""Local wallet setup. Private keys are never accepted as arguments or printed."""
import getpass
import os
from pathlib import Path
import re
import stat
import sys
import warnings

from eth_account import Account
from eth_utils import is_address, to_checksum_address


class WalletError(Exception):
    pass


def account_from_key(value):
    value = value.strip()
    if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", value):
        raise WalletError("Enter a 64-digit private key, optionally prefixed with 0x; not a recovery phrase.")
    try:
        return Account.from_key(value)
    except (ValueError, TypeError):
        raise WalletError("Invalid private key. Check the key exported from your wallet.") from None


def read_account(path):
    # Do not follow a link when reading or changing permissions on a secret file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise WalletError("The private key must be a regular file owned by your user.")
        os.fchmod(file.fileno(), 0o600)
        return account_from_key(file.read(256))


def write_new(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(value + "\n")
        file.flush()
        os.fsync(file.fileno())


def read_address(path):
    address = path.read_text().strip()
    if not is_address(address):
        raise WalletError("Invalid wallet address in the address file.")
    return to_checksum_address(address)


def require_terminal():
    if not sys.stdin.isatty():
        raise WalletError("Wallet setup needs an interactive terminal. Run ./run.sh --setup first.")


def import_account():
    require_terminal()
    while True:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                value = getpass.getpass("Private key (hidden input): ")
        except getpass.GetPassWarning:
            raise WalletError("Hidden input is unavailable. Use a terminal to import the wallet.") from None
        try:
            return account_from_key(value)
        except WalletError as error:
            print(error)


def ensure_wallet(key_file, address_file, dry_run=False):
    """Return (address, newly_configured), preserving any existing wallet identity."""
    key_path = Path(key_file).expanduser()
    address_path = Path(address_file).expanduser()
    if key_path == address_path:
        raise WalletError("Key and address files must be different paths.")
    address = read_address(address_path) if address_path.exists() else None
    if dry_run and address:
        return address, False

    new_key = False
    if key_path.exists() or key_path.is_symlink():
        account = read_account(key_path)
    else:
        require_terminal()
        if dry_run:
            while True:
                address = input("Wallet address for dry run (0x..., no private key needed): ").strip()
                if is_address(address):
                    address = to_checksum_address(address)
                    write_new(address_path, address)
                    return address, True
                print("Enter a valid Ethereum wallet address.")
        if address:
            print(f"Import the private key for the configured address: {address}")
            account = import_account()
        else:
            print("Wallet setup\n  1. Create a dedicated mining wallet\n  2. Import a private key")
            choice = input("Choose [1/2, default 1]: ").strip() or "1"
            while choice not in ("1", "2"):
                choice = input("Choose 1 or 2: ").strip()
            account = Account.create() if choice == "1" else import_account()
        new_key = True

    if address and address.lower() != account.address.lower():
        raise WalletError("Private key does not match the configured address. Existing files were kept.")
    if new_key:
        write_new(key_path, "0x" + bytes(account.key).hex())
    if not address:
        write_new(address_path, account.address)
    if new_key:
        print(f"Private key saved locally: {key_path}\nBack up this file securely; it controls this wallet.")
    return account.address, new_key or address is None
