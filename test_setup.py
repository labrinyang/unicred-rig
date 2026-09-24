"""Offline tests for first-run setup. All wallets and files are temporary test fixtures."""
import contextlib
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from eth_account import Account

import launch
import wallet


class WalletTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "wallet"
        self.key = self.directory / "hot.key"
        self.address = self.directory / "hot.addr"
        self.account = Account.from_key(bytes([1]) * 32)  # public test fixture, never funded
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))

    def configure(self, dry_run=False):
        return wallet.ensure_wallet(self.key, self.address, dry_run)

    def save_key(self, account=None):
        account = account or self.account
        wallet.write_new(self.key, "0x" + bytes(account.key).hex())

    def test_create_and_reuse_wallet_without_exposing_key(self):
        with patch("wallet.sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="1"), \
                patch("wallet.Account.create", return_value=self.account) as create:
            self.assertEqual(self.configure(), (self.account.address, True))
            self.assertEqual(self.configure(), (self.account.address, False))
            create.assert_called_once()
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(self.address.read_text().strip(), self.account.address)
        self.assertNotIn(bytes(self.account.key).hex(), self.output.getvalue())

    def test_import_retries_invalid_input_without_echoing_it(self):
        secret = bytes(self.account.key).hex()
        with patch("wallet.sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="2"), \
                patch("wallet.getpass.getpass", side_effect=["not-a-private-key", secret]) as hidden:
            self.assertEqual(self.configure(), (self.account.address, True))
            self.assertEqual(hidden.call_count, 2)
        self.assertNotIn(secret, self.output.getvalue())
        self.assertNotIn("not-a-private-key", self.output.getvalue())

    def test_reject_invalid_private_key_scalars(self):
        for value in ["00" * 32, "ff" * 32, "12" * 31, "one two three four"]:
            with self.subTest(value_length=len(value)), self.assertRaises(wallet.WalletError):
                wallet.account_from_key(value)

    def test_existing_key_recovers_missing_address_and_permissions(self):
        self.save_key()
        self.key.chmod(0o644)
        self.assertEqual(self.configure(), (self.account.address, True))
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        self.assertEqual(self.address.read_text().strip(), self.account.address)

    def test_mismatched_existing_files_are_not_replaced(self):
        self.save_key()
        other = Account.from_key(bytes([2]) * 32).address
        wallet.write_new(self.address, other)
        original = self.key.read_bytes()
        with self.assertRaises(wallet.WalletError):
            self.configure()
        self.assertEqual(self.key.read_bytes(), original)
        self.assertEqual(self.address.read_text().strip(), other)

    def test_wrong_import_for_address_only_wallet_does_not_save_key(self):
        wallet.write_new(self.address, self.account.address)
        with patch("wallet.sys.stdin.isatty", return_value=True), \
                patch("wallet.getpass.getpass", return_value="02" * 32), self.assertRaises(wallet.WalletError):
            self.configure()
        self.assertFalse(self.key.exists())

    def test_dry_run_only_needs_an_address(self):
        with patch("wallet.sys.stdin.isatty", return_value=True), \
                patch("builtins.input", return_value=self.account.address), patch("wallet.Account.create") as create:
            self.assertEqual(self.configure(dry_run=True), (self.account.address, True))
            self.assertEqual(self.configure(dry_run=True), (self.account.address, False))
            create.assert_not_called()
        self.assertFalse(self.key.exists())

    def test_noninteractive_setup_does_not_create_a_wallet(self):
        with patch("wallet.sys.stdin.isatty", return_value=False), self.assertRaises(wallet.WalletError):
            self.configure()
        self.assertFalse(self.directory.exists())

    def test_hidden_input_unavailable_does_not_fall_back_to_echo(self):
        with patch("wallet.sys.stdin.isatty", return_value=True), \
                patch("wallet.getpass.getpass", side_effect=wallet.getpass.GetPassWarning), \
                self.assertRaises(wallet.WalletError):
            wallet.import_account()

    def test_key_survives_failure_to_write_address(self):
        save = wallet.write_new

        def fail_address(path, value):
            if path == self.address:
                raise OSError("address write failed")
            save(path, value)

        with patch("wallet.sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="1"), \
                patch("wallet.Account.create", return_value=self.account), patch("wallet.write_new", side_effect=fail_address), \
                self.assertRaises(OSError):
            self.configure()
        self.assertTrue(self.key.exists())
        self.assertEqual(self.configure(), (self.account.address, True))

    def test_refuse_overwrite_and_symlink_key(self):
        self.save_key()
        original = self.key.read_bytes()
        with self.assertRaises(FileExistsError):
            wallet.write_new(self.key, "replacement")
        target = self.key.with_name("original.key")
        self.key.rename(target)
        self.key.symlink_to(target)
        with self.assertRaises(OSError):
            self.configure()
        self.assertEqual(target.read_bytes(), original)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {"BOT_ARGS": "", "DRY": ""}))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def test_legacy_backends_and_quoted_options(self):
        with patch.dict(os.environ, {"BOT_ARGS": '--rpc "https://example.com/rpc?a=1&b=2" --max-wins 5', "DRY": "1"}):
            args = launch.parse_args(["./miner", "ssh root@GPU_HOST", "--max-wins", "2"])
        self.assertEqual(args.backend, ["./miner", "ssh root@GPU_HOST"])
        self.assertEqual(args.rpc, ["https://example.com/rpc?a=1&b=2"])
        self.assertEqual(args.max_wins, 2)
        self.assertTrue(args.dry_run and args.verify_hits)

    def test_auto_selection_and_explicit_cpu(self):
        with patch("launch.platform.system", return_value="Darwin"), \
                patch("launch.platform.machine", return_value="arm64"):
            self.assertEqual(launch.select_engine("auto"), "metal")
        with patch("launch.platform.system", return_value="Linux"), \
                patch("launch.cuda_compiler", return_value="/toolchain/nvcc"):
            self.assertEqual(launch.select_engine("auto"), "cuda")
        with patch("launch.platform.system", return_value="Linux"), patch("launch.cuda_compiler", return_value=None):
            with self.assertRaises(launch.SetupError):
                launch.select_engine("auto")
            self.assertEqual(launch.select_engine("cpu"), "cpu")

    def test_missing_cuda_toolchain_gives_installation_guidance(self):
        with patch("launch.cuda_compiler", return_value=None), self.assertRaisesRegex(launch.SetupError, "CUDA Toolkit"):
            launch.build_spec("cuda")

    def test_test_mode_never_loads_wallet_or_starts_bot(self):
        with patch("launch.build_engine", return_value="./fake-miner"), \
                patch("launch.select_engine", return_value="metal"), patch("launch.subprocess.run") as run, \
                patch("wallet.ensure_wallet") as ensure, patch("bot.Bot") as bot:
            self.assertEqual(launch.run(launch.parse_args(["--test"])), 0)
            ensure.assert_not_called()
            bot.assert_not_called()
            self.assertIn("test_engine.py", run.call_args.args[0][1])

    def test_setup_mode_never_builds_or_mines(self):
        with patch("launch.build_engine") as build, \
                patch("wallet.ensure_wallet", return_value=("test-address", True)), patch("bot.Bot") as bot, \
                patch("builtins.input") as prompt:
            self.assertEqual(launch.run(launch.parse_args(["--setup"])), 0)
            build.assert_not_called()
            bot.assert_not_called()
            prompt.assert_not_called()

    def test_existing_wallet_starts_with_selected_engine(self):
        with patch("launch.build_engine", return_value="'path with spaces/miner'"), \
                patch("wallet.ensure_wallet", return_value=("test-address", False)), \
                patch("bot.Bot") as bot, patch("builtins.input") as prompt:
            args = launch.parse_args(["--engine", "cpu", "--dry-run", "--max-wins", "2"])
            self.assertEqual(launch.run(args), 0)
            self.assertEqual(args.backend, ["'path with spaces/miner'"])
            self.assertTrue(args.verify_hits)
            bot.return_value.run.assert_called_once()
            prompt.assert_not_called()

    def test_build_cache_rebuilds_on_source_change_and_preserves_working_binary_on_failure(self):
        with tempfile.TemporaryDirectory(prefix="setup test ") as directory:
            root = Path(directory)
            source = root / "source.cc"
            source.write_text("first")

            def compile_engine(command, **kwargs):
                Path(command[-1]).write_text("working engine")

            with patch("launch.ROOT", root), patch("launch.build_spec", return_value=(["compiler"], ["source.cc"])), \
                    patch("launch.subprocess.run", side_effect=compile_engine) as compile, patch("launch.check_engine"):
                first = launch.build_engine("metal")
                self.assertEqual(launch.build_engine("metal"), first)
                self.assertEqual(compile.call_count, 1)
                source.write_text("second")
                launch.build_engine("metal")
                self.assertEqual(compile.call_count, 2)
                source.write_text("third")
                compile.side_effect = subprocess.CalledProcessError(1, ["compiler"])
                with self.assertRaises(subprocess.CalledProcessError):
                    launch.build_engine("metal")
                self.assertEqual((root / ".build/miner-metal").read_text(), "working engine")
                self.assertEqual(sorted(p.name for p in (root / ".build").iterdir()), ["metal.sha256", "miner-metal"])

    def test_dependencies_are_installed_once_and_refreshed_when_requirements_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            requirements.write_text("example==1")
            environment = root / ".venv"

            def install(command, **kwargs):
                if "venv" in command:
                    (environment / "bin").mkdir(parents=True)
                    (environment / "bin/python").touch()

            with patch("launch.ROOT", root), patch("launch.sys.prefix", str(environment)), \
                    patch("launch.subprocess.run", side_effect=install) as run:
                launch.bootstrap()
                self.assertEqual(run.call_count, 2)
                launch.bootstrap()
                self.assertEqual(run.call_count, 2)
                requirements.write_text("example==2")
                launch.bootstrap()
                self.assertEqual(run.call_count, 3)


if __name__ == "__main__":
    unittest.main()
