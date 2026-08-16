"""Command-line entry point."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path

from icloudpy import ICloudPyService

from .backend import ICloudPyBackend
from .config import (
    DEFAULT_CONFIG_PATH,
    config_from_auth_args,
    load_config,
    save_config,
)
from .encryption_backend import (
    EncryptedBackend,
    create_recovery_public_bundle,
    load_recovery_public_bundle,
)
from .keybroker import KeyBrokerClient
from .coordination import ValkeyCoordinator
from .sms_auth import request_sms_code, trusted_phone_numbers, validate_sms_code
from .webdav import build_server


def _env_or(value: str | None, env_name: str) -> str | None:
    return value or os.environ.get(env_name)


def _path_from_config(value: str | Path, config_path: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config_path.expanduser().resolve().parent / path
    return path.resolve()


def _connect(args, *, interactive: bool):
    apple_id = _env_or(args.apple_id, "ICLOUD_APPLE_ID")
    if not apple_id:
        raise ValueError("Apple ID is required (--apple-id or ICLOUD_APPLE_ID)")
    password = os.environ.get(args.apple_password_env)
    if password is None and interactive:
        password = getpass.getpass(f"iCloud password for {apple_id} (blank = keyring): ") or None

    cookie_dir = _path_from_config(args.session_dir, args.config)
    cookie_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        cookie_dir.chmod(0o700)
    kwargs = {"cookie_directory": str(cookie_dir)}
    if args.region == "china":
        kwargs.update(
            home_endpoint="https://www.icloud.com.cn",
            setup_endpoint="https://setup.icloud.com.cn/setup/ws/1",
        )
    service = ICloudPyService(apple_id, password, **kwargs)

    if service.requires_2fa:
        if not interactive:
            raise RuntimeError("2FA is required; run `icloud-webdav auth` interactively")
        method = args.auth_method
        if method == "ask":
            method = (
                input("Two-factor method: trusted device or SMS [device/sms]: ")
                .strip()
                .lower()
                or "device"
            )
        if method == "sms":
            numbers = trusted_phone_numbers(service)
            if not numbers:
                raise RuntimeError("Apple returned no trusted phone numbers for SMS")
            for index, number in enumerate(numbers):
                label = (
                    number.get("numberWithDialCode")
                    or number.get("obfuscatedNumber")
                    or f"phone id {number['id']}"
                )
                print(f"[{index}] {label}")
            index = int(input("Select SMS destination [0]: ").strip() or "0")
            try:
                phone_number_id = int(numbers[index]["id"])
            except (IndexError, TypeError, ValueError) as exc:
                raise RuntimeError("invalid SMS destination selection") from exc
            request_sms_code(service, phone_number_id)
            code = input("Enter the SMS verification code: ").strip()
            if not validate_sms_code(service, phone_number_id, code):
                raise RuntimeError("the iCloud SMS verification code was rejected")
        elif method == "device":
            code = input("Enter the code shown on a trusted Apple device: ").strip()
            if not service.validate_2fa_code(code):
                raise RuntimeError("the iCloud 2FA code was rejected")
            if not service.is_trusted_session and not service.trust_session():
                raise RuntimeError(
                    "iCloud accepted the code but would not trust the session"
                )
        else:
            raise RuntimeError("two-factor method must be 'device' or 'sms'")
    elif service.requires_2sa:
        if not interactive:
            raise RuntimeError("2SA is required; run `icloud-webdav auth` interactively")
        devices = service.trusted_devices
        for index, device in enumerate(devices):
            label = device.get("deviceName") or f"SMS to {device.get('phoneNumber', '?')}"
            print(f"[{index}] {label}")
        index = int(input("Select verification device [0]: ").strip() or "0")
        device = devices[index]
        if not service.send_verification_code(device):
            raise RuntimeError("could not send the iCloud verification code")
        code = input("Enter verification code: ").strip()
        if not service.validate_verification_code(device, code):
            raise RuntimeError("the iCloud verification code was rejected")
    return service


def _add_icloud_args(
    parser: argparse.ArgumentParser,
    defaults: dict,
    config_path: Path,
) -> None:
    parser.add_argument("--config", type=Path, default=config_path)
    parser.add_argument(
        "--apple-id",
        default=defaults.get("apple_id"),
        help="Apple ID; or set ICLOUD_APPLE_ID",
    )
    parser.add_argument(
        "--apple-password-env",
        default=defaults.get("apple_password_env", "ICLOUD_PASSWORD"),
        help="environment variable containing the iCloud password",
    )
    parser.add_argument(
        "--session-dir", default=defaults.get("session_dir", ".state/icloudpy")
    )
    parser.add_argument(
        "--region",
        choices=("global", "china"),
        default=defaults.get("region", "global"),
    )
    parser.add_argument(
        "--auth-method",
        choices=("ask", "device", "sms"),
        default=defaults.get("auth_method", "ask"),
        help="2FA delivery method (default: ask interactively)",
    )


def make_parser(
    config: dict | None = None,
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> argparse.ArgumentParser:
    config = config or load_config(config_path)
    icloud_defaults = config.get("icloud", {})
    webdav_defaults = config.get("webdav", {})
    database_defaults = config.get("database", {})
    valkey_defaults = config.get("valkey", {})
    key_broker_defaults = config.get("key_broker", {})
    encryption_defaults = config.get("encryption", {})
    parser = argparse.ArgumentParser(prog="icloud-webdav")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    auth = sub.add_parser("auth", help="authenticate and persist an iCloud session")
    _add_icloud_args(auth, icloud_defaults, config_path)
    auth.add_argument(
        "--save-config",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="save non-secret settings after authentication (default: enabled)",
    )

    encryption_init = sub.add_parser(
        "encryption-init",
        help="create offline recovery material and enable encrypted Drive mode",
    )
    encryption_init.add_argument("--config", type=Path, default=config_path)
    encryption_init.add_argument(
        "--recovery-public-file",
        type=Path,
        default=Path(
            encryption_defaults.get(
                "recovery_public_file", ".state/recovery-public.json"
            )
        ),
    )
    encryption_init.add_argument(
        "--kem", choices=("ML-KEM-768", "ML-KEM-1024"), default="ML-KEM-768"
    )

    rewrap = sub.add_parser(
        "rewrap-keys",
        help="append and verify a new primary KEK envelope using offline recovery",
    )
    _add_icloud_args(rewrap, icloud_defaults, config_path)
    rewrap.add_argument("--database-url", default=database_defaults.get("url"))
    rewrap.add_argument(
        "--database-url-env", default=database_defaults.get("url_env", "DATABASE_URL")
    )
    rewrap.add_argument(
        "--key-broker-endpoint",
        default=key_broker_defaults.get(
            "endpoint", "unix:///run/keybroker/keybroker.sock"
        ),
    )
    rewrap.add_argument(
        "--key-broker-ca", type=Path,
        default=key_broker_defaults.get("ca"),
    )
    rewrap.add_argument(
        "--key-broker-cert", type=Path,
        default=key_broker_defaults.get("cert"),
    )
    rewrap.add_argument(
        "--key-broker-key", type=Path,
        default=key_broker_defaults.get("key"),
    )
    rewrap.add_argument(
        "--encryption-vault-folder",
        default=encryption_defaults.get("vault_folder", ".icloud-ftp-vault"),
    )
    rewrap.add_argument(
        "--drive-cache-seconds",
        type=int,
        default=int(icloud_defaults.get("drive_cache_seconds", 0)),
    )
    rewrap.add_argument(
        "--finalize",
        action="store_true",
        help="remove old primary envelopes after every new envelope is verified",
    )

    serve = sub.add_parser("serve", help="start the encrypted WebDAV gateway")
    _add_icloud_args(serve, icloud_defaults, config_path)
    serve.add_argument("--host", default=webdav_defaults.get("host", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=webdav_defaults.get("port", 8080))
    serve.add_argument("--webdav-user", default=webdav_defaults.get("user", "icloud"))
    serve.add_argument(
        "--webdav-password-env",
        default=webdav_defaults.get("password_env", "ICLOUD_WEBDAV_PASSWORD"),
    )
    cert_default = webdav_defaults.get("certfile")
    key_default = webdav_defaults.get("keyfile")
    serve.add_argument("--certfile", type=Path, default=Path(cert_default) if cert_default else None)
    serve.add_argument("--keyfile", type=Path, default=Path(key_default) if key_default else None)
    serve.add_argument(
        "--allow-insecure-remote",
        action="store_true",
        default=bool(webdav_defaults.get("allow_insecure_remote", False)),
    )
    serve.add_argument("--non-interactive", action="store_true")
    serve.add_argument(
        "--drive-cache-seconds",
        type=int,
        default=int(icloud_defaults.get("drive_cache_seconds", 5)),
        help="seconds to cache iCloud Drive metadata; 0 always refreshes",
    )
    serve.add_argument("--database-url", default=database_defaults.get("url"))
    serve.add_argument(
        "--database-url-env", default=database_defaults.get("url_env", "DATABASE_URL")
    )
    serve.add_argument("--valkey-url", default=valkey_defaults.get("url"))
    serve.add_argument(
        "--valkey-url-env", default=valkey_defaults.get("url_env", "VALKEY_URL")
    )
    serve.add_argument(
        "--valkey-namespace", default=valkey_defaults.get("namespace", "default")
    )
    serve.add_argument(
        "--valkey-lock-ttl", type=int, default=int(valkey_defaults.get("lock_ttl", 120))
    )
    serve.add_argument(
        "--encryption",
        action=argparse.BooleanOptionalAction,
        default=bool(encryption_defaults.get("enabled", False)),
        help="store iCloud Drive content as encrypted opaque objects",
    )
    serve.add_argument(
        "--recovery-public-file",
        type=Path,
        default=Path(
            encryption_defaults.get(
                "recovery_public_file", ".state/recovery-public.json"
            )
        ),
    )
    serve.add_argument(
        "--key-broker-endpoint",
        default=key_broker_defaults.get(
            "endpoint", "unix:///run/keybroker/keybroker.sock"
        ),
    )
    serve.add_argument(
        "--key-broker-ca", type=Path,
        default=key_broker_defaults.get("ca"),
    )
    serve.add_argument(
        "--key-broker-cert", type=Path,
        default=key_broker_defaults.get("cert"),
    )
    serve.add_argument(
        "--key-broker-key", type=Path,
        default=key_broker_defaults.get("key"),
    )
    serve.add_argument(
        "--recovery-mode",
        action="store_true",
        help="read-only mode unlocked by an interactively supplied recovery secret",
    )
    serve.add_argument(
        "--encryption-vault-folder",
        default=encryption_defaults.get("vault_folder", ".icloud-ftp-vault"),
    )
    serve.add_argument(
        "--encryption-strict-plaintext",
        action=argparse.BooleanOptionalAction,
        default=bool(encryption_defaults.get("strict_plaintext", True)),
        help="refuse to mix existing plaintext Drive items with the vault",
    )
    serve.add_argument(
        "--kem", choices=("ML-KEM-768", "ML-KEM-1024"),
        default=encryption_defaults.get("kem", "ML-KEM-768"),
    )
    serve.add_argument(
        "--hybrid-x25519", action=argparse.BooleanOptionalAction,
        default=bool(encryption_defaults.get("hybrid_x25519", False)),
    )
    serve.add_argument(
        "--chunk-size-mb", type=int,
        default=int(encryption_defaults.get("chunk_size_mb", 8)),
    )
    serve.add_argument(
        "--retention-days", type=int,
        default=int(encryption_defaults.get("retention_days", 30)),
    )
    for option, fallback in (
        ("small-versions", 10), ("medium-versions", 5), ("large-versions", 3)
    ):
        serve.add_argument(
            f"--{option}", type=int,
            default=int(encryption_defaults.get(option.replace("-", "_"), fallback)),
        )
    serve.add_argument(
        "--capacity-limit-gb", type=int,
        default=int(encryption_defaults.get("capacity_limit_gb", 0)),
    )
    return parser


def _config_path(argv: list[str]) -> Path:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    known, _ = pre_parser.parse_known_args(argv)
    return known.config


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    config_path = _config_path(argv)
    try:
        loaded_config = load_config(config_path)
    except Exception as exc:
        print(f"error: could not read config {config_path}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    parser = make_parser(loaded_config, config_path)
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        if args.command == "encryption-init":
            public_path = _path_from_config(args.recovery_public_file, args.config)
            recovery_secret = create_recovery_public_bundle(public_path, kem=args.kem)
            saved = loaded_config
            saved["encryption"].update(
                {
                    "enabled": True,
                    "recovery_public_file": str(args.recovery_public_file),
                    "kem": args.kem,
                    "vault_folder": saved["encryption"].get(
                        "vault_folder", ".icloud-ftp-vault"
                    ),
                    "strict_plaintext": True,
                }
            )
            save_config(args.config, saved)
            print(f"Recovery public bundle created at {public_path}")
            print(f"Encrypted mode enabled in {args.config.expanduser().resolve()}")
            print("\nOFFLINE RECOVERY SECRET (shown once):")
            print(recovery_secret)
            print(
                "\nMove this secret to an air-gapped recovery ceremony and split it "
                "with an independently audited 3-of-5 tool. Do not save it on this server."
            )
            return

        if args.command == "auth":
            service = _connect(args, interactive=True)
            count = len(service.drive.dir())
            # Save the resolved Apple ID (including an environment fallback),
            # never either password.
            args.apple_id = _env_or(args.apple_id, "ICLOUD_APPLE_ID")
            if args.save_config:
                saved = config_from_auth_args(args, loaded_config)
                save_config(args.config, saved)
                print(f"Settings saved to {args.config.expanduser().resolve()}")
            print(f"Authentication succeeded; iCloud Drive root has {count} item(s).")
            return

        if args.command == "rewrap-keys":
            database_url = args.database_url or os.environ.get(args.database_url_env)
            if not database_url or not database_url.startswith(
                ("postgresql://", "postgres://")
            ):
                raise ValueError("rewrap requires the production PostgreSQL DATABASE_URL")
            secret_text = getpass.getpass("Offline recovery secret (hex): ").strip()
            try:
                recovery_secret = bytes.fromhex(secret_text)
            except ValueError as error:
                raise ValueError("recovery secret must be hexadecimal") from error
            if len(recovery_secret) != 32:
                raise ValueError("recovery secret must decode to 32 bytes")
            new_broker = KeyBrokerClient(
                args.key_broker_endpoint,
                cafile=(
                    _path_from_config(args.key_broker_ca, args.config)
                    if args.key_broker_ca
                    else None
                ),
                certfile=(
                    _path_from_config(args.key_broker_cert, args.config)
                    if args.key_broker_cert
                    else None
                ),
                keyfile=(
                    _path_from_config(args.key_broker_key, args.config)
                    if args.key_broker_key
                    else None
                ),
            )
            service = _connect(args, interactive=True)
            raw_backend = ICloudPyBackend(
                service, cache_seconds=args.drive_cache_seconds
            )
            backend = EncryptedBackend(
                raw_backend,
                key=recovery_secret,
                key_broker=new_broker,
                database=database_url,
                vault_folder=args.encryption_vault_folder,
                strict_plaintext=True,
            )
            try:
                backend.list("/")
                result = backend.rewrap_primary_keys(
                    new_broker, finalize=args.finalize
                )
            finally:
                backend.close()
            print(
                f"Rewrap verified: {result['capsules']} capsule(s), "
                f"changed {result['changed']}, finalized={bool(result['finalized'])}"
            )
            return

        service = _connect(args, interactive=not args.non_interactive)
        if not args.encryption:
            raise ValueError(
                "this WebDAV gateway requires encrypted CAS mode; run "
                "`icloud-webdav encryption-init`"
            )
        database_url = args.database_url or os.environ.get(args.database_url_env)
        if not database_url:
            raise ValueError(f"PostgreSQL URL is required in {args.database_url_env}")
        if not database_url.startswith(("postgresql://", "postgres://")):
            raise ValueError("production state database must be PostgreSQL")
        valkey_url = args.valkey_url or os.environ.get(args.valkey_url_env)
        valkey_config = loaded_config.get("valkey", {})
        coordinator = ValkeyCoordinator(
            valkey_url,
            namespace=args.valkey_namespace,
            lock_ttl=args.valkey_lock_ttl,
            change_limit=int(valkey_config.get("change_limit", 1000)),
            delete_ratio=int(valkey_config.get("delete_ratio_percent", 20)) / 100,
        )
        raw_backend = ICloudPyBackend(service, cache_seconds=args.drive_cache_seconds)
        recovery_public_path = _path_from_config(
            args.recovery_public_file, args.config
        )
        encryption_config = loaded_config.get("encryption", {})
        if args.recovery_mode:
            if args.non_interactive:
                raise ValueError("recovery mode requires interactive secret entry")
            secret_text = getpass.getpass("Offline recovery secret (hex): ").strip()
            try:
                recovery_secret = bytes.fromhex(secret_text)
            except ValueError as error:
                raise ValueError("recovery secret must be hexadecimal") from error
            if len(recovery_secret) != 32:
                raise ValueError("recovery secret must decode to 32 bytes")
            key_broker = None
            recovery_public = None
        else:
            recovery_secret = None
            recovery_public = load_recovery_public_bundle(recovery_public_path)
            key_broker = KeyBrokerClient(
                args.key_broker_endpoint,
                cafile=(
                    _path_from_config(args.key_broker_ca, args.config)
                    if args.key_broker_ca
                    else None
                ),
                certfile=(
                    _path_from_config(args.key_broker_cert, args.config)
                    if args.key_broker_cert
                    else None
                ),
                keyfile=(
                    _path_from_config(args.key_broker_key, args.config)
                    if args.key_broker_key
                    else None
                ),
            )
        backend = EncryptedBackend(
            raw_backend,
            key=recovery_secret,
            key_broker=key_broker,
            recovery_public=recovery_public,
            database=database_url,
            vault_folder=args.encryption_vault_folder,
            strict_plaintext=args.encryption_strict_plaintext,
            kem=args.kem,
            hybrid_x25519=args.hybrid_x25519,
            chunk_size=args.chunk_size_mb * 1024 * 1024,
            retention_days=args.retention_days,
            small_versions=args.small_versions,
            medium_versions=args.medium_versions,
            large_versions=args.large_versions,
            medium_threshold=int(encryption_config.get("medium_threshold_mb", 100))
            * 1024
            * 1024,
            large_threshold=int(encryption_config.get("large_threshold_mb", 1024))
            * 1024
            * 1024,
            capacity_limit=args.capacity_limit_gb * 1024 * 1024 * 1024,
        )
        backend.list("/")
        webdav_password = os.environ.get(args.webdav_password_env)
        if webdav_password is None and not args.non_interactive:
            webdav_password = getpass.getpass("WebDAV password: ")
        if not webdav_password:
            raise ValueError(
                f"WebDAV password is required in {args.webdav_password_env} or via prompt"
            )
        server = build_server(
            backend,
            host=args.host,
            port=args.port,
            username=args.webdav_user,
            password=webdav_password,
            coordinator=coordinator,
            read_only=args.recovery_mode,
            certfile=(
                _path_from_config(args.certfile, args.config) if args.certfile else None
            ),
            keyfile=(
                _path_from_config(args.keyfile, args.config) if args.keyfile else None
            ),
            allow_insecure_remote=args.allow_insecure_remote,
        )
        scheme = "https" if args.certfile else "http"
        print(f"Serving encrypted iCloud storage via WebDAV at {scheme}://{args.host}:{args.port}")
        try:
            server.serve_forever()
        finally:
            server.server_close()
            backend.close()
    except KeyboardInterrupt:
        print("Stopped.")
    except Exception as exc:
        if args.verbose:
            raise
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
