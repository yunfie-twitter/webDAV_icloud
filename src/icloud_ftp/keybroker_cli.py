"""Host-side Key Broker service entry point."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from .keybroker import (
    HsmProvider,
    LinuxTpmUnsealProvider,
    LinuxTpmRsaProvider,
    SoftwareProvider,
    TcpKeyBrokerServer,
    UnixKeyBrokerServer,
    WindowsCngProvider,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="icloud-keybroker")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--provider",
        required=True,
        choices=("linux-tpm", "linux-tpm-unseal", "windows-cng", "hsm", "software"),
    )
    parser.add_argument("--socket", type=Path)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--tpm-context", type=Path)
    parser.add_argument("--tpm-public-key", type=Path)
    parser.add_argument("--provider-helper", type=Path)
    parser.add_argument("--software-key", type=Path)
    parser.add_argument("--ca", type=Path)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--max-concurrent", type=int, default=8)
    parser.add_argument("--max-requests-per-minute", type=int, default=600)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.provider == "linux-tpm":
        if not args.tpm_context or not args.tpm_public_key:
            raise SystemExit(
                "--tpm-context and --tpm-public-key are required for linux-tpm"
            )
        provider = LinuxTpmRsaProvider(
            str(args.tpm_context), args.tpm_public_key
        )
    elif args.provider == "linux-tpm-unseal":
        if not args.tpm_context:
            raise SystemExit("--tpm-context is required for linux-tpm-unseal")
        provider = LinuxTpmUnsealProvider(args.tpm_context)
    elif args.provider in {"windows-cng", "hsm"}:
        if not args.provider_helper:
            raise SystemExit("--provider-helper is required")
        provider = (
            WindowsCngProvider(args.provider_helper)
            if args.provider == "windows-cng"
            else HsmProvider(args.provider_helper)
        )
    else:
        if os.environ.get("ICLOUD_ALLOW_SOFTWARE_KEYBROKER") != "development-only":
            raise SystemExit(
                "software provider is disabled; set "
                "ICLOUD_ALLOW_SOFTWARE_KEYBROKER=development-only explicitly"
            )
        if not args.software_key:
            raise SystemExit("--software-key is required for software provider")
        material = args.software_key.resolve().read_bytes()
        provider = SoftwareProvider(material)

    if args.socket:
        if os.name == "nt":
            raise SystemExit("Unix sockets are for the Linux reference platform")
        server = UnixKeyBrokerServer(
            args.socket,
            provider,
            max_concurrent=args.max_concurrent,
            max_requests_per_minute=args.max_requests_per_minute,
        )
    else:
        if not all((args.ca, args.cert, args.key)):
            raise SystemExit("localhost TCP mode requires --ca, --cert, and --key")
        server = TcpKeyBrokerServer(
            (args.listen, args.port),
            provider,
            cafile=args.ca,
            certfile=args.cert,
            keyfile=args.key,
            max_concurrent=args.max_concurrent,
            max_requests_per_minute=args.max_requests_per_minute,
        )
    logging.info(
        "Key Broker ready: provider=%s key_id=%s capabilities=%s",
        provider.name,
        provider.key_id,
        provider.capabilities,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
