from __future__ import annotations

from argparse import Namespace

from icloud_ftp import cli
from icloud_ftp.cli import _config_path, make_parser
from icloud_ftp.config import config_from_auth_args, load_config, save_config


def test_auth_settings_round_trip_without_passwords(tmp_path):
    path = tmp_path / "server.toml"
    existing = load_config(path)
    args = Namespace(
        apple_id="person@example.com",
        session_dir=str(tmp_path / "sessions"),
        region="global",
        auth_method="sms",
        apple_password_env="ICLOUD_PASSWORD",
    )
    config = config_from_auth_args(args, existing)
    save_config(path, config)

    text = path.read_text(encoding="utf-8")
    assert "person@example.com" in text
    assert "password =" not in text
    loaded = load_config(path)
    assert loaded["icloud"]["apple_id"] == "person@example.com"
    assert loaded["icloud"]["auth_method"] == "sms"
    assert loaded["webdav"]["port"] == 8080


def test_serve_uses_toml_defaults_and_cli_can_override(tmp_path):
    path = tmp_path / "server.toml"
    save_config(
        path,
        {
            "version": 1,
            "icloud": {
                "apple_id": "saved@example.com",
                "session_dir": "saved-session",
                "region": "global",
                "auth_method": "device",
                "apple_password_env": "APPLE_SECRET",
            },
            "webdav": {
                "host": "0.0.0.0",
                "port": 8081,
                "user": "saved-user",
                "password_env": "WEBDAV_SECRET",
                "allow_insecure_remote": True,
            },
        },
    )
    loaded = load_config(path)
    parser = make_parser(loaded, path)
    args = parser.parse_args(["serve", "--config", str(path), "--port", "2122"])
    assert args.apple_id == "saved@example.com"
    assert args.host == "0.0.0.0"
    assert args.port == 2122
    assert args.webdav_user == "saved-user"
    assert args.webdav_password_env == "WEBDAV_SECRET"
    assert args.allow_insecure_remote


def test_config_option_is_detected_after_subcommand(tmp_path):
    path = tmp_path / "custom.toml"
    assert _config_path(["serve", "--config", str(path)]) == path


def test_auth_command_saves_resolved_login_settings(monkeypatch, tmp_path):
    class Drive:
        @staticmethod
        def dir():
            return ["one"]

    class Service:
        drive = Drive()

    monkeypatch.setattr(cli, "_connect", lambda args, interactive: Service())
    path = tmp_path / "auth.toml"
    cli.main(
        [
            "auth",
            "--config",
            str(path),
            "--apple-id",
            "saved@example.com",
            "--session-dir",
            str(tmp_path / "login"),
            "--auth-method",
            "sms",
        ]
    )
    loaded = load_config(path)
    assert loaded["icloud"]["apple_id"] == "saved@example.com"
    assert loaded["icloud"]["session_dir"] == str(tmp_path / "login")
    assert loaded["icloud"]["auth_method"] == "sms"
