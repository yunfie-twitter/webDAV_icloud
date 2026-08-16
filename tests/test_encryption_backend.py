from __future__ import annotations

import io

import pytest

from icloud_ftp.encryption_backend import EncryptedBackend, initialize_key, load_key
from fakes import FakeBackend


def make_backend(tmp_path):
    remote = FakeBackend()
    remote.files.clear()
    encrypted = EncryptedBackend(
        remote,
        key=b"k" * 32,
        database=tmp_path / "mapping.db",
        vault_folder=".vault",
        strict_plaintext=True,
    )
    return encrypted, remote


def test_encrypted_round_trip_hides_name_and_content(tmp_path):
    encrypted, remote = make_backend(tmp_path)
    source = tmp_path / "source"
    source.write_bytes(b"top secret photo bytes")
    encrypted.upload("/photo.jpg", source)

    assert [entry.name for entry in encrypted.list("/")] == ["photo.jpg"]
    remote_names = list(remote.files)
    assert len(remote_names) == 4
    assert any(name.startswith("/.vault/objects/") for name in remote_names)
    assert any(name.startswith("/.vault/manifests/") for name in remote_names)
    assert len([name for name in remote_names if name.startswith("/.vault/keys/")]) == 2
    assert all(b"photo.jpg" not in data for data in remote.files.values())
    assert all(b"top secret photo bytes" not in data for data in remote.files.values())

    output = io.BytesIO()
    encrypted.download("/photo.jpg", output)
    assert output.getvalue() == b"top secret photo bytes"


def test_ciphertext_tampering_is_detected(tmp_path):
    encrypted, remote = make_backend(tmp_path)
    source = tmp_path / "source"
    source.write_bytes(b"authenticated")
    encrypted.upload("/file.bin", source)
    remote_name = next(name for name in remote.files if "/objects/" in name)
    damaged = bytearray(remote.files[remote_name])
    damaged[-1] ^= 1
    remote.files[remote_name] = bytes(damaged)
    with pytest.raises(ValueError, match="authentication failed"):
        encrypted.download("/file.bin", io.BytesIO())


def test_web_deleted_ciphertext_removes_plain_mapping(tmp_path):
    encrypted, remote = make_backend(tmp_path)
    source = tmp_path / "source"
    source.write_bytes(b"data")
    encrypted.upload("/file.bin", source)
    remote.files.clear()  # Represents deletion in iCloud Web.
    encrypted.missing_observations = 1
    encrypted.missing_grace = 0
    assert encrypted.list("/") == []


def test_one_empty_icloud_listing_does_not_remove_plain_mapping(tmp_path):
    encrypted, remote = make_backend(tmp_path)
    source = tmp_path / "source"
    source.write_bytes(b"data")
    encrypted.upload("/file.bin", source)
    encrypted.reconcile_interval = 0
    encrypted.missing_grace = 0
    remote.files.clear()

    assert [entry.name for entry in encrypted.list("/")] == ["file.bin"]
    assert encrypted.list("/") == []


def test_virtual_directories_and_renames_do_not_create_plain_remote_names(tmp_path):
    encrypted, remote = make_backend(tmp_path)
    encrypted.mkdir("/folder")
    source = tmp_path / "source"
    source.write_bytes(b"data")
    encrypted.upload("/folder/file.txt", source)
    encrypted.rename("/folder", "/renamed")
    assert encrypted.stat("/renamed/file.txt").size == 4
    assert all("folder" not in path and "renamed" not in path for path in remote.files)


def test_strict_mode_rejects_existing_plaintext_drive_items(tmp_path):
    remote = FakeBackend()  # Contains /hello.txt.
    encrypted = EncryptedBackend(
        remote,
        key=b"k" * 32,
        database=tmp_path / "mapping.db",
        strict_plaintext=True,
    )
    with pytest.raises(RuntimeError, match="plaintext items"):
        encrypted.list("/")


def test_key_initialization_never_overwrites(tmp_path):
    path = tmp_path / "vault.key"
    initialize_key(path)
    first = load_key(path)
    assert len(first) == 32
    with pytest.raises(FileExistsError):
        initialize_key(path)
    assert load_key(path) == first
