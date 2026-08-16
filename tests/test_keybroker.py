from __future__ import annotations

import io
import json

from fakes import FakeBackend
from icloud_ftp.encryption_backend import (
    EncryptedBackend,
    create_recovery_public_bundle,
    load_recovery_public_bundle,
)
from icloud_ftp.keybroker import (
    KeyBrokerPolicy,
    LinuxTpmRsaProvider,
    SoftwareProvider,
)


def test_primary_broker_and_offline_recovery_can_unwrap_same_data(tmp_path):
    public_path = tmp_path / "recovery-public.json"
    secret = bytes.fromhex(create_recovery_public_bundle(public_path))
    public = load_recovery_public_bundle(public_path)
    remote = FakeBackend()
    remote.files.clear()
    primary = SoftwareProvider(b"p" * 32)

    normal = EncryptedBackend(
        remote,
        key=None,
        key_broker=primary,
        recovery_public=public,
        database=tmp_path / "state.db",
        vault_folder=".vault",
        hybrid_x25519=True,
    )
    normal.upload_stream("/survives.bin", io.BytesIO(b"recoverable"), 11)
    normal.close()

    # Simulates total primary-broker/TPM loss. No primary KEK is available.
    recovery = EncryptedBackend(
        remote,
        key=secret,
        database=tmp_path / "state.db",
        vault_folder=".vault",
        hybrid_x25519=True,
    )
    output = io.BytesIO()
    recovery.download("/survives.bin", output)
    assert output.getvalue() == b"recoverable"
    recovery.close()


def test_wrapped_key_envelope_binds_context():
    provider = SoftwareProvider(b"z" * 32)
    envelope = provider.wrap(b"d" * 32, b"object-one")
    assert provider.unwrap(envelope, b"object-one") == b"d" * 32
    import pytest

    with pytest.raises(Exception):
        provider.unwrap(envelope, b"object-two")


def test_recovery_rewraps_only_key_capsules_for_new_primary(tmp_path):
    public_path = tmp_path / "recovery-public.json"
    secret = bytes.fromhex(create_recovery_public_bundle(public_path))
    public = load_recovery_public_bundle(public_path)
    remote = FakeBackend()
    remote.files.clear()
    old_broker = SoftwareProvider(b"o" * 32)
    new_broker = SoftwareProvider(b"n" * 32)
    original = EncryptedBackend(
        remote,
        key=None,
        key_broker=old_broker,
        recovery_public=public,
        database=tmp_path / "state.db",
        vault_folder=".vault",
    )
    original.upload_stream("/rotate.bin", io.BytesIO(b"rotate me"), 9)
    object_ciphertexts = {
        name: data
        for name, data in remote.files.items()
        if "/objects/" in name or "/manifests/" in name
    }
    original.close()

    recovery = EncryptedBackend(
        remote,
        key=secret,
        key_broker=new_broker,
        database=tmp_path / "state.db",
        vault_folder=".vault",
    )
    result = recovery.rewrap_primary_keys(new_broker, finalize=True)
    assert result["finalized"] == 1
    assert {
        name: data
        for name, data in remote.files.items()
        if "/objects/" in name or "/manifests/" in name
    } == object_ciphertexts
    recovery.close()

    restored = EncryptedBackend(
        remote,
        key=None,
        key_broker=new_broker,
        recovery_public=public,
        database=tmp_path / "state.db",
        vault_folder=".vault",
    )
    output = io.BytesIO()
    restored.download("/rotate.bin", output)
    assert output.getvalue() == b"rotate me"
    restored.close()


def test_key_broker_policy_rejects_concurrency_and_rate_excess():
    class Policy(KeyBrokerPolicy):
        pass

    policy = Policy()
    policy._init_policy(max_concurrent=1, max_requests_per_minute=2)
    assert policy.admit_request()
    assert not policy.admit_request()
    policy.release_request()
    assert policy.admit_request()
    policy.release_request()
    assert not policy.admit_request()


def test_linux_tpm_provider_uses_key_bound_oaep_scheme(tmp_path, monkeypatch):
    public_key = tmp_path / "primary-kek.pem"
    public_key.write_bytes(b"PUBLIC KEY\n")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[0] == "tpm2_readpublic":
            output = command[command.index("-o") + 1]
            with open(output, "wb") as stream:
                stream.write(public_key.read_bytes())
            return type("Result", (), {"stdout": b""})()
        if command[0] == "tpm2_rsaencrypt":
            return type("Result", (), {"stdout": b"wrapped"})()
        return type("Result", (), {"stdout": b"d" * 32})()

    monkeypatch.setattr("icloud_ftp.keybroker.subprocess.run", fake_run)
    provider = LinuxTpmRsaProvider("0x81000003", public_key)
    envelope = provider.wrap(b"d" * 32, b"context")
    assert provider.unwrap(envelope, b"context") == b"d" * 32

    crypto_calls = [call for call in calls if call[0] != "tpm2_readpublic"]
    assert all(call[call.index("-s") + 1] == "null" for call in crypto_calls)
    assert all("-g" not in call for call in crypto_calls)


def test_resumed_rewrap_rejects_a_corrupt_existing_new_envelope(tmp_path):
    import pytest

    public_path = tmp_path / "recovery-public.json"
    secret = bytes.fromhex(create_recovery_public_bundle(public_path))
    public = load_recovery_public_bundle(public_path)
    remote = FakeBackend()
    remote.files.clear()
    old_broker = SoftwareProvider(b"o" * 32)
    new_broker = SoftwareProvider(b"n" * 32)
    original = EncryptedBackend(
        remote,
        key=None,
        key_broker=old_broker,
        recovery_public=public,
        database=tmp_path / "state.db",
        vault_folder=".vault",
    )
    original.upload_stream("/file.bin", io.BytesIO(b"payload"), 7)
    original.close()

    recovery = EncryptedBackend(
        remote,
        key=secret,
        key_broker=new_broker,
        database=tmp_path / "state.db",
        vault_folder=".vault",
    )
    recovery.rewrap_primary_keys(new_broker)
    capsule_path = next(path for path in remote.files if "/keys/" in path)
    capsule = json.loads(remote.files[capsule_path])
    envelope = next(
        item for item in capsule["primary"] if item["key_id"] == new_broker.key_id
    )
    envelope["wrapped_key"] = "AAAA"
    remote.files[capsule_path] = json.dumps(capsule).encode("ascii")

    with pytest.raises(Exception):
        recovery.rewrap_primary_keys(new_broker)
    recovery.close()
