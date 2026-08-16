from __future__ import annotations

import base64
import http.client
import threading

from fakes import FakeBackend
from icloud_ftp.encryption_backend import EncryptedBackend
from icloud_ftp.webdav import build_server


def _auth() -> str:
    token = base64.b64encode(b"icloud:test-password").decode("ascii")
    return "Basic " + token


def test_webdav_round_trip_and_namespace_operations(tmp_path):
    remote = FakeBackend()
    remote.files.clear()
    backend = EncryptedBackend(
        remote,
        key=b"k" * 32,
        database=tmp_path / "state.db",
        vault_folder=".vault",
    )
    server = build_server(
        backend,
        host="127.0.0.1",
        port=0,
        username="icloud",
        password="test-password",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    connection = http.client.HTTPConnection(host, port, timeout=10)
    headers = {"Authorization": _auth()}
    try:
        connection.request("MKCOL", "/Photos", headers=headers)
        response = connection.getresponse()
        assert response.status == 201
        response.read()

        body = b"plain photo content"
        connection.request("PUT", "/Photos/photo.jpg", body=body, headers=headers)
        response = connection.getresponse()
        assert response.status == 201
        response.read()

        propfind_headers = {**headers, "Depth": "1", "Content-Length": "0"}
        connection.request("PROPFIND", "/Photos", headers=propfind_headers)
        response = connection.getresponse()
        listing = response.read()
        assert response.status == 207
        assert b"photo.jpg" in listing

        connection.request("GET", "/Photos/photo.jpg", headers=headers)
        response = connection.getresponse()
        assert response.status == 200
        assert response.read() == body

        connection.request(
            "MOVE",
            "/Photos/photo.jpg",
            headers={**headers, "Destination": f"http://{host}:{port}/Photos/moved.jpg"},
        )
        response = connection.getresponse()
        assert response.status == 201
        response.read()

        connection.request("DELETE", "/Photos/moved.jpg", headers=headers)
        response = connection.getresponse()
        assert response.status == 204
        response.read()
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        backend.close()
        thread.join(timeout=5)


def test_put_with_same_checksum_does_not_create_version(tmp_path):
    remote = FakeBackend()
    remote.files.clear()
    backend = EncryptedBackend(
        remote,
        key=b"x" * 32,
        database=tmp_path / "state.db",
        vault_folder=".vault",
    )
    import io

    assert backend.upload_stream("/same.bin", io.BytesIO(b"same"), 4)
    objects_before = set(remote.files)
    assert not backend.upload_stream("/same.bin", io.BytesIO(b"same"), 4)
    assert set(remote.files) == objects_before
    assert backend.version("/same.bin") == 1
    statuses = backend.db.execute(
        "SELECT status, error FROM cas_uploads ORDER BY created"
    ).fetchall()
    assert statuses[-1]["status"] == "ACTIVE"
    assert statuses[-1]["error"] == "UNCHANGED"
    backend.close()
