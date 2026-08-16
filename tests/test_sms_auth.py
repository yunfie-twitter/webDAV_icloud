from __future__ import annotations

import json

from icloud_ftp.sms_auth import (
    request_sms_code,
    trusted_phone_numbers,
    validate_sms_code,
)


class Response:
    def __init__(self, payload=None):
        self.payload = payload or {}

    def json(self):
        return self.payload


class Session:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return Response(self.payload)

    def put(self, url, **kwargs):
        self.calls.append(("PUT", url, kwargs))
        return Response()

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return Response()


class Service:
    auth_endpoint = "https://idmsa.example/auth"
    session_data = {"scnt": "scnt-value", "session_id": "session-value"}

    def __init__(self, payload):
        self.session = Session(payload)
        self.trusted = False

    def _get_auth_headers(self, overrides=None):
        return {"X-Widget": "test", **(overrides or {})}

    def trust_session(self):
        self.trusted = True
        return True


def test_sms_flow_uses_selected_masked_phone_number():
    service = Service(
        {
            "trustedPhoneNumbers": [
                {"id": 7, "numberWithDialCode": "+81 ••-••••-1234"}
            ]
        }
    )
    assert trusted_phone_numbers(service)[0]["id"] == 7

    request_sms_code(service, 7)
    method, url, kwargs = service.session.calls[-1]
    assert method == "PUT"
    assert url.endswith("/verify/phone")
    assert json.loads(kwargs["data"]) == {
        "phoneNumber": {"id": 7},
        "mode": "sms",
    }

    assert validate_sms_code(service, 7, "123456")
    method, url, kwargs = service.session.calls[-1]
    assert method == "POST"
    assert url.endswith("/verify/phone/securitycode")
    assert json.loads(kwargs["data"])["securityCode"]["code"] == "123456"
    assert service.trusted


def test_nested_phone_number_response_is_supported():
    service = Service(
        {"phoneNumberVerification": {"trustedPhoneNumbers": [{"id": 2}]}}
    )
    assert trusted_phone_numbers(service) == [{"id": 2}]

