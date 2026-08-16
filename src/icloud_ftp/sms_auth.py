"""SMS second-factor support missing from icloudpy's HSA2 API.

These endpoints are used by Apple's own web sign-in flow but are not a public
API. Keep this adapter small so it can be updated independently if Apple
changes the response shape.
"""

from __future__ import annotations

import json
from typing import Any

from icloudpy.exceptions import ICloudPyAPIResponseException


def _headers(service) -> dict[str, str]:
    headers = service._get_auth_headers(  # pylint: disable=protected-access
        {"Accept": "application/json", "Content-Type": "application/json"}
    )
    if service.session_data.get("scnt"):
        headers["scnt"] = service.session_data["scnt"]
    if service.session_data.get("session_id"):
        headers["X-Apple-ID-Session-Id"] = service.session_data["session_id"]
    return headers


def trusted_phone_numbers(service) -> list[dict[str, Any]]:
    """Return the account's masked trusted phone-number descriptions."""
    response = service.session.get(
        service.auth_endpoint,
        headers=_headers(service),
    )
    payload = response.json()
    numbers = payload.get("trustedPhoneNumbers")
    if numbers is None:
        numbers = payload.get("phoneNumberVerification", {}).get(
            "trustedPhoneNumbers", []
        )
    return [number for number in numbers if isinstance(number, dict) and "id" in number]


def request_sms_code(service, phone_number_id: int) -> None:
    """Ask Apple to send an HSA2 verification code over SMS."""
    service.session.put(
        f"{service.auth_endpoint}/verify/phone",
        headers=_headers(service),
        data=json.dumps(
            {"phoneNumber": {"id": phone_number_id}, "mode": "sms"}
        ),
    )


def validate_sms_code(service, phone_number_id: int, code: str) -> bool:
    """Validate an SMS HSA2 code and trust the resulting web session."""
    try:
        service.session.post(
            f"{service.auth_endpoint}/verify/phone/securitycode",
            headers=_headers(service),
            data=json.dumps(
                {
                    "phoneNumber": {"id": phone_number_id},
                    "securityCode": {"code": code},
                    "mode": "sms",
                }
            ),
        )
    except ICloudPyAPIResponseException as error:
        if error.code == -21669:
            return False
        raise
    return bool(service.trust_session())

