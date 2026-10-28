#!/var/ossec/framework/python/bin/python3
"""Wazuh integration: forward an alert to CloudShield, signed with HMAC-SHA256.

Installed on the Wazuh manager as /var/ossec/integrations/custom-cloudshield and enabled with:

  <integration>
    <name>custom-cloudshield</name>
    <hook_url>https://cloudshield.example.internal/v1/ingest/wazuh</hook_url>
    <api_key>HMAC_SECRET_FROM_SECRETS_MANAGER</api_key>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>

Wazuh calls it as: custom-cloudshield <alert_file> <api_key> <hook_url>
"""

import hashlib
import hmac
import sys
import urllib.request


def main(alert_file: str, secret: str, hook_url: str) -> int:
    if not hook_url.startswith("https://"):
        print("refusing to send evidence over plain HTTP", file=sys.stderr)
        return 1
    with open(alert_file, "rb") as fh:
        body = fh.read()
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        hook_url,
        data=body,
        method="POST",
        headers={"content-type": "application/json", "x-cloudshield-signature": signature},
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
        return 0 if response.status in (200, 202) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
