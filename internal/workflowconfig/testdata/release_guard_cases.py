"""Execute the workflow's real inline guard with synthetic API responses only."""
import base64
import contextlib
import copy
import io
import http.client
import json
import os
import sys
import urllib.error
import urllib.request
from unittest.mock import patch

code = sys.stdin.read()
secret = "benign-release-token-sentinel"
registry_secret = "benign-registry-token-sentinel"
os.environ.update(REPOSITORY="Fixture/threat-bot", REPOSITORY_ID="123", VERSION="v0.1.0", GH_TOKEN=secret, ACTOR="fixture")
base = {
    "repository": (200, {"id": 123, "full_name": "Fixture/threat-bot", "owner": {"login": "Fixture", "type": "Organization"}}),
    "release": (404, {"message": "Not Found"}),
    "package": (404, {"message": "Not Found"}),
    "token": (200, {"token": registry_secret}),
    "manifest": (404, {"errors": [{"code": "MANIFEST_UNKNOWN"}]}),
}
correct_package = {"name": "threat-bot", "package_type": "container", "repository": {"id": 123}}
cases = [
    ("first release", {}, True),
    ("first release with package-specific 404", {"package": (404, {"message": "Package not found."})}, True),
    ("new version in owned package", {"package": (200, correct_package)}, True),
]
for stage in ("repository", "release", "package", "token", "manifest"):
    for status in (401, 403, 429, 500, 302):
        cases.append((stage + " HTTP " + str(status), {stage: (status, {"message": secret})}, False))
    cases.append((stage + " network failure", {stage: None}, False))
    cases.append((stage + " protocol failure", {stage: False}, False))
    cases.append((stage + " malformed JSON", {stage: (200, "not-json:" + secret)}, False))
cases.extend([
    ("existing release", {"release": (200, {"tag_name": "v0.1.0"})}, False),
    ("existing image", {"manifest": (200, {"schemaVersion": 2})}, False),
    ("repository not accessible", {"repository": (404, {"message": "Not Found"})}, False),
    ("renamed historical repository", {"repository": (200, {"id": 456, "full_name": "Fixture/threat-bot", "owner": {"type": "Organization", "login": "Fixture"}})}, False),
    ("historical package binding", {"package": (200, {**correct_package, "repository": {"id": 456}})}, False),
    ("unverifiable package binding", {"package": (200, {**correct_package, "repository": None})}, False),
    ("missing registry token", {"token": (200, {})}, False),
    ("registry token not found", {"token": (404, {"message": "Not Found"})}, False),
    ("unconfirmed manifest absence", {"manifest": (404, {"message": "Not Found"})}, False),
    ("unconfirmed release absence", {"release": (404, {"message": secret})}, False),
    ("package response cannot confirm missing release", {"release": (404, {"message": "Package not found."})}, False),
    ("unconfirmed package absence", {"package": (404, {"message": secret})}, False),
])

class Response(io.BytesIO):
    def __init__(self, status, body):
        super().__init__((json.dumps(body) if not isinstance(body, str) else body).encode())
        self.status = status

for name, overrides, allowed in cases:
    fixtures = copy.deepcopy(base)
    fixtures.update(overrides)
    calls = []

    class Opener:
        def open(self, request, timeout):
            url = request.full_url
            if url == "https://api.github.com/repos/Fixture/threat-bot":
                stage = "repository"
            elif url == "https://api.github.com/repos/Fixture/threat-bot/releases/tags/v0.1.0":
                stage = "release"
            elif url == "https://api.github.com/orgs/Fixture/packages/container/threat-bot":
                stage = "package"
            elif url.startswith("https://ghcr.io/token?"):
                stage = "token"
            elif url == "https://ghcr.io/v2/fixture/threat-bot/manifests/v0.1.0":
                stage = "manifest"
            else:
                raise AssertionError("unexpected request destination")
            assert request.get_method() == "GET", "guard attempted a mutation"
            assert 0 < timeout <= 30, "request must be bounded"
            auth = request.get_header("Authorization")
            if stage in ("repository", "release", "package"):
                assert auth == "Bearer " + secret, "missing GitHub authentication"
            elif stage == "token":
                assert auth == "Basic " + base64.b64encode(("fixture:" + secret).encode()).decode(), "missing registry authentication"
            else:
                assert auth == "Bearer " + registry_secret, "missing manifest authentication"
            calls.append(stage)
            result = fixtures[stage]
            if result is None:
                raise urllib.error.URLError(secret)
            if result is False:
                raise http.client.BadStatusLine(secret)
            status, body = result
            response = Response(status, body)
            if status >= 300:
                raise urllib.error.HTTPError(url, status, secret, {}, response)
            return response

    output = io.StringIO()
    outcome = True
    with patch("urllib.request.build_opener", return_value=Opener()), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        try:
            exec(compile(code, "release-workflow-guard", "exec"), {"__name__": "__main__"})
        except SystemExit as error:
            outcome = error.code in (None, 0)
            if error.code not in (None, 0):
                print(error.code)
    assert outcome == allowed, name + " outcome mismatch: " + output.getvalue()
    assert secret not in output.getvalue() and registry_secret not in output.getvalue(), name + " leaked a benign credential sentinel"
    if allowed:
        assert calls == ["repository", "release", "package", "token", "manifest"], "incomplete existence/ownership checks"
    if name == "existing release":
        assert calls == ["repository", "release"], "existing release must stop before registry access"
    if name in ("historical package binding", "unverifiable package binding"):
        assert "token" not in calls, "invalid package ownership must stop before registry access"
print("Passed " + str(len(cases)) + " isolated release-guard scenarios; no real network or writes")
