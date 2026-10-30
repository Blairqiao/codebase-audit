import sys

import pytest

from repo_audit.publishers import GhTransport, PublicationError


def fake_gh(tmp_path, body):
    executable = tmp_path / "fake-gh"
    executable.write_text(f"#!{sys.executable}\n" + body)
    executable.chmod(0o700)
    return str(executable)


def test_gh_argv_json_payload_and_credential_separation(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "synthetic-publisher-token")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-model-key")
    executable = fake_gh(tmp_path, """import json,os,sys
from pathlib import Path
args=sys.argv[1:]
payload=json.loads(Path(args[args.index('--input')+1]).read_text())
print(json.dumps({'args':args,'payload':payload,'keys':list(os.environ)}))
""")
    response = GhTransport(executable).request("POST", "repos/owner/repo/issues", {"title": "literal $(touch never)", "body": "safe"})
    assert response["args"][:2] == ["api", "--hostname"]
    assert response["payload"] == {"title": "literal $(touch never)", "body": "safe"}
    assert "GH_TOKEN" in response["keys"]
    assert "OPENAI_API_KEY" not in response["keys"]
    assert not (tmp_path / "never").exists()


@pytest.mark.parametrize("body,kwargs,reason", [
    ("import time; time.sleep(2)\n", {"timeout": .05}, "timed out"),
    ("print('x'*10000)\n", {"max_output_bytes": 128}, "output limit"),
    ("import sys; print('synthetic-secret',file=sys.stderr); sys.exit(1)\n", {}, "exit code"),
    ("print('not json')\n", {}, "valid JSON"),
])
def test_gh_failures_are_bounded_without_echoing_raw_output(tmp_path, body, kwargs, reason):
    executable = fake_gh(tmp_path, body)
    with pytest.raises(PublicationError, match=reason) as caught:
        GhTransport(executable, **kwargs).request("GET", "repos/owner/repo/issues")
    assert "synthetic-secret" not in str(caught.value)
