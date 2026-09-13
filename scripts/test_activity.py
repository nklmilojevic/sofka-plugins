#!/usr/bin/env python3
"""Exercise built adapters with mock tools and a broken activity destination.

Run `cargo build --locked --workspace` then `python3 scripts/test_activity.py`.
No cluster, certificate renewal, or HTTP load is used.
"""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
if not TARGET.is_absolute():
    TARGET = ROOT / TARGET

MOCK = r'''
import json
import os
from pathlib import Path
import signal
import sys

signal.signal(signal.SIGPIPE, signal.SIG_DFL)
root = Path(os.environ["ACTIVITY_FIXTURES"])
name = Path(sys.argv[0]).name
if name == "trivy" and os.environ.get("MALFORMED_TRIVY"):
    sys.stderr.write("8 / 81 [--->____] 9.88% 1 p/s")
    sys.stdout.write("{")
else:
    # More than a pipe buffer: the adapter must drain after forwarding fails.
    sys.stderr.write("mock diagnostic\n" * 10000)
    if name in {"trivy", "popeye", "oha"}:
        sys.stdout.write((root / name / "fixtures/scan.json").read_text())
    elif name == "cmctl":
        if sys.argv[1] == "status":
            sys.stdout.write((root / "cert-manager/fixtures/status.txt").read_text())
        else:
            sys.stdout.write("renewal requested\n")
    elif name == "kubectl":
        request = json.loads((root / "cert-manager/fixtures/inspect-request.json").read_text())
        request["object"]["data"]["tls.key"] = "PRIVATE_KEY_SENTINEL"
        sys.stdout.write(json.dumps(request["object"]))
    else:
        raise AssertionError(name)
'''


def fixture(plugin, name="request.json"):
    return json.loads((ROOT / "plugins" / plugin / "fixtures" / name).read_text())


@unittest.skipUnless(os.name == "posix", "requires POSIX pipe descriptors")
class ActivityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sofka-activity-test-")
        self.addCleanup(temporary.cleanup)
        self.tools = Path(temporary.name)
        for name in ["trivy", "popeye", "oha", "cmctl", "kubectl"]:
            tool = self.tools / name
            tool.write_text(f"#!{sys.executable}\n" + MOCK)
            tool.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(self.tools) + os.pathsep + os.environ.get("PATH", ""),
            "ACTIVITY_FIXTURES": str(ROOT / "plugins"),
            "MALFORMED_TRIVY": "",
        }

    def run_adapter(self, plugin, request, args=(), broken=False):
        stderr = subprocess.PIPE
        if broken:
            reader, stderr = os.pipe()
            os.close(reader)
        try:
            return subprocess.run(
                [str(TARGET / "debug" / ("sofka-plugin-" + plugin)), *args],
                input=json.dumps(request).encode(),
                stdout=subprocess.PIPE,
                stderr=stderr,
                cwd=ROOT,
                env=self.env,
                timeout=15,
            )
        finally:
            if broken:
                os.close(stderr)

    def test_successful_reports_survive_a_broken_activity_pipe(self):
        cases = []
        for plugin in ["trivy", "popeye", "oha"]:
            request = fixture(plugin)
            request["inputs"].pop("report")
            cases.append((plugin, request, []))
        status = fixture("cert-manager")
        status["inputs"].pop("replay")
        cases.append(("cert-manager", status, ["status"]))
        inspect = fixture("cert-manager", "inspect-request.json")
        cases.append(("cert-manager", inspect, ["inspect"]))
        fallback = copy.deepcopy(inspect)
        fallback["object"].pop("data")
        cases.append(("cert-manager", fallback, ["inspect"]))
        for dry_run in ["true", "false"]:
            renew = fixture("cert-manager", "renew-request.json")
            renew["inputs"]["dry_run"] = dry_run
            cases.append(("cert-manager", renew, ["renew"]))
        for plugin, request, args in cases:
            with self.subTest(plugin=plugin, args=args, inputs=request["inputs"]):
                normal = self.run_adapter(plugin, request, args)
                self.assertEqual(normal.returncode, 0, normal.stderr)
                broken = self.run_adapter(plugin, request, args, broken=True)
                self.assertEqual(broken.returncode, 0)
                self.assertEqual(json.loads(broken.stdout), json.loads(normal.stdout))
                self.assertNotIn(b"PRIVATE_KEY_SENTINEL", normal.stderr + broken.stdout)

    def test_trivy_progress_does_not_replace_a_json_parse_error(self):
        self.env["MALFORMED_TRIVY"] = "1"
        request = fixture("trivy")
        request["inputs"].pop("report")
        result = self.run_adapter("trivy", request)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(result.stdout)
        self.assertIn(b"Trivy progress:", result.stderr)
        self.assertIn(b"EOF", result.stderr)
        self.assertNotIn(b"Trivy failed: Trivy progress:", result.stderr)


if __name__ == "__main__":
    unittest.main()
