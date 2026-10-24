"""Exercise the pinned CLI against a local fake API, without paid model calls."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import runner


def message(block, reason):
    return {"id": "msg_local_test", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
            "content": [block], "stop_reason": reason, "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 20}}


class FakeAPI(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if "count_tokens" in self.path:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"input_tokens":100}')
            return
        if not self.path.startswith("/v1/messages"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")
            return
        self.server.requests.append(payload)
        index, turn = divmod(len(self.server.requests) - 1, 2)
        skill = runner.SKILLS[min(index, 3)]
        if self.headers.get("x-api-key") != "dummy-local-key":
            self.server.errors.append("apiKeyHelper did not supply the dummy key")
        if payload.get("model") != "claude-opus-5-5" or payload.get("output_config", {}).get("effort") != "xhigh":
            self.server.errors.append("configured model/effort was not sent to the API")
        if turn == 0:
            if f"TRUSTED-SKILL-CONTENT-{skill}" not in json.dumps(payload.get("messages")):
                self.server.errors.append(f"native skill content not loaded: {skill}")
            source = self.server.work / skill
            paths = [self.server.private / "key", self.server.root / "controller", self.server.out / "receipt.json",
                     self.server.work / "trusted-plugin/skills" / skill / "SKILL.md"]
            script = f"""import json
from pathlib import Path
results = {{}}
Path({str(source / 'probe-ran')!r}).write_text('yes')
try:
    Path({str(paths[0])!r}).read_text()
    results['key_denied'] = False
except OSError:
    results['key_denied'] = True
for name, path in {[(str(i), str(path)) for i, path in enumerate(paths[1:])]!r}:
    try:
        Path(path).write_text('tampered')
        results[name] = False
    except OSError:
        results[name] = True
print('SANDBOX_PROBE:' + json.dumps(results, sort_keys=True))
"""
            block = {"type": "tool_use", "id": "toolu_probe", "name": "Bash",
                     "input": {"command": shlex.join([sys.executable, "-c", script]), "description": "Check sandbox boundaries", "timeout": 10000}}
            if self.server.native_read:
                block.update(name="Read", input={"file_path": str(self.server.read_path)})
            reason = "tool_use"
        else:
            content = payload["messages"][-1]["content"]
            text = content[0]["content"]
            if isinstance(text, list):
                text = "\n".join(block.get("text", "") for block in text)
            if self.server.native_read:
                if "dummy-local-key" in text or "denied" not in text.lower():
                    self.server.errors.append("native Read did not deny key access")
            else:
                match = re.search(r"SANDBOX_PROBE:(\{[^\n]*\})", text)
                if not match or json.loads(match[1]) != {"key_denied": True, "0": True, "1": True, "2": True}:
                    self.server.errors.append("sandbox boundary probe failed: " + text[-2000:])
            block = {"type": "tool_use", "id": "toolu_result", "name": "StructuredOutput",
                     "input": {"complete": True, "report": f"Local API smoke test: {skill}."}}
            reason = "tool_use"
        response = message(block, reason)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if payload.get("stream") else "application/json")
        self.end_headers()
        if not payload.get("stream"):
            self.wfile.write(json.dumps(response).encode())
            return
        start = {**response, "content": [], "stop_reason": None}
        initial = {**block, "input": {}} if block["type"] == "tool_use" else {**block, "text": ""}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])} if block["type"] == "tool_use" else {"type": "text_delta", "text": block["text"]}
        events = [
            ("message_start", {"type": "message_start", "message": start}),
            ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": initial}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": delta}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": reason, "stop_sequence": None}, "usage": {"output_tokens": 20}}),
            ("message_stop", {"type": "message_stop"}),
        ]
        for event, value in events:
            self.wfile.write(f"event: {event}\ndata: {json.dumps(value)}\n\n".encode())
        self.wfile.flush()


@unittest.skipUnless(os.environ.get("RAGU_AUDIT_NATIVE_TEST") == "1", "set RAGU_AUDIT_NATIVE_TEST=1 to exercise the installed CLI")
class NativeTests(unittest.TestCase):
    def test_real_cli_loads_all_four_skills_and_sandboxes_commands(self):
        self.probe(native_read=False)

    def test_native_file_tool_cannot_read_key_or_claim_completion(self):
        self.probe(native_read=True)

    def test_source_symlink_cannot_expose_model_key(self):
        self.probe(native_read=True, symlink=True)

    def probe(self, native_read, symlink=False):
        self.assertIsNotNone(shutil.which("claude"))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            root, work, out, private = [directory / name for name in ("root", "work", "reports", "private")]
            root.mkdir()
            work.mkdir()
            private.mkdir(mode=0o700)
            (private / "key").write_text("dummy-local-key")
            (root / "controller").write_text("trusted")
            (root / "qa/audit").mkdir(parents=True)
            shutil.copyfile(Path(runner.__file__), root / "qa/audit/runner.py")
            for skill in runner.SKILLS:
                path = root / ".claude/skills" / skill
                path.mkdir(parents=True)
                (path / "SKILL.md").write_text(f"---\nname: {skill}\ndescription: Native review test\n---\nTRUSTED-SKILL-CONTENT-{skill}\nReturn a review report.")
                (work / skill).mkdir()
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeAPI)
            server.root, server.work, server.out, server.private = root, work, out, private
            server.requests, server.errors = [], []
            server.native_read = native_read
            server.read_path = private / "key"
            if symlink:
                server.read_path = work / runner.SKILLS[0] / "key-link"
                server.read_path.symlink_to(private / "key")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            original_environment = runner.environment
            original_subprocess = subprocess.run

            def environment(run, directory):
                values = original_environment(run, directory)
                values["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{server.server_port}"
                return values

            run = {"head": "a" * 40, "base": "b" * 40, "configuration": "b" * 40, "model": "claude-opus-5-5", "effort": "xhigh"}
            try:
                with patch.object(runner, "prepare", return_value=run["base"]), patch.object(runner, "environment", side_effect=environment), \
                     patch.object(subprocess, "run", side_effect=lambda *args, **kwargs: original_subprocess(*args, **{**kwargs, "timeout": 120})), \
                     patch.object(runner, "git", side_effect=lambda root, command, *args: run["head"] if command == "rev-parse" else ""):
                    if native_read:
                        with self.assertRaisesRegex(ValueError, "review incomplete"):
                            runner.review(root, run, work, out, private)
                    else:
                        runner.review(root, run, work, out, private)
                self.assertEqual(server.errors, [])
                if native_read:
                    self.assertEqual(runner.read_json(out / "receipt.json")["phases"], [])
                else:
                    runner.verify(run, out)
                    self.assertEqual(len(server.requests), 8)
                    for skill in runner.SKILLS:
                        self.assertEqual((work / skill / "probe-ran").read_text(), "yes")
                self.assertEqual((root / "controller").read_text(), "trusted")
            except Exception:
                for path in out.glob("*.stderr"):
                    print(path.name, path.read_text()[-5000:])
                for path in out.glob("*.json"):
                    print(path.name, path.read_text()[-5000:])
                print("Fake API errors:", server.errors)
                raise
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
