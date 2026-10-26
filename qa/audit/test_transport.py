"""Exercise controller request retries without network access or real tokens."""

import io
from http.client import IncompleteRead
import json
import os
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

import github
import runner
import test_audit


class TruncatedResponse(io.BytesIO):
    def read(self, *args):
        raise IncompleteRead(b"UNTRUSTED_RESPONSE_CANARY", 32)


class TransportTests(unittest.TestCase):
    def test_repeatable_requests_recover_from_transient_failures(self):
        for method in ("GET", "PATCH"):
            for error in (HTTPError("https://api.github.com", 503, "Unavailable", {}, None), URLError("connection failed")):
                with self.subTest(method=method, error=type(error).__name__), \
                     patch.object(runner, "urlopen", side_effect=[error, io.BytesIO(b'{"ok":true}')]) as send, \
                     patch.object(runner.time, "sleep") as sleep:
                    request = Request("https://api.github.com", method=method)
                    self.assertEqual(runner.github_response(request, timeout=10), b'{"ok":true}')
                self.assertEqual(send.call_count, 2)
                sleep.assert_called_once_with(1)

    def test_truncated_response_reads_are_retried_and_persistent_failures_are_safe(self):
        for method in ("GET", "PATCH", "POST"):
            with self.subTest(method=method), \
                 patch.object(runner, "urlopen", side_effect=[TruncatedResponse(), io.BytesIO(b'{"ok":true}')]) as send, \
                 patch.object(runner.time, "sleep"):
                request = Request("https://api.github.com", method=method)
                if method == "POST":
                    with self.assertRaises(OSError) as error:
                        runner.github_response(request, timeout=10)
                    self.assertNotIn("UNTRUSTED_RESPONSE_CANARY", str(error.exception))
                    self.assertEqual(send.call_count, 1)
                else:
                    self.assertEqual(runner.github_response(request, timeout=10), b'{"ok":true}')
                    self.assertEqual(send.call_count, 2)
        with patch.object(runner, "urlopen", side_effect=lambda *args, **kwargs: TruncatedResponse()) as send, \
             patch.object(runner.time, "sleep"), self.assertRaises(OSError):
            runner.github_response(Request("https://api.github.com"), timeout=10)
        self.assertEqual(send.call_count, runner.GITHUB_ATTEMPTS)

    def test_deletion_monitor_survives_a_failed_truncated_response_lookup(self):
        cancelled = threading.Event()
        responses = [io.BytesIO(b'{}'), *[TruncatedResponse() for _ in range(runner.GITHUB_ATTEMPTS)],
                     HTTPError("https://api.github.com", 404, "Not found", {}, None)]
        with patch.dict(os.environ, {"GH_TOKEN": "dummy-read-only-token"}), \
             patch.object(runner, "urlopen", side_effect=responses), \
             patch.object(runner, "COMMENT_POLL_SECONDS", 0.01), patch.object(runner.time, "sleep"), \
             runner.watch_comment({"comment_id": 12}, cancelled):
            self.assertTrue(cancelled.wait(timeout=1), "transient response failure killed deletion monitoring")

    def test_creations_and_permanent_errors_are_not_retried(self):
        for method, code in (("POST", 503), ("GET", 404), ("GET", 403), ("GET", 429)):
            with self.subTest(method=method, code=code), \
                 patch.object(runner, "urlopen", side_effect=HTTPError("https://api.github.com", code, "error", {}, None)) as send, \
                 patch.object(runner.time, "sleep") as sleep, self.assertRaises(HTTPError):
                runner.github_response(Request("https://api.github.com", method=method), timeout=10)
            self.assertEqual(send.call_count, 1)
            sleep.assert_not_called()

    def test_retry_count_is_bounded_and_server_delays_are_respected(self):
        for retry_after, expected_calls, delays in ((None, 3, [1, 2]), ("4", 3, [4, 4]), ("60", 1, [])):
            headers = {} if retry_after is None else {"Retry-After": retry_after}
            with self.subTest(retry_after=retry_after), \
                 patch.object(runner, "urlopen", side_effect=HTTPError("https://api.github.com", 503, "Unavailable", headers, None)) as send, \
                 patch.object(runner.time, "sleep") as sleep, self.assertRaises(HTTPError):
                runner.github_response(Request("https://api.github.com"), timeout=10)
            self.assertEqual(send.call_count, expected_calls)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], delays)

    def test_startup_comment_lookup_recovers_before_launching_review(self):
        cancelled = threading.Event()
        with patch.dict(os.environ, {"GH_TOKEN": "dummy-read-only-token"}), \
             patch.object(runner, "urlopen", side_effect=[HTTPError("https://api.github.com", 503, "Unavailable", {}, None), io.BytesIO(b'{}')]), \
             patch.object(runner.time, "sleep"), runner.watch_comment({"comment_id": 12}, cancelled):
            self.assertFalse(cancelled.is_set())

    def test_monitor_honours_rate_limit_and_server_backoff(self):
        for code, headers, expected in (
            (503, {"Retry-After": "120"}, 120),
            (429, {}, 60),
            (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "600"}, 500),
            (503, {"Retry-After": "invalid"}, 60),
        ):
            with self.subTest(code=code, headers=headers), patch.object(runner.time, "time", return_value=100):
                self.assertEqual(runner.github_delay(HTTPError("https://api.github.com", code, "error", headers, None), 15), expected)

    def test_real_controller_retries_without_losing_completed_reports(self):
        for endpoint in ("comment", "check", "check_after_apply", "create_after_apply", "summary_after_apply",
                         "comment_truncated", "check_truncated", "create_truncated", "summary_truncated"):
            with self.subTest(endpoint=endpoint):
                fixture = test_audit.AuditTests()
                fixture.setUp()
                try:
                    backend, injected = fixture.api, False
                    enabled = endpoint.startswith(("create_", "summary_"))

                    def send(request, timeout):
                        nonlocal injected
                        url = urlsplit(request.full_url)
                        path = url.path + ("?" + url.query if url.query else "")
                        method = request.get_method()
                        if endpoint.startswith("comment"):
                            hit = path.endswith("/issues/comments/12") and method == "GET"
                        elif endpoint.startswith("create_"):
                            hit = path.endswith("/check-runs") and method == "POST"
                        elif endpoint.startswith("summary_"):
                            hit = url.path.endswith("/comments") and method == "POST"
                        else:
                            hit = "/check-runs/" in path and method == "PATCH"
                        if enabled and hit and not injected:
                            injected = True
                            if endpoint.endswith("after_apply") or (endpoint.endswith("truncated") and method != "GET"):
                                backend.call(path, json.loads(request.data), method)
                            if endpoint.endswith("truncated"):
                                return TruncatedResponse()
                            raise HTTPError(request.full_url, 503, "Unavailable", {}, None)
                        if method == "GET" and "/commits/" in path:
                            value = {"check_runs": list(backend.pages(path, "check_runs"))}
                        elif method == "GET" and url.path.endswith("/comments"):
                            value = list(backend.pages(path.split("?", 1)[0]))
                        else:
                            data = json.loads(request.data) if request.data is not None else None
                            value = backend.call(path, data, None if method == "GET" else method)
                        return io.BytesIO(json.dumps(value).encode())

                    with patch.dict(os.environ, {**test_audit.ENV, "GH_TOKEN": "dummy-publisher-token"}), \
                         patch.object(runner, "urlopen", side_effect=send), patch.object(runner.time, "sleep"):
                        api = github.GitHub()
                        run = github.queue(api, 9, test_audit.HEAD, 12)
                        fixture.reports(run)
                        enabled = True
                        github.publish(api, run, fixture.out, "success")
                    self.assertTrue(injected)
                    self.assertEqual(len(backend.checks), 1)
                    self.assertEqual(len(backend.comments), 1)
                    self.assertEqual(backend.checks[0]["conclusion"], "success")
                    self.assertIn("audit: completed", backend.comments[0]["body"])
                    self.assertIn("4/4 reviews completed", backend.comments[0]["body"])
                finally:
                    fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
