"""
Zero-dependency smoke tests for AGY Control Center (stdlib unittest only).

    python -I tests/test_smoke.py

All Google / CloudCode / Windows Credential Manager calls are stubbed, and hub state is
redirected to a temp directory, so this never touches real accounts or the network.
On non-Windows hosts the Win32 DLL loader is stubbed so the module can be imported;
the real ctypes / WinCred code paths are therefore NOT exercised by this suite.
"""
import ctypes
import http.client
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

if os.name != "nt":
    ctypes.WinDLL = lambda *a, **k: mock.MagicMock()

os.environ["AGY_HUB_DATA_DIR"] = tempfile.mkdtemp(prefix="agy_hub_test_")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agy_hub as hub  # noqa: E402

FUTURE = "2099-01-01T00:00:00+00:00"
RESET = "2030-01-01T00:00:00Z"


def http_error(code: int, message: str = "boom") -> urllib.error.HTTPError:
    body = json.dumps({"error": {"message": message}}).encode()
    return urllib.error.HTTPError("https://example.invalid", code, "err", {}, io.BytesIO(body))


def full_catalog(fraction: float = 0.5) -> dict:
    models = {
        mid: {"displayName": hub.label_from_model_id(mid), "quotaInfo": {"remainingFraction": fraction, "resetTime": RESET}}
        for mid in hub.MODEL_SORT_PRIORITY
    }
    # Legacy aliases that must be filtered out
    models["gemini-2.5-flash"] = {"displayName": "Gemini 3 Flash"}
    models["chat_20706"] = {"displayName": "Gemini 3.5 Flash Lite"}
    return models


QUOTA_SUMMARY = {"groups": [{"displayName": "Gemini", "buckets": [
    {"bucketId": "gemini-5h", "remainingFraction": 0.9, "resetTime": RESET, "window": "5h"},
    {"bucketId": "gemini-argon-wtu-weekly", "remainingFraction": 0.25, "resetTime": RESET, "window": "weekly"},
]}]}


def new_account(name: str = "a") -> dict:
    return {
        "id": f"acc_{name}", "email": f"{name}@example.com", "name": name, "picture": "p",
        "token": {"access_token": f"tok-{name}", "refresh_token": f"ref-{name}", "expiry": FUTURE},
    }


class FakeCloud:
    """Scriptable stand-in for cloudcode_post: per-endpoint failure queues."""

    def __init__(self):
        self.fail = {}      # endpoint -> list of exceptions raised before succeeding (or "always")
        self.calls = []
        self.models = full_catalog()

    def __call__(self, endpoint, access_token, payload=None):
        self.calls.append(endpoint)
        plan = self.fail.get(endpoint)
        if plan == "always":
            raise http_error(503, "unavailable")
        if plan:
            raise plan.pop(0)
        if endpoint == "loadCodeAssist":
            return {"paidTier": {"name": "Google AI Pro", "id": "g1-pro-tier"}, "cloudaicompanionProject": "proj-1"}
        if endpoint == "retrieveUserQuotaSummary":
            return QUOTA_SUMMARY
        return {"models": self.models}


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeCloud()
        for name, value in {
            "cloudcode_post": self.cloud,
            "wincred_read": lambda *a, **k: None,
            "discover_language_server": lambda *a, **k: None,
            "refresh_google_token": lambda rt: {
                "access_token": "fresh", "token_type": "Bearer", "refresh_token": rt, "expiry": FUTURE, "expires_in": 3599},
            "fetch_google_userinfo": lambda tok: {"email": "new@example.com", "name": "New", "picture": "p"},
        }.items():
            p = mock.patch.object(hub, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch("time.sleep")  # no real backoff waits
        self.sleep = p.start()
        self.addCleanup(p.stop)
        hub.HUB.accounts.clear()
        hub.HUB.pending_oauth.clear()


class PureFunctionTests(unittest.TestCase):
    def test_existing_ci_assertions(self):
        self.assertEqual(hub.format_exact_pct(0.004097), 0.4)
        self.assertEqual(hub.format_exact_pct(0.148157), 14.8)
        self.assertEqual(hub.format_exact_pct(1.0), 100.0)
        self.assertIn("gemini-4-argon-high", hub.MODEL_SORT_PRIORITY)
        self.assertIn("gemini-2.5-flash", hub.LEGACY_ALIAS_MODEL_IDS)
        self.assertTrue(hub.sanitize_local_path(str(hub.HOME_DIR / "Desktop" / "project")).startswith("~/"))

    def test_quota_fraction_handles_omitted_zero(self):
        self.assertEqual(hub.quota_fraction({"remainingFraction": 0.5, "resetTime": RESET}), 0.5)
        self.assertEqual(hub.quota_fraction({"resetTime": RESET}), 0.0)   # proto3 omits 0 -> exhausted
        self.assertEqual(hub.quota_fraction({}), 1.0)                     # not metered
        self.assertEqual(hub.quota_fraction(None), 1.0)
        self.assertEqual(hub.quota_fraction({"remainingFraction": 7}), 1.0)
        self.assertEqual(hub.quota_fraction({"remainingFraction": None, "resetTime": RESET}), 0.0)

    def test_catalog_is_18_models_without_aliases(self):
        models, _ = hub.build_model_catalog(full_catalog())
        self.assertEqual(len(models), 18)
        self.assertEqual(list(models)[:3], hub.MODEL_SORT_PRIORITY[:3])
        self.assertNotIn("gemini-2.5-flash", models)
        self.assertEqual(len({m["label"].lower() for m in models.values()}), 18)

    def test_catalog_keeps_argon_tiers_sharing_one_display_name(self):
        raw = full_catalog()
        for mid in hub.MODEL_SORT_PRIORITY[:3]:
            raw[mid]["displayName"] = "Gemini 4 Argon"
        models, _ = hub.build_model_catalog(raw)
        self.assertEqual(len(models), 18)
        self.assertEqual(
            [models[m]["label"] for m in hub.MODEL_SORT_PRIORITY[:3]],
            ["Gemini 4 Argon (High)", "Gemini 4 Argon (Medium)", "Gemini 4 Argon (Low)"])

    def test_catalog_keeps_argon_without_display_name_and_survives_bad_entries(self):
        raw = full_catalog()
        del raw["gemini-4-argon-high"]["displayName"]
        raw["gemini-4-argon-medium"]["quotaInfo"] = {"remainingFraction": None, "resetTime": RESET}
        raw["gemini-4-argon-low"]["maxTokens"] = "not-a-number"
        raw["aaa-broken"] = "not a dict"
        models, _ = hub.build_model_catalog(raw)
        self.assertEqual(len(models), 18)
        self.assertEqual(models["gemini-4-argon-high"]["label"], "Gemini 4 Argon (High)")
        self.assertEqual(models["gemini-4-argon-medium"]["remainingExactPct"], 0.0)

    def test_retry_backoff(self):
        sleeps = []
        attempts = iter([http_error(503), urllib.error.URLError("reset"), "ok"])

        def flaky():
            item = next(attempts)
            if isinstance(item, Exception):
                raise item
            return item

        self.assertEqual(hub.call_with_retry(flaky, sleep=sleeps.append), "ok")
        self.assertEqual(len(sleeps), 2)
        self.assertLess(sleeps[0], sleeps[1])  # exponential

        calls = []

        def bad_request():
            calls.append(1)
            raise http_error(400)

        with self.assertRaises(urllib.error.HTTPError):
            hub.call_with_retry(bad_request, sleep=sleeps.append)
        self.assertEqual(len(calls), 1)  # 4xx is not retried

        with self.assertRaises(urllib.error.HTTPError):
            hub.call_with_retry(lambda: (_ for _ in ()).throw(http_error(503)), attempts=3, sleep=lambda s: None)

    def test_parse_oauth_paste(self):
        self.assertEqual(
            hub.parse_oauth_paste(" http://localhost:17420/auth/callback?state=S1&code=4/0Ab-c&scope=x "),
            {"code": "4/0Ab-c", "state": "S1", "error": ""})
        self.assertEqual(hub.parse_oauth_paste("?state=S1&code=4%2F0Ab")["code"], "4/0Ab")
        self.assertEqual(hub.parse_oauth_paste("localhost:17420/auth/callback?code=c1&state=s")["state"], "s")
        self.assertEqual(hub.parse_oauth_paste("4/0AbCd_ef"), {"code": "4/0AbCd_ef", "state": "", "error": ""})
        self.assertEqual(hub.parse_oauth_paste("4%2F0AbCd")["code"], "4/0AbCd")
        self.assertEqual(hub.parse_oauth_paste("http://localhost:17420/auth/callback?error=access_denied")["error"], "access_denied")
        self.assertEqual(hub.parse_oauth_paste("https://example.com/")["code"], "")
        self.assertEqual(hub.parse_oauth_paste(None)["code"], "")


class ArgonSyncTests(BaseCase):
    def test_successful_poll(self):
        acc = hub.poll_account_telemetry(new_account())
        self.assertEqual(acc["sync"]["state"], "ok")
        self.assertEqual(acc["status"], "Enabled")
        self.assertIsNone(acc["last_error"])
        self.assertEqual(len(acc["models"]), 18)
        self.assertEqual(acc["argon_status"]["remainingExactPct"], 50.0)
        self.assertEqual(acc["argon_status"]["source"], "fetchAvailableModels")
        self.assertEqual(acc["quota_windows"][0]["bucketId"], "gemini-4-argon")
        self.assertEqual(sum(w["bucketId"].count("argon") > 0 for w in acc["quota_windows"]), 1)
        self.assertEqual(acc["project_id"], "proj-1")

    def test_transient_failures_are_retried(self):
        self.cloud.fail["fetchAvailableModels"] = [http_error(503), urllib.error.URLError("timed out")]
        acc = hub.poll_account_telemetry(new_account())
        self.assertEqual(acc["sync"]["state"], "ok")
        self.assertEqual(self.cloud.calls.count("fetchAvailableModels"), 3)
        self.assertTrue(acc["argon_status"]["available"])

    def test_models_failure_keeps_argon_via_quota_bucket(self):
        acc = hub.poll_account_telemetry(new_account())
        first_sync = acc["last_synced"]
        self.cloud.fail["fetchAvailableModels"] = "always"
        hub.poll_account_telemetry(acc)
        self.assertEqual(acc["sync"]["state"], "partial")
        self.assertEqual(acc["status"], "Degraded")
        self.assertIn("fetchAvailableModels", acc["last_error"])
        self.assertEqual(acc["argon_status"]["source"], "retrieveUserQuotaSummary")
        self.assertEqual(acc["argon_status"]["remainingExactPct"], 25.0)
        self.assertEqual(len(acc["models"]), 18)               # previous list kept
        self.assertTrue(acc["sync"]["stale"]["models"])
        self.assertEqual(acc["last_synced"], first_sync)       # not advanced on a non-fresh sync

    def test_total_failure_keeps_data_flagged_stale(self):
        acc = hub.poll_account_telemetry(new_account())
        self.cloud.fail = {e: "always" for e in ("loadCodeAssist", "retrieveUserQuotaSummary", "fetchAvailableModels")}
        hub.poll_account_telemetry(acc)
        self.assertEqual(acc["sync"]["state"], "failed")
        self.assertEqual(acc["status"], "Sync Error")
        self.assertTrue(acc["argon_status"]["stale"])
        self.assertEqual(acc["argon_status"]["remainingExactPct"], 50.0)
        self.assertTrue(acc["quota_windows"] and all(w["stale"] for w in acc["quota_windows"]))
        self.assertEqual(acc["sync"]["consecutiveFailures"], 1)
        self.assertEqual(acc["project_id"], "proj-1")          # cached project survives

        self.cloud.fail = {}
        hub.poll_account_telemetry(acc)
        self.assertEqual(acc["sync"]["state"], "ok")
        self.assertFalse(any(w["stale"] for w in acc["quota_windows"]))
        self.assertEqual(acc["sync"]["consecutiveFailures"], 0)

    def test_argon_cleared_only_on_clean_catalog_without_it(self):
        acc = hub.poll_account_telemetry(new_account())
        self.cloud.models = {k: v for k, v in full_catalog().items() if "argon" not in k}
        with mock.patch.dict(QUOTA_SUMMARY, {"groups": [{"displayName": "G", "buckets": [QUOTA_SUMMARY["groups"][0]["buckets"][0]]}]}):
            hub.poll_account_telemetry(acc)
        self.assertEqual(acc["sync"]["state"], "ok")
        self.assertIsNone(acc["argon_status"])

    def test_token_refresh_failure(self):
        acc = new_account()
        acc["token"]["expiry"] = "2000-01-01T00:00:00+00:00"
        with mock.patch.object(hub, "refresh_google_token", side_effect=http_error(400, "invalid_grant")):
            hub.poll_account_telemetry(acc)
        self.assertEqual(acc["status"], "Token Error")
        self.assertEqual(acc["sync"]["state"], "failed")
        self.assertEqual(self.cloud.calls, [])

    def test_expired_access_token_is_refreshed_once_on_401(self):
        self.cloud.fail["loadCodeAssist"] = [http_error(401)]
        acc = hub.poll_account_telemetry(new_account())
        self.assertEqual(acc["sync"]["state"], "ok")
        self.assertEqual(acc["token"]["access_token"], "fresh")


class HubTests(BaseCase):
    def test_one_failing_account_does_not_block_others(self):
        good, bad = new_account("good"), new_account("bad")
        hub.HUB.accounts.extend([good, bad])
        real = hub.poll_account_telemetry

        def flaky_poll(account, **kw):
            if account["email"].startswith("bad"):
                raise RuntimeError("unexpected crash")
            return real(account, **kw)

        with mock.patch.object(hub, "poll_account_telemetry", flaky_poll):
            result = {a["id"]: a for a in hub.HUB.refresh_all_accounts()}
        self.assertEqual(result["acc_good"]["sync"]["state"], "ok")
        self.assertEqual(result["acc_bad"]["sync"]["state"], "failed")
        self.assertIn("unexpected crash", result["acc_bad"]["last_error"])
        self.assertFalse(any(a["syncing"] for a in result.values()))
        self.assertNotIn("token", result["acc_good"])  # tokens never leave the backend
        saved = json.loads(hub.ACCOUNTS_FILE.read_text(encoding="utf-8"))
        self.assertEqual({a["id"] for a in saved}, {"acc_good", "acc_bad"})
        self.assertFalse(list(hub.DATA_DIR.glob("*.tmp")))

    def test_poll_keeps_token_replaced_during_poll(self):
        acc = new_account()
        hub.HUB.accounts.append(acc)
        real = hub.poll_account_telemetry

        def relogin_mid_poll(account, **kw):
            hub.HUB.accounts[0]["token"] = {"access_token": "relogin", "refresh_token": "relogin-r", "expiry": FUTURE}
            return real(account, **kw)

        with mock.patch.object(hub, "poll_account_telemetry", relogin_mid_poll):
            hub.HUB.poll_account("acc_a")
        self.assertEqual(hub.HUB.accounts[0]["token"]["refresh_token"], "relogin-r")
        self.assertEqual(hub.HUB.accounts[0]["sync"]["state"], "ok")

    def test_restore_snapshot_rejects_bad_ids(self):
        for bad in ("", "..", "../..", "snap_../x", None):
            self.assertFalse(hub.restore_snapshot(bad))


class HttpTests(BaseCase):
    def setUp(self):
        super().setUp()
        self.server = hub.ThreadedHTTPServer(("127.0.0.1", 0), hub.HubRequestHandler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        p = mock.patch.object(hub.webbrowser, "open", lambda url: True)
        p.start()
        self.addCleanup(p.stop)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        hdrs = {"Content-Type": "application/json"} if body is not None else {}
        hdrs.update(headers or {})
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        ctype = resp.getheader("Content-Type", "")
        return resp.status, (json.loads(raw) if "json" in ctype else raw.decode("utf-8")), ctype

    def test_pages_and_state(self):
        status, page, ctype = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn("/static/app.js", page)
        for path, expected in (("/static/app.js", "javascript"), ("/static/app.css", "text/css")):
            status, _, ctype = self.request("GET", path)
            self.assertEqual((status, expected in ctype), (200, True))
        self.assertEqual(self.request("GET", "/static/../agy_hub.py")[0], 404)

        hub.HUB.accounts.append(new_account())
        status, state, _ = self.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(len(state["accounts"]), 1)
        self.assertNotIn("tok-a", json.dumps(state))
        self.assertNotIn("ref-a", json.dumps(state))
        self.assertIn("autoRefreshIntervalSec", state["hub"])
        self.assertEqual(self.request("GET", "/api/accounts")[1]["accounts"][0]["id"], "acc_a")

    def test_refresh_endpoints(self):
        hub.HUB.accounts.extend([new_account("a"), new_account("b")])
        status, res, _ = self.request("POST", "/api/accounts/refresh", {"accountId": "acc_a"})
        self.assertEqual(status, 200)
        by_id = {a["id"]: a for a in res["accounts"]}
        self.assertEqual(by_id["acc_a"]["sync"]["state"], "ok")
        self.assertNotIn("sync", by_id["acc_b"])
        status, res, _ = self.request("POST", "/api/accounts/refresh", {})
        self.assertTrue(all(a["sync"]["state"] == "ok" for a in res["accounts"]))
        self.assertEqual(self.request("POST", "/api/accounts/refresh", {"accountId": "nope"})[0], 404)

    def test_foreign_requests_are_rejected(self):
        self.assertEqual(self.request("GET", "/api/state", headers={"Host": "evil.example"})[0], 403)
        status, _, _ = self.request("POST", "/api/accounts/remove", {"accountId": "x"}, headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/accounts/remove", {"accountId": "x"},
                                    headers={"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 200)
        self.assertEqual(self.request("GET", "/api/state", headers={"Host": f"localhost:{self.port}"})[0], 200)

    def test_callback_page_escapes_input(self):
        status, page, _ = self.request("GET", "/auth/callback?error=" + urllib.parse.quote("<script>alert(1)</script>"))
        self.assertEqual(status, 400)
        self.assertNotIn("<script>alert(1)", page)

    def _token_endpoint(self, ok=True):
        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, *a, **k):
            if not ok:
                raise http_error(400, "Malformed auth code.")
            sent = urllib.parse.parse_qs(req.data.decode())
            assert sent["grant_type"] == ["authorization_code"] and sent["code_verifier"][0]
            return Resp(json.dumps({"access_token": "at", "refresh_token": "rt", "expires_in": 3599}).encode())

        return mock.patch.object(hub.urllib.request, "urlopen", fake_urlopen)

    def test_add_account_link_flow(self):
        status, start, _ = self.request("POST", "/api/accounts/add-oauth", {"openBrowser": False})
        self.assertEqual(status, 200)
        url = urllib.parse.urlparse(start["authUrl"])
        qs = urllib.parse.parse_qs(url.query)
        self.assertEqual(qs["state"], [start["state"]])
        self.assertEqual(qs["code_challenge_method"], ["S256"])
        self.assertEqual(qs["redirect_uri"], [f"http://localhost:{self.port}/auth/callback"])
        self.assertFalse(start["browserOpened"])
        status_path = "/api/oauth/status?state=" + start["state"]
        self.assertEqual(self.request("GET", status_path)[1]["status"], "pending")

        complete = "/api/accounts/add-oauth/complete"
        state = start["state"]
        for bad_input in ("", "https://example.com/", "two words", f"http://localhost/auth/callback?state=other&code=c",
                          "http://localhost/auth/callback?error=access_denied"):
            status, res, _ = self.request("POST", complete, {"state": state, "input": bad_input})
            self.assertEqual((status, res["ok"]), (400, False), bad_input)
        self.assertEqual(self.request("POST", complete, {"state": "unknown", "input": "code"})[0], 400)

        with self._token_endpoint(ok=False):
            status, res, _ = self.request("POST", complete, {"state": state, "input": "badcode"})
        self.assertEqual(status, 400)
        self.assertIn("Malformed auth code", res["error"])
        st = self.request("GET", status_path)[1]
        self.assertEqual((st["status"], "Malformed" in st["error"]), ("error", True))

        pasted = f"http://localhost:{self.port}/auth/callback?state={state}&code=4/0Agood&scope=email"
        with self._token_endpoint():
            status, res, _ = self.request("POST", complete, {"state": state, "input": pasted})
            self.assertEqual((status, res["ok"], res["email"]), (200, True, "new@example.com"))
            # Pasting again (or the redirect also reaching the hub) is idempotent
            status, res, _ = self.request("POST", complete, {"state": state, "input": pasted})
            self.assertEqual((status, res["ok"]), (200, True))
        self.assertEqual(self.request("GET", status_path)[1]["status"], "completed")
        self.assertEqual([a["email"] for a in hub.HUB.accounts], ["new@example.com"])
        self.assertEqual(hub.HUB.accounts[0]["token"]["refresh_token"], "rt")

    def test_add_account_direct_callback_cancel_and_expiry(self):
        state = self.request("POST", "/api/accounts/add-oauth", {"openBrowser": True})[1]["state"]
        with self._token_endpoint():
            status, page, _ = self.request("GET", f"/auth/callback?state={state}&code=good")
        self.assertEqual(status, 200)
        self.assertIn("new@example.com", page)

        state2 = self.request("POST", "/api/accounts/add-oauth", {"openBrowser": False})[1]["state"]
        self.assertTrue(self.request("POST", "/api/accounts/add-oauth/cancel", {"state": state2})[1]["cancelled"])
        self.assertEqual(self.request("GET", "/api/oauth/status?state=" + state2)[1]["status"], "unknown")

        state3 = self.request("POST", "/api/accounts/add-oauth", {"openBrowser": False})[1]["state"]
        hub.HUB.pending_oauth[state3]["created_at"] -= hub.OAUTH_FLOW_TTL_SEC + 1
        self.assertEqual(self.request("GET", "/api/oauth/status?state=" + state3)[1]["status"], "expired")
        self.assertEqual(self.request("POST", "/api/accounts/add-oauth/complete", {"state": state3, "input": "c"})[0], 400)

    def test_settings_are_coerced(self):
        res = self.request("POST", "/api/settings/update", {"autoRefreshIntervalSec": 5, "pinWorkspacesOnSwitch": 0})[1]
        self.assertEqual(res["settings"]["autoRefreshIntervalSec"], 30)
        self.assertIs(res["settings"]["pinWorkspacesOnSwitch"], False)
        self.assertEqual(self.request("POST", "/api/settings/update", {"autoRefreshIntervalSec": "x"})[1]["settings"]["autoRefreshIntervalSec"], 120)
        self.assertEqual(self.request("POST", "/api/settings/update", {"autoRefreshIntervalSec": 0})[1]["settings"]["autoRefreshIntervalSec"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
