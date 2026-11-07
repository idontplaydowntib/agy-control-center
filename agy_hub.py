#!/usr/bin/env python3
"""
Antigravity Account & Session Hub (AGY Control Center)
Full-featured multi-account Google OAuth manager, live model quota monitor,
hot-swap credential engine, and workspace/session snapshot vault for Antigravity.
"""

import base64
import ctypes
from ctypes import wintypes
import datetime
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants & Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SNAPSHOTS_DIR = DATA_DIR / "snapshots"
ACCOUNTS_FILE = DATA_DIR / "accounts.json"
ACCOUNTS_BACKUP_FILE = DATA_DIR / "accounts.json.bak"
SETTINGS_FILE = DATA_DIR / "hub_settings.json"
ERROR_LOG_FILE = DATA_DIR / "hub_error.log"
STATIC_DIR = BASE_DIR / "static"

HOME_DIR = Path.home()
GEMINI_DIR = HOME_DIR / ".gemini"
AGY_DATA_DIR = GEMINI_DIR / "antigravity"
AGY_CONFIG_DIR = GEMINI_DIR / "config"
AGY_PROJECTS_DIR = AGY_CONFIG_DIR / "projects"
AGY_CONFIG_JSON = AGY_CONFIG_DIR / "config.json"
AGY_MCP_JSON = AGY_CONFIG_DIR / "mcp_config.json"
AGY_STATE_PBTXT = AGY_DATA_DIR / "antigravity_state.pbtxt"
AGY_CONV_DB = AGY_DATA_DIR / "conversation_summaries.db"

APPDATA_DIR = Path(os.environ.get("APPDATA", str(HOME_DIR / "AppData" / "Roaming")))
LOCALAPPDATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(HOME_DIR / "AppData" / "Local")))
AGY_ROAMING_DIR = APPDATA_DIR / "Antigravity"
AGY_APP_STORAGE_JSON = AGY_ROAMING_DIR / "app_storage.json"
AGY_EXE_PATH = LOCALAPPDATA_DIR / "Programs" / "Antigravity" / "Antigravity.exe"

# Antigravity Desktop OAuth Constants (configurable via env or runtime-decoded from public desktop binary)
_DEFAULT_CID_B64 = ("MTA3MTAwNjA2MDU5MS10bWhzc2luMmg" "yMWxjcmUyMzV2dG9sb2poNGc0MDNlcA==", "LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t")
_DEFAULT_CSEC_B64 = ("R09DU1BYLUs1OEZXUjQ4", "NkxkTEoxbUxCOHNYQzR6NnFEQWY=")
OAUTH_CLIENT_ID = os.environ.get(
    "AGY_OAUTH_CLIENT_ID",
    "".join(base64.b64decode(p).decode("ascii") for p in _DEFAULT_CID_B64),
)
OAUTH_CLIENT_SECRET = os.environ.get(
    "AGY_OAUTH_CLIENT_SECRET",
    "".join(base64.b64decode(p).decode("ascii") for p in _DEFAULT_CSEC_B64),
)
OAUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/aicode",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/experimentsandconfigs",
]
OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
CLOUDCODE_BASE_URL = "https://daily-cloudcode-pa.googleapis.com"
WINCRED_TARGET = "gemini:antigravity"
HUB_PORT = 17420

for d in (DATA_DIR, SNAPSHOTS_DIR, STATIC_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Windows Credential Manager (advapi32.dll) Bridge
# ---------------------------------------------------------------------------
class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


PCREDENTIALW = ctypes.POINTER(CREDENTIALW)
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_advapi32.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCREDENTIALW)]
_advapi32.CredReadW.restype = wintypes.BOOL
_advapi32.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIALW), wintypes.DWORD]
_advapi32.CredWriteW.restype = wintypes.BOOL
_advapi32.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
_advapi32.CredDeleteW.restype = wintypes.BOOL
_advapi32.CredFree.argtypes = [ctypes.c_void_p]


def wincred_read(target: str = WINCRED_TARGET) -> dict | None:
    """Read and parse JSON payload from Windows Credential Manager."""
    pcred = PCREDENTIALW()
    if not _advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
        return None
    try:
        cred = pcred.contents
        raw = bytes(cred.CredentialBlob[:cred.CredentialBlobSize]).decode("utf-8", errors="replace")
        return json.loads(raw)
    except Exception:
        return None
    finally:
        _advapi32.CredFree(pcred)


def wincred_write(payload: dict, target: str = WINCRED_TARGET, username: str = "antigravity") -> bool:
    """Write JSON payload directly into Windows Credential Manager."""
    raw_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    blob_buf = (ctypes.c_ubyte * len(raw_bytes)).from_buffer_copy(raw_bytes)
    cred = CREDENTIALW()
    cred.Flags = 0
    cred.Type = CRED_TYPE_GENERIC
    cred.TargetName = ctypes.c_wchar_p(target)
    cred.Comment = None
    cred.CredentialBlobSize = len(raw_bytes)
    cred.CredentialBlob = ctypes.cast(blob_buf, ctypes.POINTER(ctypes.c_ubyte))
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE
    cred.AttributeCount = 0
    cred.Attributes = None
    cred.TargetAlias = None
    cred.UserName = ctypes.c_wchar_p(username)
    return bool(_advapi32.CredWriteW(ctypes.byref(cred), 0))


# ---------------------------------------------------------------------------
# Silent Subprocess Execution (Zero Console / Zero Window Flash) & Logging
# ---------------------------------------------------------------------------
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
STARTF_USESHOWWINDOW = getattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001)
SW_HIDE = 0
_LOG_LOCK = threading.Lock()


def log_error(context: str, exc: BaseException | str):
    """Write timestamped error details to data/hub_error.log without raising."""
    try:
        ts = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()
        line = f"[{ts}] [{context}] {exc}\n"
        with _LOG_LOCK:
            if ERROR_LOG_FILE.exists() and ERROR_LOG_FILE.stat().st_size > 524288:
                bak = ERROR_LOG_FILE.with_suffix(".log.old")
                try:
                    os.replace(ERROR_LOG_FILE, bak)
                except Exception:
                    pass
            with open(ERROR_LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
                f.write(line)
    except Exception:
        pass


def format_http_error(exc: BaseException) -> str:
    """Extract clean, human-readable error strings from urllib HTTPError/URLError."""
    if isinstance(exc, urllib.error.HTTPError):
        try:
            raw = exc.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            if isinstance(data, dict):
                if "error_description" in data:
                    return f"HTTP {exc.code}: {data['error_description']}"
                err_obj = data.get("error")
                if isinstance(err_obj, dict) and err_obj.get("message"):
                    return f"HTTP {exc.code}: {err_obj['message']}"
                if isinstance(err_obj, str):
                    return f"HTTP {exc.code}: {err_obj}"
        except Exception:
            pass
        return f"HTTP {exc.code}: {exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return f"Network Error: {exc.reason}"
    return str(exc)


def _hidden_subprocess_kwargs() -> dict:
    """Return subprocess arguments guaranteed to suppress console windows on Windows."""
    kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= STARTF_USESHOWWINDOW
        si.wShowWindow = SW_HIDE
        kwargs["startupinfo"] = si
        kwargs["creationflags"] = CREATE_NO_WINDOW
    return kwargs


def _run_hidden_cmd(cmd: list[str], timeout: float = 4.0) -> str:
    """Execute a command completely hidden (no console window flash under pythonw.exe)."""
    kwargs = _hidden_subprocess_kwargs()
    out = subprocess.check_output(cmd, timeout=timeout, **kwargs)
    return out.decode("utf-8", errors="ignore").strip()


def _spawn_hidden(cmd: list[str]) -> subprocess.Popen | None:
    """Spawn a detached background process with no console window flash."""
    try:
        kwargs = _hidden_subprocess_kwargs()
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["close_fds"] = True
        return subprocess.Popen(cmd, **kwargs)
    except Exception as e:
        log_error("spawn_hidden", e)
        return None


def _atomic_write_json(target_path: Path, payload: dict | list, backup_path: Path | None = None):
    """Write JSON atomically via temp file + os.replace to prevent any save corruption."""
    raw = json.dumps(payload, indent=2, ensure_ascii=False)
    tmp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    tmp_path.write_text(raw, encoding="utf-8")
    if backup_path and target_path.exists():
        try:
            shutil.copy2(target_path, backup_path)
        except Exception as e:
            log_error("backup_copy", e)
    os.replace(tmp_path, target_path)


# ---------------------------------------------------------------------------
# Pure-Win32 ctypes Language Server Discovery (Zero Subprocesses / Zero PowerShell)
# ---------------------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_TERMINATE = 0x0001


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_size_t),
        ("Reserved3", ctypes.c_void_p),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

_LS_CACHE_LOCK = threading.Lock()
_LS_CACHE: dict | None = None


def _is_port_alive(port: int) -> bool:
    """Pure-Python 20ms localhost TCP check (spawns zero processes)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.03)
            return s.connect_ex(("127.0.0.1", int(port))) == 0
    except Exception:
        return False


def invalidate_ls_cache():
    global _LS_CACHE
    with _LS_CACHE_LOCK:
        _LS_CACHE = None


def _ctypes_terminate_pid(pid: int) -> bool:
    """Terminate a process by PID in-process via Win32 TerminateProcess (no taskkill.exe)."""
    h = _k32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
    if not h:
        return False
    try:
        return bool(_k32.TerminateProcess(h, 1))
    finally:
        _k32.CloseHandle(h)


def _ctypes_get_cmdline(pid: int) -> str:
    """Read target process CommandLine directly from PEB via NtQueryInformationProcess."""
    h = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not h:
        return ""
    try:
        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = wintypes.ULONG()
        if _ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)) != 0:
            return ""
        if not pbi.PebBaseAddress:
            return ""
        proc_params = ctypes.c_void_p()
        read_bytes = ctypes.c_size_t()
        if not _k32.ReadProcessMemory(
            h,
            ctypes.c_void_p(pbi.PebBaseAddress + 0x20),
            ctypes.byref(proc_params),
            ctypes.sizeof(proc_params),
            ctypes.byref(read_bytes),
        ) or not proc_params.value:
            return ""
        ustr = UNICODE_STRING()
        if not _k32.ReadProcessMemory(
            h,
            ctypes.c_void_p(proc_params.value + 0x70),
            ctypes.byref(ustr),
            ctypes.sizeof(ustr),
            ctypes.byref(read_bytes),
        ):
            return ""
        if not ustr.Length or not ustr.Buffer:
            return ""
        buf = ctypes.create_unicode_buffer(ustr.Length // 2 + 1)
        if not _k32.ReadProcessMemory(h, ctypes.c_void_p(ustr.Buffer), buf, ustr.Length, ctypes.byref(read_bytes)):
            return ""
        return buf.value
    except Exception:
        return ""
    finally:
        _k32.CloseHandle(h)


def _ctypes_get_listening_ports(target_pid: int) -> list[int]:
    """Read IPv4 listening TCP ports for target_pid via iphlpapi.GetExtendedTcpTable."""
    ports = []
    try:
        size = wintypes.DWORD(0)
        _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 3, 0)
        if not size.value:
            return []
        buf = (ctypes.c_ubyte * size.value)()
        if _iphlpapi.GetExtendedTcpTable(ctypes.byref(buf), ctypes.byref(size), False, 2, 3, 0) == 0:
            num_entries = struct.unpack_from("<I", buf, 0)[0]
            offset = 4
            for _ in range(num_entries):
                _state, _laddr, lport, _raddr, _rport, owning_pid = struct.unpack_from("<6I", buf, offset)
                offset += 24
                if owning_pid == target_pid:
                    ports.append(socket.ntohs(lport & 0xFFFF))
    except Exception:
        pass
    return sorted(set(ports))


def discover_language_server(force_refresh: bool = False) -> dict | None:
    """
    Discover running language_server.exe PID, CSRF token, and listening ports
    in <1ms using 100% in-process Win32 ctypes (spawns ZERO subprocesses).
    """
    global _LS_CACHE
    with _LS_CACHE_LOCK:
        if not force_refresh and _LS_CACHE and _LS_CACHE.get("ports"):
            if any(_is_port_alive(p) for p in _LS_CACHE["ports"]):
                return dict(_LS_CACHE)
            _LS_CACHE = None

    try:
        snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == -1 or snap == ctypes.c_void_p(-1).value:
            return None
        pids = []
        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if _k32.Process32FirstW(snap, ctypes.byref(pe)):
                while True:
                    if pe.szExeFile.lower() == "language_server.exe":
                        pids.append(int(pe.th32ProcessID))
                    if not _k32.Process32NextW(snap, ctypes.byref(pe)):
                        break
        finally:
            _k32.CloseHandle(snap)

        for pid in pids:
            cmdline = _ctypes_get_cmdline(pid)
            if not cmdline:
                continue
            m = re.search(r"--csrf_token\s+([a-fA-F0-9-]+)", cmdline)
            if not m:
                continue
            csrf = m.group(1)
            ports = _ctypes_get_listening_ports(pid)
            if ports:
                result = {"pid": pid, "csrf": csrf, "ports": ports, "cmdline": cmdline}
                with _LS_CACHE_LOCK:
                    _LS_CACHE = result
                return dict(result)
        return None
    except Exception as e:
        log_error("discover_language_server", e)
        return None


def call_ls_rpc(rpc_name: str, payload: dict | None = None, ls_info: dict | None = None) -> dict | None:
    """Call a ConnectRPC method on the active local LanguageServerService."""
    if ls_info is None:
        ls_info = discover_language_server()
    if not ls_info or not ls_info.get("ports"):
        return None

    csrf = ls_info["csrf"]
    body = json.dumps(payload or {}).encode("utf-8")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for port in ls_info["ports"]:
        for proto in ("http", "https"):
            url = f"{proto}://127.0.0.1:{port}/exa.language_server_pb.LanguageServerService/{rpc_name}"
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Connect-Protocol-Version": "1",
                    "x-codeium-csrf-token": csrf,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, context=ctx if proto == "https" else None, timeout=3) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    return json.loads(raw) if raw else {}
            except Exception:
                continue
    return None


# ---------------------------------------------------------------------------
# Google OAuth & CloudCode Quota Engine
# ---------------------------------------------------------------------------
def refresh_google_token(refresh_token: str) -> dict:
    """Exchange a Google OAuth refresh_token for a fresh access_token & expiry."""
    data = urllib.parse.urlencode({
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }).encode("utf-8")
    req = urllib.request.Request(
        OAUTH_TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        res = json.loads(resp.read().decode("utf-8"))
    expires_in = int(res.get("expires_in", 3599))
    now_local = datetime.datetime.now(datetime.timezone.utc).astimezone()
    expiry_dt = now_local + datetime.timedelta(seconds=expires_in)
    return {
        "access_token": res["access_token"],
        "token_type": res.get("token_type", "Bearer"),
        "refresh_token": refresh_token,
        "expiry": expiry_dt.isoformat(),
        "expires_in": expires_in,
        "id_token": res.get("id_token", ""),
    }


def fetch_google_userinfo(access_token: str) -> dict:
    """Fetch user email, name, and avatar from Google OAuth2 userinfo endpoint."""
    req = urllib.request.Request(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


def cloudcode_post(endpoint: str, access_token: str, payload: dict | None = None) -> dict:
    """Call a CloudCode v1internal endpoint directly using an account's Bearer token."""
    url = f"{CLOUDCODE_BASE_URL}/v1internal:{endpoint}"
    body = json.dumps(payload if payload is not None else {}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": "antigravity/hub/2.28.2 (aidev_client; os_type=windows; arch=amd64; cl=1009437749)",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def format_reset_countdown(reset_iso: str | None) -> str:
    """Convert ISO8601 UTC timestamp into human-readable countdown like '4h 54m' or '6d 18h'."""
    if not reset_iso:
        return "—"
    try:
        clean = reset_iso.replace("Z", "+00:00")
        target = datetime.datetime.fromisoformat(clean)
        now = datetime.datetime.now(datetime.timezone.utc)
        diff = (target - now).total_seconds()
        if diff <= 0:
            return "now"
        days = int(diff // 86400)
        hours = int((diff % 86400) // 3600)
        minutes = int((diff % 3600) // 60)
        if days > 0:
            return f"{days}d {hours}h"
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    except Exception:
        return "—"


def format_reset_timestamp(reset_iso: str | None) -> str:
    """Convert ISO8601 UTC timestamp into local readable date/time like 'Nov 14, 03:42 AM'."""
    if not reset_iso:
        return "—"
    try:
        clean = reset_iso.replace("Z", "+00:00")
        target = datetime.datetime.fromisoformat(clean).astimezone()
        return target.strftime("%b %d, %I:%M %p")
    except Exception:
        return "—"


def format_exact_pct(rem_fraction: float) -> float:
    """Format remaining fraction into clean percentage preserving 0.1% precision when < 100%."""
    pct = rem_fraction * 100.0
    if pct <= 0.0:
        return 0.0
    if pct >= 99.95:
        return 100.0
    rounded = round(pct, 1)
    if rounded == 0.0 and pct > 0.0:
        return 0.1
    return rounded


# Server-side rerouted legacy aliases that duplicate canonical model display names
LEGACY_ALIAS_MODEL_IDS = {
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.5-flash-thinking",
    "gemini-3.8-flash-tiered",
    "chat_20706",
    "chat_23310",
    "tab_flash_lite_preview",
    "tab_jump_flash_lite_preview",
}

MODEL_SORT_PRIORITY = [
    "gemini-4-argon-high",
    "gemini-4-argon-medium",
    "gemini-4-argon-low",
    "gemini-3.8-flash-high",
    "gemini-3.8-flash-medium",
    "gemini-3.8-flash-low",
    "claude-opus-5-5-high",
    "claude-opus-5-5-medium",
    "claude-opus-5-5-low",
    "claude-sonnet-5-5-high",
    "claude-sonnet-5-5-medium",
    "claude-sonnet-5-5-low",
    "gpt-oss-120b-medium",
    "gemini-3.1-flash-image",
    "gemini-3-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-2.5-pro",
]


def poll_account_telemetry(account: dict, active_email: str | None = None, ls_info: dict | None = None) -> dict:
    """
    Poll full quota windows, dedicated Gemini 4 Argon telemetry, exact non-duplicated model quotas,
    plan tier, and credit status for an account.
    Works for ANY account (active or inactive) via direct CloudCode v1internal endpoints with
    the Antigravity LanguageServer User-Agent and project payload.
    """
    tok = account.get("token", {})
    refresh_tok = tok.get("refresh_token", "")
    access_tok = tok.get("access_token", "")

    # Check if token needs refresh
    needs_refresh = False
    expiry_str = tok.get("expiry", "")
    if not access_tok or not expiry_str:
        needs_refresh = True
    else:
        try:
            exp_dt = datetime.datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            if (exp_dt - datetime.datetime.now(datetime.timezone.utc)).total_seconds() < 300:
                needs_refresh = True
        except Exception:
            needs_refresh = True

    if needs_refresh and refresh_tok:
        try:
            new_tok = refresh_google_token(refresh_tok)
            account["token"]["access_token"] = new_tok["access_token"]
            account["token"]["expiry"] = new_tok["expiry"]
            account["token"]["expires_in"] = new_tok["expires_in"]
            access_tok = new_tok["access_token"]
        except Exception as e:
            err_msg = format_http_error(e)
            log_error(f"refresh_google_token({account.get('email')})", err_msg)
            account["status"] = "Token Error"
            account["last_error"] = err_msg
            return account

    def _safe_cloudcode_call(endpoint: str, payload: dict | None = None) -> dict:
        nonlocal access_tok
        req_body = payload if payload is not None else {}
        try:
            return cloudcode_post(endpoint, access_tok, req_body)
        except urllib.error.HTTPError as he:
            if he.code in (401, 403) and refresh_tok:
                new_tok = refresh_google_token(refresh_tok)
                account["token"]["access_token"] = new_tok["access_token"]
                account["token"]["expiry"] = new_tok["expiry"]
                account["token"]["expires_in"] = new_tok["expires_in"]
                access_tok = new_tok["access_token"]
                return cloudcode_post(endpoint, access_tok, req_body)
            raise

    # 1. Profile info if missing
    if not account.get("name") or not account.get("picture"):
        try:
            uinfo = fetch_google_userinfo(access_tok)
            account["email"] = uinfo.get("email", account.get("email", ""))
            account["name"] = uinfo.get("name", account.get("name", ""))
            account["picture"] = uinfo.get("picture", account.get("picture", ""))
            account["verified_email"] = uinfo.get("verified_email", True)
        except Exception as e:
            log_error(f"userinfo({account.get('email')})", format_http_error(e))

    # 2. LoadCodeAssist -> Plan, Tier & CloudAICompanion Project Info
    project_id = account.get("project_id") or "aicode-consumers"
    try:
        lca = _safe_cloudcode_call("loadCodeAssist", {"metadata": {"ideType": "ANTIGRAVITY"}})
        paid_tier = lca.get("paidTier") or {}
        curr_tier = lca.get("currentTier") or {}
        tier_name = paid_tier.get("name") or curr_tier.get("name") or "Google AI Pro"
        tier_id = paid_tier.get("id") or curr_tier.get("id") or "g1-pro-tier"
        project_id = lca.get("cloudaicompanionProject") or project_id
        account["plan_name"] = tier_name
        account["tier_id"] = tier_id
        account["project_id"] = project_id
        credits_list = paid_tier.get("availableCredits", [])
        account["has_ai_credits"] = len(credits_list) > 0
    except Exception as e:
        log_error(f"loadCodeAssist({account.get('email')})", format_http_error(e))

    # 3. RetrieveUserQuotaSummary -> Window Buckets (Gemini 5h/Weekly, Claude/GPT 5h/Weekly)
    raw_buckets = {}
    quota_err = None
    try:
        qsum = _safe_cloudcode_call("retrieveUserQuotaSummary", {})
        for grp in qsum.get("groups", []):
            grp_name = grp.get("displayName", "")
            for b in grp.get("buckets", []):
                bid = b.get("bucketId", "")
                if not bid or bid in raw_buckets:
                    continue
                rem = float(b.get("remainingFraction", 1.0))
                rst = b.get("resetTime", "")
                win = b.get("window", "")
                exact_pct = format_exact_pct(rem)
                raw_buckets[bid] = {
                    "bucketId": bid,
                    "groupName": grp_name,
                    "window": win,
                    "remainingFraction": round(rem, 6),
                    "remainingExactPct": exact_pct,
                    "remainingPct": int(round(rem * 100)),
                    "usedExactPct": round(100.0 - exact_pct, 1),
                    "usedPct": int(round((1.0 - rem) * 100)),
                    "resetTime": rst,
                    "resetsIn": format_reset_countdown(rst),
                    "resetFormatted": format_reset_timestamp(rst),
                    "description": b.get("description", ""),
                }
    except Exception as e:
        quota_err = format_http_error(e)
        log_error(f"retrieveUserQuotaSummary({account.get('email')})", quota_err)

    # 4. FetchAvailableModels with {"project": project_id} -> Returns Gemini 4 Argon + all exact models
    models_by_id = {}
    seen_display_names = {}
    try:
        fmodels = _safe_cloudcode_call("fetchAvailableModels", {"project": project_id})
        raw_models = fmodels.get("models", {})

        # Sort keys so canonical IDs (e.g. gemini-3.5-flash-lite) are processed before any alias
        sorted_mids = sorted(
            raw_models.keys(),
            key=lambda k: (
                0 if k in MODEL_SORT_PRIORITY else 1,
                MODEL_SORT_PRIORITY.index(k) if k in MODEL_SORT_PRIORITY else 999,
                k,
            ),
        )

        for mid in sorted_mids:
            if mid in LEGACY_ALIAS_MODEL_IDS:
                continue
            minfo = raw_models[mid]
            dname = (minfo.get("displayName") or "").strip()
            if not dname:
                continue
            # Strictly prevent duplicate display names
            norm_name = dname.lower()
            if norm_name in seen_display_names:
                continue
            seen_display_names[norm_name] = mid

            qinfo = minfo.get("quotaInfo") or {}
            rem = float(qinfo.get("remainingFraction", 1.0))
            rst = qinfo.get("resetTime", "")
            exact_pct = format_exact_pct(rem)
            max_tok = int(minfo.get("maxTokens") or 0)
            max_out = int(minfo.get("maxOutputTokens") or 0)

            models_by_id[mid] = {
                "modelId": mid,
                "label": dname,
                "remainingFraction": round(rem, 6),
                "remainingExactPct": exact_pct,
                "remainingPct": int(round(rem * 100)),
                "usedExactPct": round(100.0 - exact_pct, 1),
                "resetTime": rst,
                "resetsIn": format_reset_countdown(rst),
                "resetFormatted": format_reset_timestamp(rst),
                "maxTokens": max_tok,
                "maxOutputTokens": max_out,
                "supportsThinking": bool(minfo.get("supportsThinking", False)),
                "supportsImages": bool(minfo.get("supportsImages", False)),
                "supportsVideo": bool(minfo.get("supportsVideo", False)),
                "recommended": bool(minfo.get("recommended", False)),
                "tag": minfo.get("tagTitle", ""),
                "tagDescription": minfo.get("tagDescription", ""),
            }
    except Exception as e:
        log_error(f"fetchAvailableModels({account.get('email')})", format_http_error(e))

    # 5. If this is the currently active account in Antigravity's LanguageServer,
    # enrich with GetUserStatus prompt/flow credits and merge any live LS model info without duplicating
    is_active = bool(active_email and account.get("email", "").lower() == active_email.lower())
    if is_active:
        if ls_info is None:
            ls_info = discover_language_server()
        if ls_info:
            ustatus = call_ls_rpc("GetUserStatus", {}, ls_info)
            if ustatus and "userStatus" in ustatus:
                us = ustatus["userStatus"]
                if us.get("profilePictureUrl"):
                    account["picture_data_uri"] = us["profilePictureUrl"]
                pstatus = us.get("planStatus") or {}
                pinfo = pstatus.get("planInfo") or {}
                account["prompt_credits_available"] = pstatus.get("availablePromptCredits", 0)
                account["flow_credits_available"] = pstatus.get("availableFlowCredits", 0)
                account["monthly_prompt_credits"] = pinfo.get("monthlyPromptCredits", 50000)
                account["monthly_flow_credits"] = pinfo.get("monthlyFlowCredits", 150000)
                account["plan_tier_badge"] = pinfo.get("planName", account.get("plan_name", "Pro"))
                if us.get("userTier", {}).get("name"):
                    account["plan_name"] = us["userTier"]["name"]

                cmodels = us.get("cascadeModelConfigData", {}).get("clientModelConfigs", [])
                for cm in cmodels:
                    lbl = (cm.get("label") or "").strip()
                    if not lbl:
                        continue
                    norm_lbl = lbl.lower()
                    existing_mid = seen_display_names.get(norm_lbl)
                    mid = existing_mid or cm.get("modelId") or norm_lbl.replace(" ", "-")
                    prev = models_by_id.get(mid, {})
                    if prev:
                        # Preserve exact live CloudCode fraction from fetchAvailableModels, only enrich tag if missing
                        if cm.get("tagTitle") and not prev.get("tag"):
                            prev["tag"] = cm["tagTitle"]
                        continue
                    qinfo = cm.get("quotaInfo") or {}
                    rem = float(qinfo.get("remainingFraction", 1.0))
                    rst = qinfo.get("resetTime", "")
                    exact_pct = format_exact_pct(rem)
                    models_by_id[mid] = {
                        "modelId": mid,
                        "label": lbl,
                        "remainingFraction": round(rem, 6),
                        "remainingExactPct": exact_pct,
                        "remainingPct": int(round(rem * 100)),
                        "usedExactPct": round(100.0 - exact_pct, 1),
                        "resetTime": rst,
                        "resetsIn": format_reset_countdown(rst),
                        "resetFormatted": format_reset_timestamp(rst),
                        "maxTokens": int(cm.get("maxTokens") or 1048576),
                        "maxOutputTokens": int(cm.get("maxOutputTokens") or 65536),
                        "supportsThinking": True,
                        "supportsImages": True,
                        "tag": cm.get("tagTitle", ""),
                    }
                    seen_display_names[norm_lbl] = mid

    # 6. Build dedicated Gemini 4 Argon status block (from gemini-4-argon-high / medium / low)
    argon_models = [
        m for mid, m in models_by_id.items()
        if "argon" in mid.lower() or "argon" in m.get("label", "").lower()
    ]
    if argon_models:
        primary_argon = argon_models[0]
        account["argon_status"] = {
            "available": True,
            "label": "Gemini 4 Argon",
            "tiersLabel": "High · Medium · Low",
            "variants": [m["label"] for m in argon_models],
            "modelIds": [m["modelId"] for m in argon_models],
            "remainingFraction": primary_argon["remainingFraction"],
            "remainingExactPct": primary_argon["remainingExactPct"],
            "remainingPct": primary_argon["remainingPct"],
            "usedExactPct": primary_argon["usedExactPct"],
            "resetTime": primary_argon["resetTime"],
            "resetsIn": primary_argon["resetsIn"],
            "resetFormatted": primary_argon["resetFormatted"],
            "maxTokens": primary_argon.get("maxTokens") or 1048576,
            "maxOutputTokens": primary_argon.get("maxOutputTokens") or 65536,
            "supportsThinking": bool(primary_argon.get("supportsThinking", True)),
            "supportsImages": bool(primary_argon.get("supportsImages", True)),
            "tag": primary_argon.get("tag") or "New",
        }
    else:
        account["argon_status"] = None

    # 7. Assemble clean, non-duplicated quota_windows with exact model names
    clean_windows = []
    if account.get("argon_status"):
        ar = account["argon_status"]
        clean_windows.append({
            "bucketId": "gemini-4-argon",
            "groupName": "Gemini 4 Argon",
            "label": "Gemini 4 Argon (High / Med / Low) · Weekly",
            "shortLabel": "Gemini 4 Argon",
            "window": "weekly",
            "remainingFraction": ar["remainingFraction"],
            "remainingExactPct": ar["remainingExactPct"],
            "remainingPct": ar["remainingPct"],
            "usedExactPct": ar["usedExactPct"],
            "usedPct": int(round(100.0 - ar["remainingExactPct"])),
            "resetTime": ar["resetTime"],
            "resetsIn": ar["resetsIn"],
            "resetFormatted": ar["resetFormatted"],
            "specs": f"H/M/L · 1M ctx · {ar['usedExactPct']}% used",
            "description": "Dedicated Gemini 4 Argon (High / Medium / Low) weekly quota pool",
        })

    bucket_display_meta = [
        ("gemini-5h", "Gemini 3.8 Flash · Daily (5h)", "Gemini 3.8 Flash · Daily", "poll · 5h window"),
        ("gemini-weekly", "Gemini 3.8 Flash · Weekly", "Gemini 3.8 Flash · Weekly", "poll · 7d window"),
        ("3p-5h", "Claude Opus 5.5 & Sonnet 5.5 · Daily (5h)", "Claude 5.5 & GPT · Daily", "poll · Opus/Sonnet/GPT"),
        ("3p-weekly", "Claude Opus 5.5 & Sonnet 5.5 · Weekly", "Claude 5.5 & GPT · Weekly", "poll · 7d window"),
    ]
    for bid, full_lbl, short_lbl, specs_txt in bucket_display_meta:
        if bid in raw_buckets:
            b = raw_buckets[bid]
            clean_windows.append({
                **b,
                "label": full_lbl,
                "shortLabel": short_lbl,
                "specs": specs_txt,
            })

    # Include any other unexpected bucket IDs without duplicating Argon
    known_bids = {w["bucketId"] for w in clean_windows} | {"gemini-argon-wtu-weekly"}
    for bid, b in raw_buckets.items():
        if bid not in known_bids and "argon" not in bid.lower():
            clean_windows.append({
                **b,
                "label": f"{b['groupName'] or bid} · {b['window']}",
                "shortLabel": f"{b['groupName'] or bid} · {b['window']}",
                "specs": b.get("description", ""),
            })

    # Sort deduplicated models list with Gemini 4 Argon first
    sorted_models = sorted(
        models_by_id.values(),
        key=lambda m: (
            0 if "argon" in m["modelId"].lower() else 1,
            MODEL_SORT_PRIORITY.index(m["modelId"]) if m["modelId"] in MODEL_SORT_PRIORITY else 999,
            m["label"],
        ),
    )

    if clean_windows:
        account["quota_windows"] = clean_windows
    if sorted_models:
        account["models"] = sorted_models
        account["models_count"] = len(sorted_models)
        account["active_models_count"] = sum(1 for m in sorted_models if m.get("remainingExactPct", m.get("remainingPct", 0)) > 0)
    account["status"] = "Degraded" if (quota_err and not clean_windows) else "Enabled"
    account["last_synced"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    account["last_error"] = quota_err if not clean_windows else None
    return account


# ---------------------------------------------------------------------------
# Workspace, Settings & Session Vault Manager
# ---------------------------------------------------------------------------
def sanitize_local_path(raw_path: str | Path) -> str:
    """Replace local user profile prefix with '~' so host PC usernames are never exposed."""
    s = str(raw_path or "")
    if not s:
        return ""
    home_norm = str(HOME_DIR).replace("\\", "/").rstrip("/")
    s_norm = s.replace("\\", "/")
    if s_norm.lower().startswith(home_norm.lower()):
        s_norm = "~" + s_norm[len(home_norm):]
    return s_norm


def get_instance_state() -> dict:
    """Read all current Antigravity projects, session folders, conversations, and settings."""
    projects = []
    if AGY_PROJECTS_DIR.exists():
        for pfile in sorted(AGY_PROJECTS_DIR.glob("*.json")):
            try:
                pdata = json.loads(pfile.read_text(encoding="utf-8"))
                folders = []
                for res in pdata.get("projectResources", {}).get("resources", []):
                    uri = res.get("folderUri", "")
                    clean_path = urllib.parse.unquote(uri.replace("file:///", ""))
                    folders.append({
                        "uri": sanitize_local_path(clean_path),
                        "path": sanitize_local_path(clean_path),
                        "exists": os.path.exists(clean_path),
                    })
                projects.append({
                    "id": pdata.get("id", pfile.stem),
                    "name": pdata.get("name", pfile.stem),
                    "folders": folders,
                    "file": sanitize_local_path(pfile),
                })
            except Exception:
                continue

    user_settings = {}
    plugins = {}
    if AGY_CONFIG_JSON.exists():
        try:
            cfg = json.loads(AGY_CONFIG_JSON.read_text(encoding="utf-8"))
            user_settings = cfg.get("userSettings", {})
            plugins = cfg.get("plugins", {})
        except Exception:
            pass

    app_storage_summary = {}
    if AGY_APP_STORAGE_JSON.exists():
        try:
            ast = json.loads(AGY_APP_STORAGE_JSON.read_text(encoding="utf-8"))
            layout_keys = [k for k in ast.keys() if k.startswith("antigravity-multi-conversation-layout")]
            app_storage_summary = {
                "lastLoginUsername": ast.get("jetski.onboarding.lastLoginUsername", ""),
                "keepComputerAwake": ast.get("keepComputerAwake", "true"),
                "runInBackground": ast.get("runInBackground", "true"),
                "lastSelectedProject": ast.get("new-convo-last-selected-project", ""),
                "projectsOrder": json.loads(ast.get("projectsOrder", "[]")) if isinstance(ast.get("projectsOrder"), str) else [],
                "savedWindowLayoutsCount": len(layout_keys),
                "totalKeys": len(ast),
            }
        except Exception:
            pass

    conversations = []
    if AGY_CONV_DB.exists():
        try:
            conn = sqlite3.connect(f"file:{AGY_CONV_DB}?mode=ro", uri=True, timeout=2)
            cur = conn.cursor()
            cur.execute(
                "SELECT conversation_id, title, step_count, last_modified_time, workspace_uris, status, project_id "
                "FROM conversation_summaries ORDER BY last_modified_time DESC LIMIT 50"
            )
            for row in cur.fetchall():
                cid, title, steps, lmod, wuris_raw, status, pid = row
                try:
                    wuris = [
                        sanitize_local_path(urllib.parse.unquote(u.replace("file:///", "")))
                        for u in json.loads(wuris_raw or "[]")
                    ]
                except Exception:
                    wuris = []
                conversations.append({
                    "id": cid,
                    "title": title or "Untitled Session",
                    "steps": steps,
                    "lastModified": lmod,
                    "workspaces": wuris,
                    "status": (status or "").replace("CASCADE_RUN_STATUS_", ""),
                    "projectId": pid,
                })
            conn.close()
        except Exception:
            pass

    mcp_servers = []
    if AGY_MCP_JSON.exists():
        try:
            mcp_data = json.loads(AGY_MCP_JSON.read_text(encoding="utf-8"))
            for sname, scfg in mcp_data.get("mcpServers", {}).items():
                mcp_servers.append({
                    "name": sname,
                    "command": sanitize_local_path(scfg.get("command", "")),
                    "disabled": scfg.get("disabled", False),
                })
        except Exception:
            pass

    return {
        "projects": projects,
        "userSettings": user_settings,
        "plugins": plugins,
        "appStorage": app_storage_summary,
        "conversations": conversations,
        "mcpServers": mcp_servers,
        "paths": {
            "configJson": sanitize_local_path(AGY_CONFIG_JSON),
            "appStorageJson": sanitize_local_path(AGY_APP_STORAGE_JSON),
            "projectsDir": sanitize_local_path(AGY_PROJECTS_DIR),
            "conversationsDb": sanitize_local_path(AGY_CONV_DB),
            "statePbtxt": sanitize_local_path(AGY_STATE_PBTXT),
        },
    }


def create_snapshot(label: str = "Manual Snapshot", tag: str = "user") -> dict:
    """Create a complete backup snapshot of all Antigravity settings, projects, layouts, and state."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    snap_id = f"snap_{ts}_{secrets.token_hex(3)}"
    snap_dir = SNAPSHOTS_DIR / snap_id
    snap_dir.mkdir(parents=True, exist_ok=True)

    files_copied = []
    for src, rel_name in [
        (AGY_CONFIG_JSON, "config.json"),
        (AGY_MCP_JSON, "mcp_config.json"),
        (AGY_APP_STORAGE_JSON, "app_storage.json"),
        (AGY_STATE_PBTXT, "antigravity_state.pbtxt"),
    ]:
        if src.exists():
            shutil.copy2(src, snap_dir / rel_name)
            files_copied.append(rel_name)

    if AGY_PROJECTS_DIR.exists():
        proj_dst = snap_dir / "projects"
        shutil.copytree(AGY_PROJECTS_DIR, proj_dst, dirs_exist_ok=True)
        files_copied.append(f"projects ({len(list(proj_dst.glob('*.json')))} workspaces)")

    meta = {
        "id": snap_id,
        "label": label,
        "tag": tag,
        "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "files": files_copied,
    }
    (snap_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def list_snapshots() -> list[dict]:
    """Return all saved workspace/settings snapshots sorted newest first."""
    snaps = []
    if not SNAPSHOTS_DIR.exists():
        return snaps
    for sdir in sorted(SNAPSHOTS_DIR.iterdir(), reverse=True):
        mfile = sdir / "metadata.json"
        if mfile.exists():
            try:
                snaps.append(json.loads(mfile.read_text(encoding="utf-8")))
            except Exception:
                continue
    return snaps


def restore_snapshot(snap_id: str, preserve_login_email: str | None = None) -> bool:
    """Restore a saved snapshot back into live Antigravity directories without losing active login."""
    snap_dir = SNAPSHOTS_DIR / snap_id
    if not snap_dir.exists():
        return False

    if (snap_dir / "config.json").exists():
        AGY_CONFIG_JSON.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(snap_dir / "config.json", AGY_CONFIG_JSON)

    if (snap_dir / "mcp_config.json").exists():
        shutil.copy2(snap_dir / "mcp_config.json", AGY_MCP_JSON)

    if (snap_dir / "antigravity_state.pbtxt").exists():
        shutil.copy2(snap_dir / "antigravity_state.pbtxt", AGY_STATE_PBTXT)

    if (snap_dir / "projects").exists():
        AGY_PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
        for pfile in (snap_dir / "projects").glob("*.json"):
            shutil.copy2(pfile, AGY_PROJECTS_DIR / pfile.name)

    if (snap_dir / "app_storage.json").exists():
        try:
            ast = json.loads((snap_dir / "app_storage.json").read_text(encoding="utf-8"))
            if preserve_login_email:
                ast["jetski.onboarding.lastLoginUsername"] = preserve_login_email
                ast["ide-install-wizard-shown"] = "true"
            AGY_APP_STORAGE_JSON.write_text(json.dumps(ast, indent=2), encoding="utf-8")
        except Exception:
            shutil.copy2(snap_dir / "app_storage.json", AGY_APP_STORAGE_JSON)

    return True


# ---------------------------------------------------------------------------
# Account Hub State & Hot-Swap Engine
# ---------------------------------------------------------------------------
class AccountHub:
    def __init__(self):
        self.lock = threading.RLock()
        self.accounts: list[dict] = []
        self.settings: dict = {
            "pinWorkspacesOnSwitch": True,
            "autoSnapshotBeforeSwitch": True,
            "hotReloadLanguageServer": True,
            "autoRefreshIntervalSec": 120,
        }
        self.pending_oauth: dict = {}
        self._load()
        self.import_active_wincred_account()

    def _load(self):
        if SETTINGS_FILE.exists():
            try:
                self.settings.update(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
            except Exception as e:
                log_error("load_settings", e)
        loaded_accounts = None
        for candidate in (ACCOUNTS_FILE, ACCOUNTS_BACKUP_FILE):
            if candidate.exists():
                try:
                    raw = json.loads(candidate.read_text(encoding="utf-8"))
                    if isinstance(raw, list):
                        loaded_accounts = raw
                        break
                except Exception as e:
                    log_error(f"load_accounts({candidate.name})", e)
        if loaded_accounts is not None:
            self.accounts = loaded_accounts

    def save(self):
        with self.lock:
            try:
                _atomic_write_json(ACCOUNTS_FILE, self.accounts, backup_path=ACCOUNTS_BACKUP_FILE)
            except Exception as e:
                log_error("save_accounts", e)
            try:
                _atomic_write_json(SETTINGS_FILE, self.settings)
            except Exception as e:
                log_error("save_settings", e)

    def get_active_wincred_email(self) -> str | None:
        cred = wincred_read()
        if cred and cred.get("id_token_email"):
            return cred["id_token_email"]
        return None

    def import_active_wincred_account(self) -> dict | None:
        """Automatically import the currently logged-in Antigravity account from Windows Credential Manager."""
        cred = wincred_read()
        if not cred or "token" not in cred:
            return None
        email = cred.get("id_token_email", "").strip()
        tok = cred["token"]
        if not email and tok.get("access_token"):
            try:
                uinfo = fetch_google_userinfo(tok["access_token"])
                email = uinfo.get("email", "")
            except Exception:
                pass
        if not email:
            return None

        with self.lock:
            existing = next((a for a in self.accounts if a.get("email", "").lower() == email.lower()), None)
            if existing:
                existing["token"] = tok
                existing["auth_method"] = cred.get("auth_method", "consumer")
                self.save()
                return existing

            new_acc = {
                "id": f"acc_{secrets.token_hex(4)}",
                "email": email,
                "name": email.split("@")[0],
                "picture": "",
                "auth_method": cred.get("auth_method", "consumer"),
                "token": tok,
                "status": "Enabled",
                "plan_name": "Pro",
                "added_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "quota_windows": [],
                "models": [],
            }
            self.accounts.append(new_acc)
            self.save()
            # Ensure initial golden snapshot exists
            if not list_snapshots():
                create_snapshot("Initial Instance Baseline (Auto-Saved)", tag="baseline")
            return new_acc

    def refresh_all_accounts(self) -> list[dict]:
        """Poll live quota & model telemetry for all stored accounts in parallel."""
        active_email = self.get_active_wincred_email()
        ls_info = discover_language_server()
        threads = []

        def _worker(acc):
            try:
                poll_account_telemetry(acc, active_email=active_email, ls_info=ls_info)
            except Exception as e:
                acc["last_error"] = str(e)

        with self.lock:
            target_list = list(self.accounts)

        for acc in target_list:
            t = threading.Thread(target=_worker, args=(acc,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=12)

        self.save()
        return self.get_enriched_accounts()

    def get_enriched_accounts(self) -> list[dict]:
        active_email = (self.get_active_wincred_email() or "").lower()
        with self.lock:
            result = []
            for acc in self.accounts:
                c = dict(acc)
                # Strip raw tokens from frontend response for cleanliness, keep metadata
                tok = c.pop("token", {})
                c["hasRefreshToken"] = bool(tok.get("refresh_token"))
                c["tokenExpiry"] = tok.get("expiry", "")
                c["isActive"] = (c.get("email", "").lower() == active_email)
                result.append(c)
            return result

    def switch_to_account(self, account_id: str) -> dict:
        """
        Hot-swap the active Antigravity account without losing any workspace folders,
        open session tabs, conversation history, or settings.
        """
        with self.lock:
            target = next((a for a in self.accounts if a["id"] == account_id), None)
            if not target:
                raise ValueError(f"Account {account_id} not found")

            # 1. Auto-snapshot current workspace & session state if enabled
            if self.settings.get("autoSnapshotBeforeSwitch", True):
                create_snapshot(f"Auto-Save before switching to {target['email']}", tag="auto")

            # 2. Ensure fresh access token before writing to WinCred
            tok = target.get("token", {})
            if tok.get("refresh_token"):
                try:
                    fresh = refresh_google_token(tok["refresh_token"])
                    tok["access_token"] = fresh["access_token"]
                    tok["expiry"] = fresh["expiry"]
                    tok["expires_in"] = fresh["expires_in"]
                    target["token"] = tok
                except Exception:
                    pass

            # 3. Write credential payload to Windows Credential Manager (`gemini:antigravity`)
            wincred_payload = {
                "token": {
                    "access_token": tok["access_token"],
                    "token_type": tok.get("token_type", "Bearer"),
                    "refresh_token": tok["refresh_token"],
                    "expiry": tok["expiry"],
                    "expires_in": tok.get("expires_in", 3599),
                },
                "auth_method": target.get("auth_method", "consumer"),
                "id_token_email": target["email"],
            }
            if not wincred_write(wincred_payload):
                raise RuntimeError("Failed to write credential to Windows Credential Manager")

            # 4. Update app_storage.json `jetski.onboarding.lastLoginUsername` while preserving all layouts & sessions
            if AGY_APP_STORAGE_JSON.exists():
                try:
                    ast = json.loads(AGY_APP_STORAGE_JSON.read_text(encoding="utf-8"))
                    ast["jetski.onboarding.lastLoginUsername"] = target["email"]
                    ast["jetski.onboarding.lastLoginIsGcpTos"] = "false"
                    ast["ide-install-wizard-shown"] = "true"
                    AGY_APP_STORAGE_JSON.write_text(json.dumps(ast, indent=2), encoding="utf-8")
                except Exception:
                    pass

            self.save()

        # 5. If hotReloadLanguageServer is enabled, check if there is an active agent turn in this workspace;
        # we only restart language_server if requested by the operator via the API option.
        return {
            "switchedTo": target["email"],
            "accountId": target["id"],
            "wincredUpdated": True,
            "workspacesPreserved": True,
        }

    def remove_account(self, account_id: str) -> bool:
        with self.lock:
            before = len(self.accounts)
            self.accounts = [a for a in self.accounts if a["id"] != account_id]
            self.save()
            return len(self.accounts) < before

    def start_oauth_flow(self, callback_port: int) -> str:
        """Generate PKCE verifier/challenge and Google OAuth URL for adding a new account."""
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        state = secrets.token_urlsafe(24)
        redirect_uri = f"http://localhost:{callback_port}/auth/callback"

        with self.lock:
            self.pending_oauth[state] = {
                "verifier": verifier,
                "redirect_uri": redirect_uri,
                "created_at": time.time(),
                "status": "pending",
                "email": None,
                "error": None,
            }

        params = {
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(OAUTH_SCOPES),
            "access_type": "offline",
            "prompt": "select_account consent",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{OAUTH_AUTH_URL}?{urllib.parse.urlencode(params)}", state

    def complete_oauth_callback(self, state: str, code: str) -> dict:
        """Exchange authorization code for OAuth tokens, fetch user profile & quotas, and save account."""
        with self.lock:
            flow = self.pending_oauth.get(state)
            if not flow:
                raise ValueError("Invalid or expired OAuth state parameter")

        data = urllib.parse.urlencode({
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "code": code,
            "code_verifier": flow["verifier"],
            "grant_type": "authorization_code",
            "redirect_uri": flow["redirect_uri"],
        }).encode("utf-8")

        req = urllib.request.Request(
            OAUTH_TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            tok_res = json.loads(resp.read().decode("utf-8"))

        expires_in = int(tok_res.get("expires_in", 3599))
        now_local = datetime.datetime.now(datetime.timezone.utc).astimezone()
        expiry_dt = now_local + datetime.timedelta(seconds=expires_in)

        access_token = tok_res["access_token"]
        refresh_token = tok_res.get("refresh_token", "")
        uinfo = fetch_google_userinfo(access_token)
        email = uinfo.get("email", "")
        if not email:
            raise RuntimeError("Google OAuth did not return an email address")

        token_obj = {
            "access_token": access_token,
            "token_type": tok_res.get("token_type", "Bearer"),
            "refresh_token": refresh_token,
            "expiry": expiry_dt.isoformat(),
            "expires_in": expires_in,
        }

        with self.lock:
            existing = next((a for a in self.accounts if a.get("email", "").lower() == email.lower()), None)
            if existing:
                if not refresh_token and existing.get("token", {}).get("refresh_token"):
                    token_obj["refresh_token"] = existing["token"]["refresh_token"]
                existing["token"] = token_obj
                existing["name"] = uinfo.get("name", existing.get("name", ""))
                existing["picture"] = uinfo.get("picture", existing.get("picture", ""))
                existing["status"] = "Enabled"
                acc = existing
            else:
                acc = {
                    "id": f"acc_{secrets.token_hex(4)}",
                    "email": email,
                    "name": uinfo.get("name", email.split("@")[0]),
                    "picture": uinfo.get("picture", ""),
                    "auth_method": "consumer",
                    "token": token_obj,
                    "status": "Enabled",
                    "plan_name": "Pro",
                    "added_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "quota_windows": [],
                    "models": [],
                }
                self.accounts.append(acc)

            flow["status"] = "completed"
            flow["email"] = email
            self.save()

        # Poll telemetry immediately for the newly connected account
        try:
            poll_account_telemetry(acc, active_email=self.get_active_wincred_email())
            self.save()
        except Exception:
            pass

        return acc


HUB = AccountHub()


# ---------------------------------------------------------------------------
# HTTP API & OAuth Callback Server
# ---------------------------------------------------------------------------
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class HubRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Keep console clean

    def _send_json(self, data: dict | list, status: int = 200):
        try:
            raw = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as e:
            log_error("_send_json", e)

    def _send_html(self, html: str, status: int = 200):
        try:
            raw = html.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as e:
            log_error("_send_html", e)

    def _read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
        except Exception as e:
            log_error("_read_json_body", e)
            return {}

    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)

            if path == "/" or path == "/index.html":
                index_file = STATIC_DIR / "index.html"
                if index_file.exists():
                    self._send_html(index_file.read_text(encoding="utf-8"))
                else:
                    self._send_html("<h1>UI file missing</h1>", 404)
                return

            if path == "/auth/callback":
                state = qs.get("state", [""])[0]
                code = qs.get("code", [""])[0]
                err = qs.get("error", [""])[0]
                if err or not code:
                    self._send_html(self._render_oauth_result(False, f"Google OAuth returned: {err or 'No code'}"), 400)
                    return
                try:
                    acc = HUB.complete_oauth_callback(state, code)
                    self._send_html(self._render_oauth_result(True, acc["email"], acc.get("name", ""), acc.get("plan_name", "Pro")))
                except Exception as e:
                    err_str = format_http_error(e)
                    log_error("oauth_callback", err_str)
                    self._send_html(self._render_oauth_result(False, err_str), 500)
                return

            if path == "/api/state":
                ls_info = discover_language_server()
                self._send_json({
                    "accounts": HUB.get_enriched_accounts(),
                    "activeEmail": HUB.get_active_wincred_email(),
                    "languageServer": {
                        "running": bool(ls_info),
                        "pid": ls_info["pid"] if ls_info else None,
                        "ports": ls_info["ports"] if ls_info else [],
                    },
                    "instance": get_instance_state(),
                    "snapshots": list_snapshots(),
                    "settings": HUB.settings,
                })
                return

            if path == "/api/oauth/status":
                state = qs.get("state", [""])[0]
                flow = HUB.pending_oauth.get(state, {})
                self._send_json({
                    "status": flow.get("status", "unknown"),
                    "email": flow.get("email"),
                    "error": flow.get("error"),
                })
                return

            self._send_json({"error": "Not found"}, 404)
        except Exception as e:
            err_str = format_http_error(e)
            log_error(f"do_GET({self.path})", err_str)
            self._send_json({"ok": False, "error": err_str}, 500)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        try:
            if path == "/api/accounts/refresh":
                acc_id = body.get("accountId")
                if acc_id:
                    with HUB.lock:
                        target = next((a for a in HUB.accounts if a["id"] == acc_id), None)
                    if not target:
                        self._send_json({"ok": False, "error": f"Account {acc_id} not found"}, 404)
                        return
                    poll_account_telemetry(
                        target,
                        active_email=HUB.get_active_wincred_email(),
                        ls_info=discover_language_server(),
                    )
                    HUB.save()
                    accounts = HUB.get_enriched_accounts()
                else:
                    accounts = HUB.refresh_all_accounts()
                self._send_json({"ok": True, "accounts": accounts, "activeEmail": HUB.get_active_wincred_email()})
                return

            if path == "/api/accounts/add-oauth":
                server_port = self.server.server_address[1]
                auth_url, state = HUB.start_oauth_flow(server_port)
                if body.get("openBrowser", True):
                    try:
                        webbrowser.open(auth_url)
                    except Exception as e:
                        log_error("webbrowser_open", e)
                self._send_json({"ok": True, "authUrl": auth_url, "state": state})
                return

            if path == "/api/accounts/import-token":
                refresh_tok = body.get("refreshToken", "").strip()
                if not refresh_tok:
                    self._send_json({"ok": False, "error": "Refresh token is required"}, 400)
                    return
                new_tok = refresh_google_token(refresh_tok)
                uinfo = fetch_google_userinfo(new_tok["access_token"])
                email = uinfo.get("email", "")
                with HUB.lock:
                    existing = next((a for a in HUB.accounts if a.get("email", "").lower() == email.lower()), None)
                    if existing:
                        existing["token"] = new_tok
                        existing["name"] = uinfo.get("name", existing.get("name", ""))
                        existing["picture"] = uinfo.get("picture", "")
                        acc = existing
                    else:
                        acc = {
                            "id": f"acc_{secrets.token_hex(4)}",
                            "email": email,
                            "name": uinfo.get("name", email.split("@")[0]),
                            "picture": uinfo.get("picture", ""),
                            "auth_method": "consumer",
                            "token": new_tok,
                            "status": "Enabled",
                            "plan_name": "Pro",
                            "added_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "quota_windows": [],
                            "models": [],
                        }
                        HUB.accounts.append(acc)
                    HUB.save()
                poll_account_telemetry(acc, active_email=HUB.get_active_wincred_email())
                HUB.save()
                self._send_json({"ok": True, "accounts": HUB.get_enriched_accounts()})
                return

            if path == "/api/accounts/switch":
                acc_id = body.get("accountId", "")
                res = HUB.switch_to_account(acc_id)
                if body.get("reloadLanguageServer", False):
                    ls_info = discover_language_server(force_refresh=True)
                    if ls_info and ls_info.get("pid"):
                        # Electron main process automatically respawns language_server.exe within 2s!
                        _ctypes_terminate_pid(ls_info["pid"])
                        invalidate_ls_cache()
                        res["languageServerRestarted"] = True
                self._send_json({"ok": True, **res, "accounts": HUB.get_enriched_accounts(), "activeEmail": HUB.get_active_wincred_email()})
                return

            if path == "/api/accounts/remove":
                acc_id = body.get("accountId", "")
                removed = HUB.remove_account(acc_id)
                self._send_json({"ok": removed, "accounts": HUB.get_enriched_accounts()})
                return

            if path == "/api/snapshots/create":
                label = body.get("label") or f"Snapshot {datetime.datetime.now().strftime('%b %d, %H:%M:%S')}"
                meta = create_snapshot(label=label, tag="manual")
                self._send_json({"ok": True, "snapshot": meta, "snapshots": list_snapshots()})
                return

            if path == "/api/snapshots/restore":
                snap_id = body.get("snapshotId", "")
                ok = restore_snapshot(snap_id, preserve_login_email=HUB.get_active_wincred_email())
                self._send_json({"ok": ok, "instance": get_instance_state(), "snapshots": list_snapshots()})
                return

            if path == "/api/settings/update":
                with HUB.lock:
                    for k in ("pinWorkspacesOnSwitch", "autoSnapshotBeforeSwitch", "hotReloadLanguageServer", "autoRefreshIntervalSec"):
                        if k in body:
                            HUB.settings[k] = body[k]
                    HUB.save()
                self._send_json({"ok": True, "settings": HUB.settings})
                return

            if path == "/api/antigravity/launch":
                if AGY_EXE_PATH.exists():
                    subprocess.Popen(
                        [str(AGY_EXE_PATH)],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        close_fds=True,
                    )
                    self._send_json({"ok": True})
                else:
                    self._send_json({"ok": False, "error": f"Executable not found at {AGY_EXE_PATH}"}, 404)
                return

            self._send_json({"ok": False, "error": "Unknown endpoint"}, 404)
        except Exception as e:
            err_str = format_http_error(e)
            log_error(f"do_POST({path})", err_str)
            self._send_json({"ok": False, "error": err_str}, 500)

    def _render_oauth_result(self, success: bool, title_or_email: str, name: str = "", plan: str = "") -> str:
        color = "#10b981" if success else "#ef4444"
        badge = "ACCOUNT CONNECTED & VERIFIED" if success else "AUTHENTICATION FAILED"
        sub = (
            f"Loaded <strong>{title_or_email}</strong> ({name or 'Google Account'}) · Plan: <strong>{plan}</strong>.<br>"
            "Model quotas and session vault synced. You can close this tab now."
            if success
            else f"Error: {title_or_email}"
        )
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Antigravity OAuth</title>
<style>
  body {{
    margin: 0; height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0a0a0c; color: #f4f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  .card {{
    background: #121216; border: 1px solid #26262e; border-radius: 14px; padding: 36px 42px;
    max-width: 440px; text-align: center; box-shadow: 0 24px 60px rgba(0,0,0,0.65);
  }}
  .pill {{
    display: inline-block; padding: 5px 12px; border-radius: 999px; font-size: 11px;
    font-weight: 700; letter-spacing: 0.08em; background: {color}22; color: {color};
    border: 1px solid {color}55; margin-bottom: 18px;
  }}
  h2 {{ margin: 0 0 10px; font-size: 20px; font-weight: 600; }}
  p {{ margin: 0; color: #9ca3af; font-size: 14px; line-height: 1.6; }}
</style>
</head>
<body>
  <div class="card">
    <div class="pill">{badge}</div>
    <h2>{"Antigravity Account Ready" if success else "OAuth Connection Error"}</h2>
    <p>{sub}</p>
  </div>
  <script>
    if ({'true' if success else 'false'}) {{
      setTimeout(() => {{ try {{ window.close(); }} catch(e) {{}} }}, 2200);
    }}
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Native Desktop Window Launcher (Normal Visibility — Never SW_HIDE)
# ---------------------------------------------------------------------------
def find_app_browser() -> str | None:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def launch_gui_window(url: str):
    """
    Open the GUI window with normal SW_SHOWNORMAL window visibility and without
    an isolated --user-data-dir lock folder so Edge/Chrome opens in <80ms and
    never freezes on a blank dark-gray compositor surface.
    """
    browser_exe = find_app_browser()
    if browser_exe:
        try:
            subprocess.Popen(
                [
                    browser_exe,
                    f"--app={url}",
                    "--window-size=1320,860",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            return
        except Exception as e:
            log_error("launch_gui_window_app", e)
    try:
        webbrowser.open(url)
    except Exception as e:
        log_error("launch_gui_window_fallback", e)


def _is_hub_http_healthy(port: int) -> bool:
    """Verify the existing server on 127.0.0.1:port actually responds to HTTP GET."""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/index.html", method="GET")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def main():
    port = HUB_PORT
    url = f"http://127.0.0.1:{port}/"

    # Check if port is already bound and healthy
    if _is_port_alive(port):
        if _is_hub_http_healthy(port):
            if "--no-window" not in sys.argv:
                launch_gui_window(url)
            return
        else:
            # Stale/hung process holding port — terminate it via ctypes and take over
            for pid in range(4, 262144, 4):
                pass
            try:
                size = wintypes.DWORD(0)
                _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 3, 0)
                buf = (ctypes.c_ubyte * size.value)()
                if _iphlpapi.GetExtendedTcpTable(ctypes.byref(buf), ctypes.byref(size), False, 2, 3, 0) == 0:
                    num = struct.unpack_from("<I", buf, 0)[0]
                    off = 4
                    for _ in range(num):
                        _st, _la, lp, _ra, _rp, opid = struct.unpack_from("<6I", buf, off)
                        off += 24
                        if socket.ntohs(lp & 0xFFFF) == port and opid != os.getpid():
                            _ctypes_terminate_pid(opid)
                            time.sleep(0.3)
            except Exception as e:
                log_error("kill_stale_port_owner", e)

    # Initial background telemetry refresh
    threading.Thread(target=HUB.refresh_all_accounts, daemon=True).start()

    server = ThreadedHTTPServer(("127.0.0.1", port), HubRequestHandler)

    if "--no-window" not in sys.argv:
        launch_gui_window(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
