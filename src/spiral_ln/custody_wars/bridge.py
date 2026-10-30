"""Webhook bridge: receives the harness's signed decision requests and answers
them with a local policy, a local ``codex exec`` call, or an OpenAI-compatible
upstream (They Sing's ``playtest:codex-bridge`` pattern, same env-var style).

Environment (all optional):

    CSA_BRIDGE_MODE            policy | codex | openai          (default policy)
    CSA_BRIDGE_HOST / _PORT    bind address                     (127.0.0.1:8789)
    CSA_BRIDGE_SECRET          HMAC secret; when set, unsigned or stale requests get 401
    CSA_BRIDGE_TIMEOUT_MS      upstream timeout                 (600000)
    CSA_BRIDGE_LOCAL_FALLBACK  1 = answer with the policy on upstream failure (They Sing
                               behaviour); default 0 = return 502 so the harness counts
                               the fallback itself
    CSA_BRIDGE_CODEX_MODEL     model for codex mode
    CSA_BRIDGE_OPENAI_BASE_URL e.g. http://127.0.0.1:8000/v1 (your local Codex/OpenAI bridge)
    CSA_BRIDGE_OPENAI_MODEL    e.g. gpt-5.2-codex
    CSA_BRIDGE_OPENAI_API_KEY  bearer key, if the upstream needs one (never logged)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .codex_runner import SYSTEM_BRIEF, codex_decide
from .policies import decide
from .session import verify_signature

MODES = ("policy", "codex", "openai")


def policy_decision(request: dict[str, Any]) -> dict[str, Any]:
    return decide(request["observation"], request["phase"], "default")


def openai_decision(request: dict[str, Any], cfg: dict[str, Any]) -> Any:
    base = cfg["openai_base_url"].rstrip("/")
    schema = dict(request["response_schema"])
    schema.pop("$schema", None)
    payload = {
        "model": cfg["openai_model"],
        "messages": [
            {"role": "system", "content": SYSTEM_BRIEF},
            {"role": "user", "content": json.dumps({k: request[k] for k in ("seat", "phase", "turn", "max_turns",
                                                                             "instructions", "observation")})},
        ],
        "response_format": {"type": "json_schema", "json_schema": {"name": "decision", "schema": schema, "strict": True}},
    }
    headers = {"content-type": "application/json"}
    if cfg.get("openai_api_key"):
        headers["authorization"] = f"Bearer {cfg['openai_api_key']}"
    req = urllib.request.Request(base + "/chat/completions", data=json.dumps(payload).encode(), headers=headers,
                                 method="POST")
    with urllib.request.urlopen(req, timeout=cfg["timeout_s"]) as resp:  # noqa: S310 - operator-configured URL
        body = json.loads(resp.read().decode("utf-8"))
    return json.loads(body["choices"][0]["message"]["content"])


def config_from_env(**overrides: Any) -> dict[str, Any]:
    env = os.environ
    cfg = {
        "mode": env.get("CSA_BRIDGE_MODE", "policy"),
        "host": env.get("CSA_BRIDGE_HOST", "127.0.0.1"),
        "port": int(env.get("CSA_BRIDGE_PORT", "8789")),
        "secret": env.get("CSA_BRIDGE_SECRET") or None,
        "timeout_s": int(env.get("CSA_BRIDGE_TIMEOUT_MS", "600000")) / 1000,
        "local_fallback": env.get("CSA_BRIDGE_LOCAL_FALLBACK", "0") == "1",
        "codex_model": env.get("CSA_BRIDGE_CODEX_MODEL") or None,
        "openai_base_url": env.get("CSA_BRIDGE_OPENAI_BASE_URL", "http://127.0.0.1:8000/v1"),
        "openai_model": env.get("CSA_BRIDGE_OPENAI_MODEL", "gpt-5.2-codex"),
        "openai_api_key": env.get("CSA_BRIDGE_OPENAI_API_KEY") or None,
    }
    cfg.update({k: v for k, v in overrides.items() if v is not None})
    if cfg["mode"] not in MODES:
        raise ValueError(f"CSA_BRIDGE_MODE must be one of {MODES}")
    return cfg


def answer(request: dict[str, Any], cfg: dict[str, Any]) -> Any:
    mode = cfg["mode"]
    if mode == "policy":
        return policy_decision(request)
    try:
        if mode == "codex":
            return codex_decide(request, model=cfg.get("codex_model"), timeout_s=cfg["timeout_s"])
        return openai_decision(request, cfg)
    except Exception:
        if cfg.get("local_fallback"):
            d = policy_decision(request)
            d["reasoning"] = f"bridge fell back to local policy ({mode} upstream failed)"
            return d
        raise


def make_bridge(cfg: dict[str, Any]) -> ThreadingHTTPServer:
    cache: dict[str, Any] = {}          # request_id -> decision (signed request ids cannot be forged)
    cache_lock = threading.Lock()

    class BridgeHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("[csa-bridge] " + (fmt % args) + "\n")

        def _send(self, code: int, payload: Any) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._send(200, {"ok": True, "mode": cfg["mode"], "signed": bool(cfg.get("secret"))})

        def do_POST(self) -> None:  # noqa: N802
            try:
                length = int(self.headers.get("content-length") or 0)
            except ValueError:
                return self._send(400, {"error": "invalid content-length"})
            if length < 0 or length > 4 * 1024 * 1024:
                return self._send(413, {"error": "request too large"})
            raw = self.rfile.read(length)
            if cfg.get("secret") and not verify_signature(cfg["secret"], self.headers.get("x-csa-timestamp", ""), raw,
                                                         self.headers.get("x-csa-signature", "")):
                return self._send(401, {"error": "bad or missing x-csa-signature"})
            try:
                request = json.loads(raw.decode("utf-8"))
                rid = str(request.get("request_id", ""))
                with cache_lock:
                    if rid and rid in cache:
                        # a replayed or retried delivery gets the same answer, without re-running the model
                        return self._send(200, cache[rid])
                decision = answer(request, cfg)
                with cache_lock:
                    if rid:
                        cache[rid] = decision
                        while len(cache) > 2048:
                            cache.pop(next(iter(cache)))
                return self._send(200, decision)
            except Exception as exc:  # noqa: BLE001
                return self._send(502, {"error": f"{type(exc).__name__}: {exc}"[:400]})

    return ThreadingHTTPServer((cfg["host"], cfg["port"]), BridgeHandler)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Custody Wars webhook bridge")
    ap.add_argument("--mode", choices=MODES)
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    args = ap.parse_args(argv)
    cfg = config_from_env(mode=args.mode, host=args.host, port=args.port)
    httpd = make_bridge(cfg)
    print(f"Custody Wars bridge ({cfg['mode']}) on http://{cfg['host']}:{cfg['port']}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
