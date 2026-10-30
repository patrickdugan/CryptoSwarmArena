"""Headless HTTP harness for Custody Wars (stdlib only).

Mirrors They Sing's headless harness (session REST endpoints + contracts) and
adds a pull mode so agents that can make HTTP calls but cannot host a webhook
(e.g. Codex agents using curl) can play a seat.

Auth: POST /sessions returns an ``admin_token`` and one ``seat_token`` per pull
seat. Seat-scoped reads and submissions require that seat's token (or the
admin token), so no seat can read another seat's fog-of-war view. Binds to
127.0.0.1 by default.

    GET  /health
    GET  /contract/agent-webhook | /contract/session-config | /contract/rules
    GET  /contract/decision-schema?phase=NEGOTIATION|ALLOCATION|ACTION_DECLARATION
    GET  /scenarios
    GET  /sessions                         public summaries
    POST /sessions                         create -> {summary, admin_token, seat_tokens}
    GET  /sessions/{id}                    public summary
    GET  /sessions/{id}/observation?seat=  seat token
    GET  /sessions/{id}/decision-request?seat=   seat token; 200 request | 204 nothing pending
    POST /sessions/{id}/decisions          seat token; {seat, request_id, decision}
    POST /sessions/{id}/step               admin; {force?}
    POST /sessions/{id}/advance            admin; step until a pull seat must decide
    POST /sessions/{id}/run                admin; {turns?, force?}
    GET  /sessions/{id}/replay             any session token; public events only
    GET  /sessions/{id}/referee            admin; sealed report
"""

from __future__ import annotations

import argparse
import hmac
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .content import (
    ARTIFACT_TYPES,
    ATTESTATION_TYPES,
    BIAS_CARDS,
    DAY_PHASES,
    DECISION_PHASES,
    DEFENSE_TECH,
    ENFORCEMENT_MODES,
    NODE_TYPES,
    ORDER_TYPES,
    PACT_TYPES,
    PHASES,
    RESOLUTION_STAGES,
    SCHEMA_VERSION,
    SEAT_PROFILES,
    SEATS,
    TECH_THRESHOLDS,
    UNIT_TYPES,
    VECTORS,
)
from .contract import response_schema, session_config_contract, webhook_contract
from .session import AwaitingDecisions, Session
from .world import list_scenarios

MAX_BODY = 1024 * 1024


def rules_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION + ".rules",
        "seats": SEAT_PROFILES, "phases": PHASES, "decision_phases": DECISION_PHASES,
        "resolution_stages": RESOLUTION_STAGES, "day_phases": DAY_PHASES, "vectors": VECTORS,
        "defense_tech": DEFENSE_TECH, "tech_thresholds": TECH_THRESHOLDS,
        "node_types": NODE_TYPES, "unit_types": UNIT_TYPES,
        "orders": {k: {kk: (list(vv) if isinstance(vv, tuple) else vv) for kk, vv in v.items()} for k, v in ORDER_TYPES.items()},
        "pacts": {k: {kk: (list(vv) if isinstance(vv, tuple) else vv) for kk, vv in v.items()} for k, v in PACT_TYPES.items()},
        "enforcement_modes": ENFORCEMENT_MODES, "artifacts": ARTIFACT_TYPES, "attestations": ATTESTATION_TYPES,
        "pretexts": BIAS_CARDS,
    }


class Registry:
    def __init__(self, auto_advance: bool = True) -> None:
        self.sessions: dict[str, Session] = {}
        self.locks: dict[str, threading.Lock] = {}
        self.auto_advance = auto_advance

    def create(self, config: dict[str, Any]) -> Session:
        session = Session(config)
        self.sessions[session.id] = session
        self.locks[session.id] = threading.Lock()
        return session

    def get(self, sid: str) -> Session:
        if sid not in self.sessions:
            raise LookupError(f"session {sid} not found")
        return self.sessions[sid]


class Handler(BaseHTTPRequestHandler):
    registry: Registry
    server_version = "CustodyWarsHarness/1"

    # ------------------------------------------------------------ plumbing

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter default logging
        sys.stderr.write("[csa] " + (fmt % args) + "\n")

    def _send(self, code: int, payload: Any = None) -> None:
        body = b"" if payload is None else json.dumps(payload, indent=2, sort_keys=True).encode()
        self.send_response(code)
        if payload is not None:
            self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length") or 0)
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length) if length else b""
        data = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(data, dict):
            raise ValueError("body must be a JSON object")
        return data

    def _token(self) -> str:
        auth = self.headers.get("authorization", "")
        return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

    def _require_admin(self, s: Session) -> None:
        if not hmac.compare_digest(self._token(), s.admin_token):
            raise PermissionError("admin token required")

    def _require_seat(self, s: Session, seat: str) -> None:
        tok = self._token()
        if hmac.compare_digest(tok, s.admin_token):
            return
        if seat not in s.seat_tokens or not hmac.compare_digest(tok, s.seat_tokens[seat]):
            raise PermissionError(f"seat token for {seat} required")

    def _require_any(self, s: Session) -> None:
        tok = self._token()
        if hmac.compare_digest(tok, s.admin_token) or any(hmac.compare_digest(tok, t) for t in s.seat_tokens.values()):
            return
        raise PermissionError("a session token is required")

    def _dispatch(self, method: str) -> None:
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        try:
            self._route(method, url.path.rstrip("/") or "/", q)
        except PermissionError as exc:
            self._send(401, {"error": str(exc)})
        except LookupError as exc:
            self._send(404, {"error": str(exc)})
        except AwaitingDecisions as exc:
            self._send(409, {"error": str(exc), "awaiting": exc.seats})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send(400, {"error": f"{type(exc).__name__}: {exc}"})
        except Exception as exc:  # noqa: BLE001
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    # -------------------------------------------------------------- routes

    def _route(self, method: str, path: str, q: dict[str, str]) -> None:
        reg = self.registry
        if method == "GET" and path == "/health":
            return self._send(200, {"ok": True, "sessions": len(reg.sessions), "schema": SCHEMA_VERSION})
        if method == "GET" and path == "/contract/agent-webhook":
            return self._send(200, webhook_contract())
        if method == "GET" and path == "/contract/session-config":
            return self._send(200, session_config_contract())
        if method == "GET" and path == "/contract/rules":
            return self._send(200, rules_contract())
        if method == "GET" and path == "/contract/decision-schema":
            return self._send(200, response_schema(q.get("phase", "")))
        if method == "GET" and path == "/scenarios":
            return self._send(200, {"scenarios": list_scenarios()})
        if path == "/sessions":
            if method == "GET":
                return self._send(200, {"sessions": [s.summary() for s in reg.sessions.values()]})
            if method == "POST":
                s = reg.create(self._body())
                return self._send(201, {"summary": s.summary(), "admin_token": s.admin_token,
                                        "seat_tokens": s.seat_tokens})
        m = re.fullmatch(r"/sessions/([\w-]+)(?:/([\w-]+))?", path)
        if not m:
            return self._send(404, {"error": f"unknown route {method} {path}"})
        s = reg.get(m.group(1))
        action = m.group(2)
        lock = reg.locks[s.id]
        if action is None and method == "GET":
            return self._send(200, s.summary())
        if action == "observation" and method == "GET":
            seat = q.get("seat", "")
            if seat not in SEATS:
                raise ValueError("seat query parameter required")
            self._require_seat(s, seat)
            with lock:
                return self._send(200, s.observation(seat))
        if action == "decision-request" and method == "GET":
            seat = q.get("seat", "")
            self._require_seat(s, seat)
            with lock:
                req = s.decision_request_for(seat)
            if req is None:
                return self._send(204)
            return self._send(200, req)
        if action == "decisions" and method == "POST":
            body = self._body()
            seat = str(body.get("seat", ""))
            self._require_seat(s, seat)
            with lock:
                result = s.submit(seat, str(body.get("request_id", "")), body.get("decision"))
            if reg.auto_advance and not result.get("awaiting"):
                threading.Thread(target=self._advance_bg, args=(s,), daemon=True).start()
            return self._send(200, result)
        if action in ("step", "advance", "run") and method == "POST":
            self._require_admin(s)
            body = self._body()
            with lock:
                if action == "step":
                    return self._send(200, s.step(force=bool(body.get("force"))))
                if action == "advance":
                    return self._send(200, s.advance())
                turns = body.get("turns")
                return self._send(200, s.run(int(turns) if turns else None, force=bool(body.get("force"))))
        if action == "replay" and method == "GET":
            self._require_any(s)
            return self._send(200, s.public_replay())
        if action == "referee" and method == "GET":
            self._require_admin(s)
            return self._send(200, s.referee_report())
        return self._send(404, {"error": f"unknown route {method} {path}"})

    def _advance_bg(self, s: Session) -> None:
        lock = self.registry.locks[s.id]
        with lock:
            s.advance()


def make_server(host: str = "127.0.0.1", port: int = 8788, auto_advance: bool = True) -> ThreadingHTTPServer:
    registry = Registry(auto_advance=auto_advance)
    handler = type("BoundHandler", (Handler,), {"registry": registry})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.registry = registry  # type: ignore[attr-defined]
    return httpd


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Custody Wars headless HTTP harness")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--config", help="optional session config JSON to preload")
    ap.add_argument("--no-auto-advance", action="store_true")
    args = ap.parse_args(argv)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: binding to {args.host}; session tokens are the only access control", file=sys.stderr)
    httpd = make_server(args.host, args.port, auto_advance=not args.no_auto_advance)
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            s = httpd.registry.create(json.load(fh))  # type: ignore[attr-defined]
        print(json.dumps({"session_id": s.id, "admin_token": s.admin_token, "seat_tokens": s.seat_tokens}))
    print(f"Custody Wars harness listening on http://{args.host}:{args.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
