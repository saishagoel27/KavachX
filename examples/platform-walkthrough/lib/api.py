"""Standard-library client for the KavachX API.

No third-party HTTP dependency, so the walkthrough runs against a checked-out repository with
nothing installed but Python itself. Every call returns exactly what the server sent; this module
never fills in a default for a value the server did not provide.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any


class ApiError(RuntimeError):
    def __init__(self, method: str, path: str, status: int, body: str) -> None:
        self.method = method
        self.path = path
        self.status = status
        self.body = body
        super().__init__(f"{method} {path} -> HTTP {status}\n{body}")


class Unreachable(RuntimeError):
    pass


class Api:
    """Thin JSON client. ``token`` is set once by :meth:`login`."""

    def __init__(self, base: str, *, timeout: int = 60) -> None:
        self.base = base.rstrip("/")
        self.token = ""
        self.timeout = timeout

    # -- transport ---------------------------------------------------------
    def _call(self, method: str, path: str, body: dict | None = None) -> Any:
        url = f"{self.base}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("content-type", "application/json")
        request.add_header("accept", "application/json")
        if self.token:
            request.add_header("authorization", f"Bearer {self.token}")
        try:
            # The operator's own API base, passed on the command line.
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            raise ApiError(method, path, exc.code, exc.read().decode("utf-8")[:1200]) from exc
        except urllib.error.URLError as exc:
            raise Unreachable(f"could not reach {url}: {exc.reason}") from exc

    def get(self, path: str, **params: Any) -> Any:
        if params:
            path = f"{path}?{urllib.parse.urlencode(params)}"
        return self._call("GET", path)

    def post(self, path: str, body: dict | None = None) -> Any:
        return self._call("POST", path, body or {})

    def get_raw(self, path: str) -> bytes:
        """Fetch a non-JSON body (certificate download)."""
        request = urllib.request.Request(f"{self.base}{path}", method="GET")
        if self.token:
            request.add_header("authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            raise ApiError("GET", path, exc.code, exc.read().decode("utf-8")[:1200]) from exc
        except urllib.error.URLError as exc:
            raise Unreachable(f"could not reach {self.base}{path}: {exc.reason}") from exc

    # -- auth --------------------------------------------------------------
    def login(self, email: str, password: str) -> dict:
        payload = self.post("/api/auth/login", {"email": email, "password": password})
        self.token = payload["access_token"]
        return self.get("/api/auth/me")

    # -- run following -----------------------------------------------------
    def follow(
        self,
        run_id: str,
        *,
        on_event: Callable[[dict], None],
        terminal: set[str],
        timeout_s: int,
        poll_s: float = 1.5,
    ) -> dict:
        """Replay and tail a run's event history until the run reaches a terminal status.

        Uses ``/events/history``, which is the durable, replayable record behind the console's
        live stream — so this prints exactly what the console shows, in the same order, and a
        slow poll can never miss an event.
        """
        after = 0
        deadline = time.time() + timeout_s
        detail: dict = {}
        while time.time() < deadline:
            page = self.get(f"/api/runs/{run_id}/events/history", after_seq=after, limit=500)
            for entry in page.get("events", []):
                after = max(after, int(entry["seq"]))
                on_event(entry["event"])
            detail = self.get(f"/api/runs/{run_id}")
            if detail.get("status") in terminal:
                # Drain everything emitted between the last page and the status read. Looping
                # matters: a busy phase can emit more events than one page holds, and the tail
                # of the run is exactly where the certificate and gauntlet events live.
                while True:
                    page = self.get(
                        f"/api/runs/{run_id}/events/history", after_seq=after, limit=500
                    )
                    entries = page.get("events", [])
                    if not entries:
                        return detail
                    for entry in entries:
                        after = max(after, int(entry["seq"]))
                        on_event(entry["event"])
            # A short breath while events are still flowing, a longer one while the run is
            # quiet — so following a run never becomes a tight poll loop against the API.
            time.sleep(0.25 if page.get("events") else poll_s)
        raise TimeoutError(
            f"run {run_id} did not reach a terminal status within {timeout_s}s "
            f"(last status: {detail.get('status', 'unknown')})"
        )
