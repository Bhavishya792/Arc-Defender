"""
ARC Defender Python Middleware (FastAPI / Starlette / Flask)

Easily connect your Python web backend to your ARC Defender instance.
"""

import time
import json
import urllib.request
from typing import Optional, List, Callable

class ArcDefenderClient:
    def __init__(self, endpoint: str = "http://localhost:3000", ignore_paths: Optional[List[str]] = None):
        self.endpoint = endpoint.rstrip("/") + "/arc/api/v1/ingest"
        self.ignore_paths = ignore_paths or ["/health", "/docs", "/openapi.json", "/favicon.ico"]

    def should_ignore(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.ignore_paths)

    def record_event(
        self,
        ip: str,
        method: str,
        path: str,
        status_code: int,
        response_time_ms: float,
        user_agent: str = "",
        referer: str = "",
        request_size: int = 0,
        response_size: int = 0,
        is_login_attempt: bool = False,
        login_success: bool = False,
    ):
        if self.should_ignore(path):
            return

        payload = {
            "ip": ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            "response_time_ms": round(response_time_ms, 2),
            "user_agent": user_agent,
            "referer": referer,
            "request_size": request_size,
            "response_size": response_size,
            "is_login_attempt": is_login_attempt,
            "login_success": login_success,
        }

        try:
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Async / non-blocking fire-and-forget in production
            urllib.request.urlopen(req, timeout=1.0)
        except Exception as e:
            # Silent fallback so host app is never interrupted
            pass


# -------------------------------------------------------------
# FastAPI / Starlette Middleware Example
# -------------------------------------------------------------
def get_fastapi_middleware(arc_client: ArcDefenderClient):
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    class ArcFastAPIMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Callable):
            start = time.perf_counter()
            response = await call_next(request)
            elapsed_ms = (time.perf_counter() - start) * 1000

            client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            if not client_ip and request.client:
                client_ip = request.client.host
            if not client_ip:
                client_ip = "127.0.0.1"

            arc_client.record_event(
                ip=client_ip,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                response_time_ms=elapsed_ms,
                user_agent=request.headers.get("user-agent", ""),
                referer=request.headers.get("referer", ""),
            )
            return response

    return ArcFastAPIMiddleware
