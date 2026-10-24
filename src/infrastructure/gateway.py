"""
gateway.py — Model Gateway

Sits between the application and the sandboxed LLM. Enforces:
  - Prompt size limits
  - Rate limiting per session
  - Prompt sanitization (strips control characters, null bytes)
  - Request/response logging to the security plane
  - Circuit breaker (stops sending to LLM if it's down)

All LLM traffic flows through here — no component talks to the LLM directly.
"""

import time
import re
import logging
from typing import Optional
from dataclasses import dataclass, field

from ..config import (
    CIRCUIT_BREAKER_THRESHOLD,
    CIRCUIT_BREAKER_TIMEOUT,
    MAX_PROMPT_LENGTH,
    MAX_RESPONSE_LENGTH,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW,
)
from .sandbox import get_sandbox
from .security_plane import EventType, log_event

logger = logging.getLogger(__name__)


@dataclass
class RateLimiter:
    requests: dict[str, list[float]] = field(default_factory=dict)

    def is_allowed(self, session_id: str) -> bool:
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW
        self.requests[session_id] = [
            t for t in self.requests.get(session_id, []) if t > window_start
        ]
        if len(self.requests[session_id]) >= RATE_LIMIT_REQUESTS:
            return False
        self.requests[session_id].append(now)
        return True


@dataclass
class CircuitBreaker:
    failures: int = 0
    last_failure: float = 0
    is_open: bool = False

    def record_success(self):
        self.failures = 0
        self.is_open = False

    def record_failure(self):
        self.failures += 1
        self.last_failure = time.time()
        if self.failures >= CIRCUIT_BREAKER_THRESHOLD:
            self.is_open = True

    def can_execute(self) -> bool:
        if not self.is_open:
            return True
        if time.time() - self.last_failure > CIRCUIT_BREAKER_TIMEOUT:
            self.is_open = False
            self.failures = 0
            return True
        return False


class ModelGateway:
    """
    Single entry point for all LLM interactions.
    Enforces security policies before forwarding to the sandbox.
    """

    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.circuit_breaker = CircuitBreaker()

    def query(
        self,
        prompt: str,
        system_prompt: str = "",
        session_id: str = "default",
        actor: str = "system",
    ) -> dict:
        """
        Send a prompt to the sandboxed LLM through the gateway.

        Returns:
            {
                "success": bool,
                "response": str,
                "error": Optional[str],
                "blocked": bool,
                "block_reason": Optional[str],
            }
        """
        sanitized = self._sanitize(prompt)
        if sanitized != prompt:
            log_event(
                EventType.VIOLATION_DETECTED,
                actor,
                {"reason": "prompt_contained_control_chars", "session_id": session_id},
                session_id,
            )

        if len(sanitized) > MAX_PROMPT_LENGTH:
            return {
                "success": False,
                "response": "",
                "error": f"Prompt exceeds maximum length of {MAX_PROMPT_LENGTH} characters",
                "blocked": True,
                "block_reason": "prompt_too_long",
            }

        if not self.rate_limiter.is_allowed(session_id):
            log_event(
                EventType.VIOLATION_DETECTED,
                actor,
                {"reason": "rate_limit_exceeded", "session_id": session_id},
                session_id,
            )
            return {
                "success": False,
                "response": "",
                "error": "Rate limit exceeded. Please wait before sending more requests.",
                "blocked": True,
                "block_reason": "rate_limit",
            }

        if not self.circuit_breaker.can_execute():
            return {
                "success": False,
                "response": "",
                "error": "LLM is temporarily unavailable. Please try again later.",
                "blocked": True,
                "block_reason": "circuit_breaker",
            }

        sandbox = get_sandbox()
        if not sandbox.is_running:
            return {
                "success": False,
                "response": "",
                "error": "LLM sandbox is not running.",
                "blocked": True,
                "block_reason": "sandbox_not_running",
            }

        try:
            response = sandbox.generate(sanitized, system_prompt)
            self.circuit_breaker.record_success()

            if len(response) > MAX_RESPONSE_LENGTH:
                response = response[:MAX_RESPONSE_LENGTH] + "... [truncated]"

            log_event(
                EventType.LLM_QUERY,
                actor,
                {
                    "session_id": session_id,
                    "prompt_hash": hash(sanitized) & 0xFFFFFFFF,
                    "response_hash": hash(response) & 0xFFFFFFFF,
                    "prompt_length": len(sanitized),
                    "response_length": len(response),
                },
                session_id,
            )

            return {
                "success": True,
                "response": response,
                "error": None,
                "blocked": False,
                "block_reason": None,
            }

        except Exception as e:
            self.circuit_breaker.record_failure()
            logger.error(f"LLM query failed: {e}")
            return {
                "success": False,
                "response": "",
                "error": f"LLM query failed: {str(e)}",
                "blocked": True,
                "block_reason": "llm_error",
            }

    def _sanitize(self, text: str) -> str:
        text = text.replace("\x00", "")
        text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f]", "", text)
        return text.strip()


_gateway: Optional[ModelGateway] = None


def get_gateway() -> ModelGateway:
    global _gateway
    if _gateway is None:
        _gateway = ModelGateway()
    return _gateway
