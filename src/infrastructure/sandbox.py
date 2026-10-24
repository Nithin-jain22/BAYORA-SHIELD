"""Isolated execution sandbox for the client LLM.

Two backends are supported:

* **Docker** — strongest isolation (``--network none``, read-only root,
  dropped capabilities, memory/CPU/PID limits). Used automatically when a
  Docker daemon is reachable.
* **Process** — fallback for machines without Docker. Runs a dedicated
  ``ollama serve`` in its own process group on loopback port 11435 and reuses
  the host model store so the model is not downloaded twice.

The public API is intentionally small: ``start``, ``generate``, ``stop`` and a
``status`` snapshot used by the UI. No component talks to the model directly.
"""

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from ..config import (
    DOCKER_CONTAINER_NAME,
    DOCKER_IMAGE,
    MODEL,
    SANDBOX_DATA_DIR,
    SANDBOX_PORT,
)

logger = logging.getLogger(__name__)

SANDBOX_DATA_DIR.mkdir(parents=True, exist_ok=True)


class SandboxError(Exception):
    pass


_DOCKER_FALLBACK_PATHS = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "/Applications/Docker.app/Contents/Resources/bin/docker",
)


def docker_cli() -> str:
    """Locate the Docker CLI even when the app runs with a minimal ``PATH``.

    Docker Desktop installs its CLI shim outside the default ``PATH`` on macOS,
    so apps launched from a GUI or a service manager would otherwise report
    Docker as unavailable while the daemon is running.
    """
    found = shutil.which("docker")
    if found:
        return found
    for candidate in _DOCKER_FALLBACK_PATHS:
        if os.access(candidate, os.X_OK):
            return candidate
    return "docker"


def docker_available() -> tuple[bool, str]:
    """Return ``(available, message)`` without starting a container."""
    try:
        result = subprocess.run(
            [docker_cli(), "info"], capture_output=True, text=True, timeout=5
        )
    except FileNotFoundError:
        return False, "Docker CLI not installed"
    except subprocess.TimeoutExpired:
        return False, "Docker daemon did not respond"
    except OSError as exc:
        return False, f"Docker unavailable: {exc}"

    if result.returncode == 0:
        return True, "Docker daemon reachable"
    stderr = (result.stderr or "").strip().splitlines()
    detail = stderr[-1] if stderr else "daemon not running"
    return False, detail


def _port_is_live(port: int) -> bool:
    import requests

    try:
        resp = requests.get(f"http://127.0.0.1:{port}/api/tags", timeout=2)
        return resp.status_code == 200
    except requests.RequestException:
        return False


class DockerSandbox:
    """Docker-based sandbox — strongest isolation."""

    def __init__(self, model: str = MODEL):
        self.model = model
        self._container_id: Optional[str] = None

    def start(self):
        available, message = docker_available()
        if not available:
            raise SandboxError(message)

        subprocess.run(
            [docker_cli(), "rm", "-f", DOCKER_CONTAINER_NAME],
            capture_output=True,
            timeout=10,
        )

        host_models = Path.home() / ".ollama"
        model_mount = host_models if host_models.exists() else SANDBOX_DATA_DIR

        cmd = [
            docker_cli(), "run", "-d",
            "--name", DOCKER_CONTAINER_NAME,
            # Isolated bridge network with a single published loopback port.
            # Full egress denial requires host firewall rules and is listed as
            # future work in the project scope.
            "--network", "bridge",
            "--read-only",
            "--tmpfs", "/tmp",
            # qwen3:8b needs ~5 GB resident, so 4g was OOM-killing llama-server.
            "--memory", "6g",
            # CPU-only inference on 2 cores took minutes per reply; 6 keeps the
            # sandbox bounded while remaining usable for live demos.
            "--cpus", "6",
            "--pids-limit", "512",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{model_mount.resolve()}:/root/.ollama",
            "-p", f"127.0.0.1:{SANDBOX_PORT}:11434",
            DOCKER_IMAGE,
            # The image entrypoint is already /bin/ollama; the command must be
            # the subcommand alone, otherwise Docker runs `ollama ollama serve`.
            "serve",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise SandboxError(f"Failed to start container: {result.stderr}")

        self._container_id = result.stdout.strip()
        self._wait_for_ready()
        self._ensure_model()

    def _ensure_model(self):
        if _port_is_live(SANDBOX_PORT):
            import requests

            try:
                tags = requests.get(
                    f"http://127.0.0.1:{SANDBOX_PORT}/api/tags", timeout=5
                ).json()
                if any(self.model in m.get("name", "") for m in tags.get("models", [])):
                    return
            except (requests.RequestException, ValueError):
                pass
        subprocess.run(
            [docker_cli(), "exec", DOCKER_CONTAINER_NAME, "ollama", "pull", self.model],
            capture_output=True,
            timeout=600,
        )

    def _wait_for_ready(self, timeout: int = 90):
        start = time.time()
        while time.time() - start < timeout:
            if _port_is_live(SANDBOX_PORT):
                return
            time.sleep(1)
        raise SandboxError("Docker sandbox failed to become ready")

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        import requests

        payload = {
            "model": self.model,
            "messages": [],
            "stream": False,
            # qwen3's thinking mode can emit hundreds of tokens per reply, which
            # is unusable on CPU-only container inference.
            "think": False,
            # Keep the weights resident between attacks instead of reloading.
            "keep_alive": "30m",
            "options": {"temperature": 0.7},
        }
        if system_prompt:
            payload["messages"].append({"role": "system", "content": system_prompt})
        payload["messages"].append({"role": "user", "content": prompt})

        resp = requests.post(
            f"http://127.0.0.1:{SANDBOX_PORT}/api/chat", json=payload, timeout=300
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    def stop(self):
        if self._container_id:
            subprocess.run(
                [docker_cli(), "rm", "-f", DOCKER_CONTAINER_NAME],
                capture_output=True,
                timeout=15,
            )
            self._container_id = None

    @property
    def is_running(self) -> bool:
        return self._container_id is not None


class ProcessSandbox:
    """Process-level sandbox — fallback when Docker is unavailable."""

    def __init__(self, model: str = MODEL):
        self.model = model
        self._process: Optional[subprocess.Popen] = None
        self._external = False
        self._port = SANDBOX_PORT

    def start(self):
        if _port_is_live(self._port):
            logger.warning(
                "Port %s already serving a model; reusing the existing sandbox",
                self._port,
            )
            self._external = True
            self._ensure_model()
            return

        env = os.environ.copy()
        env["OLLAMA_HOST"] = f"127.0.0.1:{self._port}"
        models_dir = Path.home() / ".ollama" / "models"
        if models_dir.exists():
            env["OLLAMA_MODELS"] = str(models_dir)

        self._process = subprocess.Popen(
            ["ollama", "serve"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self._wait_for_ready()
        self._ensure_model()

    def _ensure_model(self):
        import requests

        try:
            tags = requests.get(
                f"http://127.0.0.1:{self._port}/api/tags", timeout=5
            ).json()
            if any(self.model in m.get("name", "") for m in tags.get("models", [])):
                logger.info("Model %s already available in sandbox", self.model)
                return
        except (requests.RequestException, ValueError):
            pass

        env = os.environ.copy()
        env["OLLAMA_HOST"] = f"127.0.0.1:{self._port}"
        models_dir = Path.home() / ".ollama" / "models"
        if models_dir.exists():
            env["OLLAMA_MODELS"] = str(models_dir)
        subprocess.run(
            ["ollama", "pull", self.model],
            env=env,
            capture_output=True,
            timeout=600,
        )

    def _wait_for_ready(self, timeout: int = 60):
        start = time.time()
        while time.time() - start < timeout:
            if _port_is_live(self._port):
                return
            time.sleep(0.5)
        raise SandboxError("Process sandbox failed to become ready")

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        import requests

        payload = {
            "model": self.model,
            "messages": [],
            "stream": False,
            "think": False,
            "keep_alive": "30m",
            "options": {"temperature": 0.7},
        }
        if system_prompt:
            payload["messages"].append({"role": "system", "content": system_prompt})
        payload["messages"].append({"role": "user", "content": prompt})

        resp = requests.post(
            f"http://127.0.0.1:{self._port}/api/chat", json=payload, timeout=300
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    def stop(self):
        if self._external:
            self._kill_port_owner()
            self._external = False
            return
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

    def _kill_port_owner(self):
        try:
            result = subprocess.run(
                ["lsof", "-ti", f"tcp:{self._port}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for pid in result.stdout.split():
                if pid.isdigit():
                    os.kill(int(pid), 15)
        except (OSError, subprocess.SubprocessError):
            logger.warning("Could not stop the external sandbox on port %s", self._port)

    @property
    def is_running(self) -> bool:
        if self._external:
            return _port_is_live(self._port)
        return self._process is not None and self._process.poll() is None


class SandboxManager:
    """Selects the best available backend and exposes a uniform API."""

    def __init__(self, model: str = MODEL):
        self.model = model
        self._sandbox: Optional[DockerSandbox | ProcessSandbox] = None
        self._backend: Optional[str] = None
        self._fallback_reason: Optional[str] = None

    def start(self):
        self._fallback_reason = None
        try:
            self._sandbox = DockerSandbox(self.model)
            self._sandbox.start()
            self._backend = "docker"
            logger.info("Sandbox started with Docker backend")
            return
        except SandboxError as exc:
            self._fallback_reason = str(exc)
            logger.warning("Docker sandbox unavailable (%s); using process backend", exc)

        self._sandbox = ProcessSandbox(self.model)
        self._sandbox.start()
        self._backend = "process"

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        if not self._sandbox:
            raise SandboxError("Sandbox not started")
        return self._sandbox.generate(prompt, system_prompt)

    def stop(self):
        if self._sandbox:
            self._sandbox.stop()
        self._sandbox = None
        self._backend = None

    @property
    def backend(self) -> Optional[str]:
        return self._backend

    @property
    def fallback_reason(self) -> Optional[str]:
        return self._fallback_reason

    @property
    def is_running(self) -> bool:
        return self._sandbox is not None and self._sandbox.is_running

    def status(self) -> dict:
        available, message = docker_available()
        return {
            "running": self.is_running,
            "backend": self._backend,
            "model": self.model,
            "port": SANDBOX_PORT,
            "docker_available": available,
            "docker_message": message,
            "fallback_reason": self._fallback_reason,
        }

    def quick_status(self) -> dict:
        """Cheap status snapshot that avoids a Docker daemon round-trip."""
        return {
            "running": self.is_running,
            "listening": _port_is_live(SANDBOX_PORT),
            "backend": self._backend,
            "model": self.model,
            "port": SANDBOX_PORT,
        }


_sandbox_manager: Optional[SandboxManager] = None


def get_sandbox() -> SandboxManager:
    global _sandbox_manager
    if _sandbox_manager is None:
        _sandbox_manager = SandboxManager()
    return _sandbox_manager


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    manager = SandboxManager()
    print(f"Starting sandbox with model: {manager.model}")
    manager.start()
    print(f"Status: {manager.status()}")
    print(manager.generate("Hello, what is 2+2?"))
    manager.stop()
