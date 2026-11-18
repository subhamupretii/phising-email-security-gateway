"""Master launcher for the Phishing Email Security Gateway platform (Windows).

This script starts the platform services concurrently using ``subprocess.Popen``:

1. ``services/gateway/app.py``   – Threat gateway (SMTP server, port 1025)
2. ``services/dashboard/app.py`` – Flask audit dashboard
3. ``services/webmail/app.py``   – Unified webmail (UI port 8000, inbox SMTP port 1026)

The separate sender (8001) and receiver (8002) simulators are left in the tree for
their tests. They are not launched here because webmail owns the gateway's relay
port 1026.

It forwards ``KeyboardInterrupt`` (Ctrl+C) to shut down all child processes cleanly.

Usage::

    python -m pip install -r requirements.txt  # install deps
    python start_platform.py                    # launch all services

The script assumes it is executed from the project root (the directory containing
``services/``). It uses the current Python interpreter (``sys.executable``) so the
virtual‑environment activation is respected.
"""

import subprocess
import sys
import signal
import time
from pathlib import Path

# Define the services and their entry‑point modules
SERVICES = [
    ("Gateway", "services.gateway.app"),
    ("Dashboard", "services.dashboard.app"),
    ("Webmail", "services.webmail.app"),
]

def launch_service(name: str, module: str) -> subprocess.Popen:
    """Launch a service via ``python -m <module>``.

    Args:
        name: Human readable service name (used for logging).
        module: Dotted module path to execute.
    Returns:
        The ``subprocess.Popen`` object representing the child process.
    """
    cmd = [sys.executable, "-m", module]
    # ``creationflags`` ensures a new process group on Windows, making termination easier.
    creationflags = 0
    if sys.platform.startswith("win"):
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    print(f"Starting {name}: {' '.join(cmd)}")
    return subprocess.Popen(
        cmd,
        cwd=Path(__file__).parent,
        creationflags=creationflags,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

def main() -> None:
    processes = []
    try:
        # Launch each service
        for name, module in SERVICES:
            proc = launch_service(name, module)
            processes.append((name, proc))

        # Simple monitoring loop – forward output of each child to the console.
        while True:
            for name, proc in processes:
                # Non‑blocking read of any available line
                line = proc.stdout.readline()
                if line:
                    print(f"[{name}] {line.rstrip()}")
            # If any process has exited unexpectedly, break out.
            if any(proc.poll() is not None for _, proc in processes):
                print("One of the services exited. Shutting down remaining processes.")
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received – terminating services…")
    finally:
        # Terminate all child processes gracefully
        for name, proc in processes:
            if proc.poll() is None:
                try:
                    if sys.platform.startswith("win"):
                        # ``CTRL_BREAK_EVENT`` works for a process group on Windows
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        proc.terminate()
                    # Give the process a moment to clean up
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                print(f"{name} stopped.")

if __name__ == "__main__":
    main()
