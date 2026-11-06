import os
import state

from rich.console import Console
from rich.panel import Panel

console = Console(highlight=False)

INJECTOR_BANNER = r"""
  ██▓ ███▄    █  ▄▄▄██▀▀▀▓█████  ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███
 ▓██▒ ██ ▀█   █    ▒██   ▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒
 ▒██▒▓██  ▀█ ██▒   ░██   ▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒
 ░██░▓██▒  ▐▌██▒▓██▄██▓  ▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄
 ░██░▒██░   ▓██░ ▓███▒   ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒
 ░▓  ░ ▒░   ▒ ▒  ▒▓▒▒░   ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░
  ▒ ░░ ░░   ░ ▒░ ▒ ░▒░    ░ ░  ░  ░  ▒       ░      ░ ▒ ▒░   ░▒ ░ ▒░
  ▒ ░   ░   ░ ░  ░ ░ ░      ░   ░          ░      ░ ░ ░ ▒    ░░   ░
  ░           ░  ░   ░      ░  ░░ ░                   ░ ░     ░
                                 ░
"""


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _print_header(client_id: str, client_ip: str):
    console.print(f"[bold red]{INJECTOR_BANNER}[/bold red]")
    gw     = state.clients[client_id]["gateway"]
    queued = f"[yellow]queued: {gw.command!r}[/yellow]" if gw.command else \
             f"[magenta]pending: {gw.pending_block['id']}[/magenta]" if gw.pending_block else \
             "[dim]idle[/dim]"
    console.print(Panel(
        f"[dim]target[/dim]  [bold cyan]#{client_id}[/bold cyan]  "
        f"[white]{client_ip}[/white]  {queued}",
        border_style="red", expand=False,
    ))


def run(client_id: str, client_ip: str):
    last = None

    while True:
        _clear()
        _print_header(client_id, client_ip)

        if last is not None:
            kind, text = last
            if kind == "ok":
                console.print(Panel(f"[green]{text}[/green]", border_style="green", expand=False))
            elif kind == "error":
                console.print(Panel(f"[red]{text}[/red]", border_style="red", expand=False))

        console.print("\n[dim]type a command to inject, or[/dim] [white]back[/white]\n")

        try:
            user_input = console.input("[bold red]inject>[/bold red] ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not user_input:
            last = None
            continue

        if user_input.lower() in ("back", "q", "exit"):
            break

        gw = state.clients[client_id]["gateway"]

        if user_input.lower() == "clear":
            gw.clear()
            last = ("ok", "queue cleared")
            continue

        gw.set_command(user_input)
        last = ("ok", f"injected → #{client_id}  will execute on next request")
