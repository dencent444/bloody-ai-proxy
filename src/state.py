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
