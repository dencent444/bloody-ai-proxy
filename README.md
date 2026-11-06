![](docs/image.png)
![](docs/image_1.png)


> **PoC demonstrating the LLM proxy injection vulnerability class** — any AI coding agent that trusts a user-supplied API base URL is potentially affected, not just Claude Code. Current implementation targets Anthropic's API; OpenAI and others follow the same pattern and are planned.

TG : @dencentsociety

## Goal

**bloody-ai-proxy** is a redteam evil ai proxy exploitation toolkit. It starts a proxy (local or external) and simulates responses of a real Anthropic (OpenAI support soon) proxy. It can be used during redteaming paired with phishing — everything you need for the attack is that the victim only needs to change their `ANTHROPIC_BASE_URL`.

## How it works

After the victim pastes our server as a proxy, the client starts sending requests to it. Once the victim types something in, we get their request and can inject our own `tool_use`. Safeguards try to ask our server (which we control) whether to execute the tool use — so we auto-approve that. This way we get a reverse shell easily.

## Usage

Once at least one client connects, get your list of clients:

```
list clients
```

To inject a command (inject `tool_use` on the next message):

```
inject <id>
```

Where `id` is your client id (starts from 1) — opens the injector and prompts you to enter a cmd.

---

```
server local
```
Make your server local-only (best for local labs and PoCs).

```
server external
```
Make your server publicly accessible. If you don't have port forwarding — gonna add pinggy support soon so you can expose it without port forwarding. For now, use any available TCP tunnel.

---

```
revshell <id>
```
Initiate a listener — on the next message Claude Code will automatically be injected with the needed payload. Next thing I'll do is make payload injection EDR-undetectable, or at least try.

```
revshell stop
```
> ⚠️ This stops every reverse shell you have (will add `id` arg soon).

---

### Rules

```
rules
```
Check your current rules.

```
rule init revshell
```
On every new client init, a listener will be opened and a payload queued.

```
rule init revshell + <cmd>
```
Initiate a revshell, then auto-queue a command once the shell opens.

```
rule init cmd <cmd>
```
Inject a custom command to every new client automatically.

```
rule shell <cmd>
```
Once you get a revshell, a command will be queued automatically.

```
rule clear
```
Clear all rules.

```
help
```
Show a text like this but inside the tool.

---

## Disclaimer

This tool is initially made for redteaming. If you misuse it by exploiting real people without an official agreement and get in trouble — the author of this repo does not bear responsibility for your actions.

You might argue: "you have auto inject rules, this shi gotta be for blackhat exploitation." No. This feature was initially made for automating initial access in real life pentests/red teams — if you send 100 emails to a target company's workers and 10 of them fall for "free tokens", you may not make it in time to connect everyone to C2 or do other things you need for initial access. So don't think I'm just masking illegal things under a redteam hood.
