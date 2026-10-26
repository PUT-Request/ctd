# 🧊 ctd — native macOS shell containers

> **ctd is a semi-containerization layer for macOS.** Agent-ready: AI agents and other apps can spin up containers and work inside them over the CLI, HTTP, or stdio RPC.

> `sudo ctd base prepare` → `sudo ctd deploy -f box.yaml` → `ctd run box /bin/bash`

---

## ⚡ Features

| | |
|---|---|
| 🚀 **Startup** | milliseconds — no boot, no virtualization |
| 💾 **Disk** | ~13 MB base + **~1 MB per container** |
| 🔀 **Concurrency** | unlimited — every container gets its own isolated filesystem |
| 🔒 **Isolation** | chroot + Seatbelt write/network/signal scoping + rlimits + privdrop |
| 🌐 **Network** | off by default; `network.allow: true` → full TCP/UDP/DNS/TLS |
| 📂 **Path sharing** | `shares:` in YAML — `rw` / `ro` sync-at-exec-boundary |
| 📦 **Templates** | deploy containers from YAML, over CLI, HTTP or RPC |
| 🧰 **Bootstrapping** | install third-party apps from commands at deploy time |
| 🧱 **Firewall** | per-port outbound/inbound rules, default deny |
| 🤖 **Agent-ready** | agents work inside containers via CLI, HTTP, or stdio RPC |
| 🧪 **Self-testing** | `ctd audit` runs 14 live escape probes, exits 1 on failure |

---

## 🚀 Quickstart

```sh
go build -o ctd ./cmd/ctd && sudo cp ctd /usr/local/bin/

sudo ctd base prepare                # one-time (~13 MB)
sudo ctd create demo --ttl 1h        # ~1 MB, milliseconds
ctd run demo /bin/bash -c 'uname -a' # or: ctd shell demo
ctd exec --json demo /usr/bin/id     # captured, JSON out
sudo ctd audit demo                  # escape-probe suite
sudo ctd destroy demo
```

---

## 📦 YAML templates

```sh
ctd template new box.yaml        # documented example
ctd template validate box.yaml   # schema + toolset + SBPL checks
sudo ctd deploy -f box.yaml --name web \
     --set network.allow=true --set share=/src:/work:rw
ctd inspect web                  # state + effective spec
```

```yaml
name: web
ttl: 8h                     # seconds | "4h" | "never"
user: nobody                # dedicated 60000-range uid | root
workdir: /Users/me
home: /Users/me             # 🏠 private per-container home (default)
env: {APP_ENV: dev}
tools: [curl, grep]         # curated re-signed set
resources:                  # setrlimit before exec
  cpu_seconds: 1800
  fsize_bytes: 1073741824
  memory_bytes: 2147483648
  nproc: 256
writable:                   # Seatbelt write allow-list
  - /Users/me
  - /private/tmp
shares:                     # 📂 host ↔ container
  - host: ~/src
    container: /src
    mode: rw                # rw: synced back | ro: in only
network:
  allow: false              # 🌐 all sockets + DNS
firewall:                   # 🧱 rule-based network instead of network.allow
  dns: true                 # name resolution on
  allow_out:                # outbound, default deny
    - tcp:443
    - tcp:22
  allow_in:                 # bind/listen, default deny
    - tcp:8080
bootstrapping:              # 🧰 runs once at deploy, as root, in the container
  commands:
    - "curl -fsSL https://example.com/tool.tar.gz | tar xz -C /Users/me/.local"
  network: false            # temporary network for bootstrap only
  timeout: 300
share_process_list: false   # ps can't see host/other containers
seatbelt:
  extra_rules: ""           # raw SBPL escape hatch
```

---

## 🔌 APIs

**HTTP JSON** — `sudo ctd serve` (default `127.0.0.1:7399`), auth: `Bearer $(ctd token)`

| Method | Path | Body |
|---|---|---|
| GET | `/v1/ping` · `/v1/doctor` | — |
| GET/POST | `/v1/containers` | `{"name","ttl_seconds"}` or YAML deploy via `/v1/rpc` |
| GET/DELETE | `/v1/containers/{name}` | — |
| POST | `/v1/containers/{name}/exec` | `{"command":[…],"cwd","env","stdin","timeout_ms"}` |
| POST | `/v1/rpc` | `{"method":"container.deploy","params":{"yaml":"…"}}` |

```sh
curl -H "Authorization: Bearer $(sudo ctd token)" -H 'Content-Type: application/json' \
  -d '{"command":["/bin/bash","-c","echo hi | /usr/bin/wc -w"]}' \
  localhost:7399/v1/containers/web/exec
# {"ok":true,"result":{"stdout":"1\n","exit_code":0,"duration_ms":178}}
```

**stdio JSON-RPC** — `ctd rpc`, one JSON object per line:

```sh
echo '{"id":"1","method":"container.exec","params":{"container":"web","command":["/usr/bin/id"]}}' | ctd rpc
# {"id":"1","ok":true,"result":{"stdout":"uid=60001(nobody)…","exit_code":0}}
```

Methods: `ping` · `doctor` · `template.validate` · `container.deploy/create/list/inspect/destroy/exec/audit/gc`

---

## 🛡️ Isolation layers

Each layer independently verified by `ctd audit`:

| Layer | Stops | Verified |
|---|---|---|
| 🔑 chroot | reading any host path | `cat /Users/…` → ENOENT |
| ✍️ write allow-list | writes outside `writable:` | `/usr/bin` & `/etc` → BLOCKED |
| 🌐 network gate | all sockets incl. AF_UNIX | curl → exit 6 |
| 📡 same-sandbox signals | cross-container `kill` | DENIED ✅ |
| 👥 `kern.proc` deny | `ps` seeing host processes | `SCOPED` |
| 💿 raw-device denies | `/dev/rdisk*`, `bpf`, `io` | DENIED (even for `user: root`) |
| 📉 rlimits | cpu / fsize / nproc / nofile / mem | visible via `ulimit` |
| 🧷 privdrop | dedicated uid, not root | `uid=60001` |
| 🚫 nosuid/nodev | setuid escalation | mount flags |
| ⏳ TTL + gc + audit log | leftovers & forensic trail | `audit.jsonl` |

```text
sudo ctd audit web
  14/14 PASS ✅
```

---

## 🖥️ GUI apps

| Pattern | Status |
|---|---|
| 🌐 Web apps (`network.allow` + host browser on shared loopback) | ✅ |
| 🖱️ Native GUI on host ↔ container via exec / HTTP / RPC | ✅ design center |
| 📟 TUI (curses, vi, htop) | ✅ |
| 🎨 Headless render → file → view on host | ✅ |
| 🪟 Native AppKit `.app` inside container | ❌ needs WindowServer session + hardened-runtime bundle + TCC — VM only |

---

## 📂 Path sharing

Declare host paths in the template; ctd syncs them at every exec boundary:

- `mode: rw` — host → container before exec, container → host after
- `mode: ro` — host → container only
- The container's filesystem is also live-browsable from the host at `/opt/ctd/containers/<name>/root/`

---

## 🌐 Network & DNS

Default **off** (kernel-blocked). `network.allow: true` → everything on, `https://example.com` = **200** (DNS bridged, `resolv.conf` + CA bundle pre-seeded).

`firewall:` instead → per-port rules: only listed ports egress/bind, DNS optional via `firewall.dns`. Enforced live by `ctd audit` (allowed port reachable, unlisted port blocked).

---

## ⚠️ Limits

- Guardrail sandbox for your own code — for hostile code, use a VM.
- Only the curated toolset runs inside; extend `CuratedTools` + `base prepare --force`.
- Firewall filters by protocol/port only — no IP, CIDR, or port-range rules.

---

## 📁 Layout

```text
cmd/ctd/            CLI: doctor, base, create, deploy, template, run, exec,
                    shell, inspect, audit, ps, destroy, gc, serve, rpc
internal/core/      base prep · containers · seatbelt profiles · shares ·
                    DNS bridge · rlimits/privdrop · audit suite · templates
internal/api/       HTTP JSON + stdio JSON-RPC (shared command bus)
```
