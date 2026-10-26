// ctd — native macOS shell containers.
//
// Two roles live in this binary:
//
//   - `ctd daemon`  — the privileged long-lived daemon: owns all container
//     state, serves the HTTP JSON API and the local control socket.
//   - everything else — a thin client that talks to the daemon over the
//     socket (sudo re-exec when needed). `ctd rpc` bridges stdio JSON-RPC
//     to the daemon socket.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"ctd/internal/api"
	"ctd/internal/core"
	"ctd/internal/daemon"
)

const usage = `ctd — native macOS shell containers (chroot + APFS CoW + Seatbelt)

The privileged daemon (` + "`sudo ctd daemon`" + `) owns all container state; every
other command is a client that talks to it. Keep the daemon terminal open.

usage: ctd <command> [args]

  daemon [--listen A] [--socket P]
                          run the daemon in the foreground (default
                          listen 127.0.0.1:7399, socket /opt/ctd/ctd.sock)
  doctor                     environment probes (JSON, via daemon)
  base prepare [--force]     build shared base shadow (once, idempotent)
  create <name> [--ttl N] [--set k=v ...]
                          create container (TTL seconds, 0=never, default 3600)
  ps                         list containers
  run <name> <cmd...>        run command (streamed, stdin forwarded)
  exec <name> <cmd...>       run command (captures stdout/stderr)
  exec --json <name> <cmd..> run command, print JSON result
  shell [name]               interactive shell (default container: default)
  deploy -f tpl.yaml         create from YAML template
                             [--name n] [--set network.allow=true]
  template new [file]        write an example template (local)
  template validate <file>   validate + show resolved spec (local)
  inspect <name>             container state + effective spec (JSON)
  audit <name>               live security probe suite (JSON, exit 1 on fail)
  bootstrap <name>           re-run template bootstrapping in a container
  once [-f t.yaml] [--rm] <cmd...>   one-shot: create if needed → run → optional cleanup
  destroy <name>             detach + delete container
  gc                         destroy expired containers
  rpc                        stdio JSON-RPC proxy to the daemon socket
  token                      print the API bearer token

HTTP API (served by the daemon; Authorization: Bearer <token>, or ?token=):
  GET    /v1/ping                     health
  GET    /v1/doctor                   probes
  POST   /v1/base/prepare             {"force":false}
  GET    /v1/containers               list
  POST   /v1/containers               {"name":"demo","ttl_seconds":3600}
  GET    /v1/containers/<name>        inspect
  DELETE /v1/containers/<name>        destroy
  POST   /v1/containers/<name>/exec   {"command":["/bin/ls","/"],"timeout_ms":5000}
  POST   /v1/rpc                      {"method":"container.list","params":{}}
  POST   /v1/gc

socket JSON-RPC (one JSON object per line, via ` + "`ctd rpc`" + `):
  > {"id":"1","method":"container.list","params":{}}
  < {"id":"1","ok":true,"result":{...}}
  methods: ping, doctor, base.prepare, container.create, container.deploy,
           container.list, container.inspect, container.destroy, container.gc,
           container.exec, container.once, container.bootstrap,
           container.audit, container.audit, template.validate

examples:
  sudo ctd daemon                    # terminal 1: daemon (keep open)
  sudo ctd base prepare              # terminal 2
  sudo ctd create demo --ttl 3600
  sudo ctd run demo /bin/bash -c 'echo hi | /usr/bin/wc -w'
  sudo ctd exec --json demo /usr/bin/uname -a
  curl -s -H "Authorization: Bearer $(sudo ctd token)" \
       -d '{"command":["/bin/ls","/"]}' localhost:7399/v1/containers/demo/exec
  echo '{"id":"1","method":"container.list"}' | sudo ctd rpc
`

// subcommands that need root (daemon socket is root-owned)
var privileged = map[string]bool{
	"daemon": true, "base": true, "create": true, "destroy": true, "gc": true,
	"deploy": true, "run": true, "exec": true, "shell": true, "token": true,
	"once": true, "audit": true, "inspect": true, "bootstrap": true,
	"doctor": true, "ps": true, "list": true, "rpc": true,
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	// internal stage, runs under sandbox-exec inside the daemon's exec
	if cmd == "__inner" {
		os.Exit(core.Inner(args))
	}

	// local commands: pure file ops, no daemon needed
	if cmd == "template" {
		os.Exit(cmdTemplate(args))
	}

	if privileged[cmd] && os.Geteuid() != 0 {
		relaunchViaSudo()
	}

	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "daemon":
		listen, socket := "127.0.0.1:7399", api.SocketPath
		for i := 0; i < len(args); i++ {
			if args[i] == "--listen" && i+1 < len(args) {
				listen = args[i+1]
				i++
			} else if args[i] == "--socket" && i+1 < len(args) {
				socket = args[i+1]
				i++
			}
		}
		if err := daemon.Run(listen, socket); err != nil {
			fatal(err)
		}
	case "doctor":
		var rep core.DoctorReport
		if err := callPrint("doctor", nil, &rep); err != nil {
			fatal(err)
		}
		printJSON(rep)
		if !rep.OK {
			os.Exit(1)
		}
	case "base":
		if len(args) == 0 || args[0] != "prepare" {
			fatal(fmt.Errorf("usage: ctd base prepare [--force]"))
		}
		var m core.Manifest
		if err := callPrint("base.prepare", map[string]any{"force": hasFlag(args[1:], "--force")}, &m); err != nil {
			fatal(err)
		}
		fmt.Printf("base ready: %d tools re-signed, tree %s\n",
			len(m.ToolsSigned), core.HumanBytes(m.TreeBytes))
		if len(m.ToolsMissing) > 0 {
			fmt.Printf("not present in image (skipped): %s\n", strings.Join(m.ToolsMissing, ", "))
		}
	case "create":
		name, ttl := "", 0
		var sets []string
		for i := 0; i < len(args); i++ {
			switch {
			case args[i] == "--ttl" && i+1 < len(args):
				fmt.Sscanf(args[i+1], "%d", &ttl)
				i++
			case args[i] == "--set" && i+1 < len(args):
				sets = append(sets, args[i+1])
				i++
			case name == "" && !strings.HasPrefix(args[i], "-"):
				name = args[i]
			}
		}
		if name == "" {
			fatal(fmt.Errorf("usage: ctd create <name> [--ttl seconds] [--set key=value ...]"))
		}
		spec := core.DefaultSpec()
		spec.TTLSeconds = 3600 // default: expire in 1h (0 via --ttl 0)
		if hasFlag(args, "--ttl") {
			spec.TTLSeconds = ttl
		}
		for _, kv := range sets {
			if err := spec.Set(kv); err != nil {
				fatal(err)
			}
		}
		var c core.Container
		if err := callPrint("container.deploy", map[string]any{"name": name, "spec": spec}, &c); err != nil {
			fatal(err)
		}
		fmt.Printf("container %q created (uid=%d, network=%v, shadow %s, allocated %s, ttl %s)\n",
			c.Name, c.Uid, c.Network, core.HumanBytes(c.ShadowSize),
			core.HumanBytes(c.ShadowUsed), ttlLabel(c.TTLSeconds))
	case "ps", "list":
		var all []*core.Container
		if err := callPrint("container.list", nil, &all); err != nil {
			fatal(err)
		}
		if hasFlag(args, "--json") {
			printJSON(all)
			return
		}
		if len(all) == 0 {
			fmt.Println("no containers")
			return
		}
		fmt.Printf("%-20s %-9s %-8s %-8s %-10s %s\n", "NAME", "STATE", "SHADOW", "DISK", "ALLOC", "CREATED")
		for _, c := range all {
			state := "detached"
			if c.Attached {
				state = "running"
			}
			if c.Expired {
				state = "expired"
			}
			disk := core.HumanBytes(c.DiskUsed)
			if c.DiskMax > 0 {
				disk += "/" + core.HumanBytes(c.DiskMax)
			}
			fmt.Printf("%-20s %-9s %-8s %-8s %-10s %s ago\n", c.Name, state,
				core.HumanBytes(c.ShadowSize), disk, core.HumanBytes(c.ShadowUsed),
				core.RelTime(c.CreatedAt))
		}
	case "run":
		if len(args) < 2 {
			fatal(fmt.Errorf("usage: ctd run <name> <cmd...>"))
		}
		code, err := api.Attach(args[0], args[1:], api.AttachOptions{})
		if err != nil {
			fatal(err)
		}
		os.Exit(code)
	case "exec":
		jsonOut := hasFlag(args, "--json")
		rest := filterFlags(args, "--json")
		if len(rest) < 2 {
			fatal(fmt.Errorf("usage: ctd exec [--json] <name> <cmd...>"))
		}
		var stdin string
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
			b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
			stdin = string(b)
		}
		raw, err := api.Call("container.exec", map[string]any{
			"container":  rest[0],
			"command":    rest[1:],
			"stdin":      stdin,
			"timeout_ms": (5 * time.Minute).Milliseconds(),
		})
		if err != nil {
			fatal(err)
		}
		if jsonOut {
			var v any
			json.Unmarshal(raw, &v)
			printJSON(v)
			var er api.ExecResponse
			json.Unmarshal(raw, &er)
			os.Exit(er.ExitCode)
		}
		var er api.ExecResponse
		if err := json.Unmarshal(raw, &er); err != nil {
			fatal(err)
		}
		os.Stdout.WriteString(er.Stdout)
		os.Stderr.WriteString(er.Stderr)
		os.Exit(er.ExitCode)
	case "shell":
		name := "default"
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			name = args[0]
		}
		if _, err := api.Call("container.inspect", map[string]any{"name": name}); err != nil {
			// convenience: create default shell container on first use
			if name == "default" {
				if _, cErr := api.Call("container.deploy", map[string]any{"name": "default"}); cErr == nil {
					fmt.Fprintln(os.Stderr, "[ctd] created container \"default\" (no TTL)")
				}
			} else {
				fatal(err)
			}
		}
		code, err := api.Attach(name, []string{"/bin/bash", "-i"}, api.AttachOptions{Cwd: "/Users/me"})
		if err != nil {
			fatal(err)
		}
		os.Exit(code)
	case "destroy":
		if len(args) < 1 {
			fatal(fmt.Errorf("usage: ctd destroy <name>"))
		}
		if _, err := api.Call("container.destroy", map[string]any{"name": args[0]}); err != nil {
			fatal(err)
		}
		fmt.Printf("container %q destroyed\n", args[0])
	case "deploy":
		// ctd deploy -f tpl.yaml [--name n] [--set k=v]...
		file, name := "", ""
		var sets []string
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "-f", "--file":
				i++
				if i < len(args) {
					file = args[i]
				}
			case "--name":
				i++
				if i < len(args) {
					name = args[i]
				}
			case "--set":
				i++
				if i < len(args) {
					sets = append(sets, args[i])
				}
			default:
				if file == "" && !strings.HasPrefix(args[i], "-") {
					file = args[i]
				}
			}
		}
		if file == "" {
			fatal(fmt.Errorf("usage: ctd deploy -f template.yaml [--name n] [--set key=value ...]"))
		}
		spec, err := core.ParseTemplate(file)
		if err != nil {
			fatal(err)
		}
		for _, kv := range sets {
			if err := spec.Set(kv); err != nil {
				fatal(err)
			}
		}
		if name != "" {
			spec.Name = name
		}
		if spec.Name == "" {
			fatal(fmt.Errorf("template has no name: set name: or --name"))
		}
		var c core.Container
		if err := callPrint("container.deploy", map[string]any{"name": spec.Name, "spec": spec}, &c); err != nil {
			fatal(err)
		}
		fmt.Printf("deployed %q (uid=%d, network=%v, shares=%d, writable=%v, ttl=%s)\n",
			c.Name, c.Uid, c.Network, len(spec.Shares), spec.Writable, ttlLabel(c.TTLSeconds))
		for _, sh := range spec.Shares {
			mode := sh.Mode
			if mode == "" {
				mode = "rw"
			}
			fmt.Printf("  share: %s -> %s (%s, sync-at-exec)\n", sh.Host, sh.Container, mode)
		}
	case "inspect":
		if len(args) < 1 {
			fatal(fmt.Errorf("usage: ctd inspect <name>"))
		}
		raw, err := api.Call("container.inspect", map[string]any{"name": args[0]})
		if err != nil {
			fatal(err)
		}
		var v any
		json.Unmarshal(raw, &v)
		printJSON(v)
	case "audit":
		if len(args) < 1 {
			fatal(fmt.Errorf("usage: ctd audit <name>"))
		}
		raw, err := api.Call("container.audit", map[string]any{"name": args[0]})
		if err != nil {
			fatal(err)
		}
		var v any
		json.Unmarshal(raw, &v)
		printJSON(v)
		var rep core.AuditReport
		json.Unmarshal(raw, &rep)
		if !rep.OK {
			os.Exit(1)
		}
	case "once":
		file, name := "", ""
		rm, jsonOut := false, false
		timeout := 600
		var argv []string
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "-f" || a == "--file":
				i++
				file = args[i]
			case a == "--name":
				i++
				name = args[i]
			case a == "--rm":
				rm = true
			case a == "--json":
				jsonOut = true
			case a == "--timeout":
				i++
				fmt.Sscanf(args[i], "%d", &timeout)
			case a == "--":
				argv = args[i+1:]
				i = len(args)
			case strings.HasPrefix(a, "-"):
				fatal(fmt.Errorf("unknown flag %q for once", a))
			default:
				argv = args[i:]
				i = len(args)
			}
		}
		if len(argv) == 0 {
			fatal(fmt.Errorf("usage: ctd once [-f tpl.yaml] [--name n] [--rm] [--json] [--timeout s] <cmd...>"))
		}
		params := map[string]any{
			"command":    argv,
			"rm":         rm,
			"timeout_ms": int64(timeout) * 1000,
		}
		var spec *core.Spec
		if file != "" {
			s, err := core.ParseTemplate(file)
			if err != nil {
				fatal(err)
			}
			spec = s
			if name == "" {
				name = s.Name
			}
		}
		if name == "" {
			fatal(fmt.Errorf("container name required (--name or template name:)"))
		}
		params["name"] = name
		if spec != nil {
			params["spec"] = spec
		}
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
			b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
			params["stdin"] = string(b)
		}
		raw, err := api.Call("container.once", params)
		if err != nil {
			fatal(err)
		}
		var res core.OnceResult
		json.Unmarshal(raw, &res)
		if jsonOut {
			var v any
			json.Unmarshal(raw, &v)
			printJSON(v)
		} else if res.Result != nil {
			os.Stdout.WriteString(res.Result.Stdout)
			os.Stderr.WriteString(res.Result.Stderr)
		}
		if res.Result != nil {
			os.Exit(res.Result.ExitCode)
		}
	case "bootstrap":
		if len(args) < 1 {
			fatal(fmt.Errorf("usage: ctd bootstrap <name>"))
		}
		var n int
		if err := callPrint("container.bootstrap", map[string]any{"name": args[0]}, &n); err != nil {
			fatal(err)
		}
		fmt.Printf("bootstrapped %q (%d binary re-signed)\n", args[0], n)
	case "gc":
		var destroyed []string
		if err := callPrint("container.gc", nil, &destroyed); err != nil {
			fatal(err)
		}
		if len(destroyed) == 0 {
			fmt.Println("nothing expired")
		} else {
			fmt.Printf("destroyed: %s\n", strings.Join(destroyed, ", "))
		}
	case "rpc":
		// stdio JSON-RPC proxy: pump lines between stdin/stdout and the socket.
		c, err := api.Dial()
		if err != nil {
			fatal(err)
		}
		defer c.Close()
		go func() {
			_, _ = io.Copy(c, os.Stdin)
			// stdin EOF: half-close so the daemon sees EOF and closes the
			// session after flushing its responses.
			if uc, ok := c.(*net.UnixConn); ok {
				_ = uc.CloseWrite()
			} else {
				_ = c.Close()
			}
		}()
		_, _ = io.Copy(os.Stdout, c)
	case "token":
		fmt.Println(api.LoadToken())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

// cmdTemplate: template new | template validate — local file ops.
func cmdTemplate(args []string) int {
	if len(args) == 0 || args[0] == "new" {
		out := "/tmp/ctd-template.yaml"
		if len(args) > 1 {
			out = args[1]
		} else if len(args) > 0 && args[0] != "new" {
			out = args[0]
		}
		if _, err := os.Stat(out); err == nil {
			fatal(fmt.Errorf("%s exists (refusing to overwrite)", out))
		}
		if err := os.WriteFile(out, []byte(core.ExampleTemplate()), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s\n", out)
		return 0
	}
	if args[0] != "validate" || len(args) < 2 {
		fatal(fmt.Errorf("usage: ctd template new [file] | ctd template validate <file>"))
	}
	spec, err := core.ParseTemplate(args[1])
	if err != nil {
		fatal(err)
	}
	b, _ := json.MarshalIndent(spec, "", "  ")
	fmt.Printf("valid ✓\n%s\n", b)
	return 0
}

// callPrint performs an RPC and pretty-prints the raw result when dst is nil.
func callPrint(method string, params any, dst any) error {
	raw, err := api.Call(method, params)
	if err != nil {
		return err
	}
	if dst != nil {
		if err := json.Unmarshal(raw, dst); err != nil {
			return fmt.Errorf("decode %s result: %w", method, err)
		}
	}
	return nil
}

func ttlLabel(t int) string {
	if t <= 0 {
		return "none"
	}
	return fmt.Sprintf("%ds", t)
}

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f {
			return true
		}
	}
	return false
}

func filterFlags(args []string, flags ...string) []string {
	skip := map[string]bool{}
	for _, f := range flags {
		skip[f] = true
	}
	var out []string
	for i := 0; i < len(args); i++ {
		if skip[args[i]] {
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ctd: "+err.Error())
	os.Exit(1)
}

// relaunchViaSudo re-execs the same command under sudo (passwordless or tty).
func relaunchViaSudo() {
	exe, err := os.Executable()
	if err != nil {
		fatal(fmt.Errorf("need root (sudo): %v", err))
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		fatal(fmt.Errorf("need root (sudo): %v", err))
	}
	argv := append([]string{sudo, exe}, os.Args[1:]...)
	// #nosec G204 — argv is our own executable with user subcommand args.
	if err := syscallExec(argv[0], argv, os.Environ()); err != nil {
		fatal(fmt.Errorf("need root (sudo): %v", err))
	}
}
