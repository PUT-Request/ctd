// ctd — native macOS shell containers.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ctd/internal/api"
	"ctd/internal/core"
)

const usage = `ctd — native macOS shell containers (chroot + APFS CoW + Seatbelt)

usage: ctd <command> [args]

  doctor                     run environment probes (read-only)
  base prepare [--force]     build shared base shadow (once, idempotent)
  create <name> [--ttl N]    create container (TTL seconds, 0=never)
  ps                         list containers
  run <name> <cmd...>        run command (interactive, inherits tty)
  exec <name> <cmd...>       run command (captures stdout/stderr)
  exec --json <name> <cmd..> run command, print JSON result
  shell [name]               interactive shell (default container: default)
  deploy -f tpl.yaml         create from YAML template
                             [--name n] [--set network.allow=true]
  template new [file]        write an example template
  template validate <file>   validate + show resolved spec
  inspect <name>             container state + effective spec (JSON)
  audit <name>               live security probe suite (JSON, exit 1 on fail)
  bootstrap <name>           re-run template bootstrapping in a container
  once [-f t.yaml] [--rm] <cmd...>   one-shot: create if needed → run → optional cleanup
  destroy <name>             detach + delete container
  gc                         destroy expired containers
  serve [--listen A]         HTTP JSON API on A (default 127.0.0.1:7399) + stdio RPC
  rpc                        stdio JSON-RPC (newline-delimited JSON on stdin/stdout)
  token                      print the API bearer token

HTTP API (Authorization: Bearer <token>, or ?token=):
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

stdio JSON-RPC (one JSON object per line):
  > {"id":"1","method":"container.create","params":{"name":"demo"}}
  < {"id":"1","ok":true,"result":{...}}
  methods: ping, doctor, base.prepare, container.create, container.list,
           container.inspect, container.destroy, container.gc, container.exec

examples:
  sudo ctd base prepare
  sudo ctd create demo --ttl 3600
  ctd run demo /bin/bash -c 'echo hi | /usr/bin/wc -w'
  ctd exec --json demo /usr/bin/uname -a
  curl -s -H "Authorization: Bearer $(ctd token)" \
       -d '{"command":["/bin/ls","/"]}' localhost:7399/v1/containers/demo/exec
  echo '{"id":"1","method":"container.list"}' | ctd rpc
`

// subcommands that need root
var privileged = map[string]bool{
	"base": true, "create": true, "destroy": true, "gc": true, "deploy": true,
	"serve": true, "run": true, "exec": true, "shell": true, "token": true, "once": true,
	"audit": true, "inspect": true, "bootstrap": true,
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	// internal stage, runs under sandbox-exec
	if cmd == "__inner" {
		os.Exit(core.Inner(args))
	}

	if privileged[cmd] && os.Geteuid() != 0 {
		relaunchViaSudo()
	}

	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "doctor":
		rep := core.Doctor()
		printJSON(rep)
		if !rep.OK {
			os.Exit(1)
		}
	case "base":
		if len(args) == 0 || args[0] != "prepare" {
			fatal(fmt.Errorf("usage: ctd base prepare [--force]"))
		}
		force := hasFlag(args[1:], "--force")
		m, err := core.PrepareBase(force)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("base ready: %d tools re-signed, tree %s\n",
			len(m.ToolsSigned), core.HumanBytes(m.TreeBytes))
		if len(m.ToolsMissing) > 0 {
			fmt.Printf("not present in image (skipped): %s\n", strings.Join(m.ToolsMissing, ", "))
		}
	case "create":
		name, rest := "", args
		ttl := 0
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--ttl" && i+1 < len(rest) {
				fmt.Sscanf(rest[i+1], "%d", &ttl)
				i++
			} else if name == "" && !strings.HasPrefix(rest[i], "-") {
				name = rest[i]
			}
		}
		if name == "" {
			fatal(fmt.Errorf("usage: ctd create <name> [--ttl seconds] [--set key=value ...]"))
		}
		spec := core.DefaultSpec()
		spec.TTLSeconds = ttl
		if !hasFlag(args, "--ttl") {
			spec.TTLSeconds = 3600 // default: expire in 1h (0 via --ttl 0)
		}
		for i := 0; i < len(args); i++ {
			if args[i] == "--set" && i+1 < len(args) {
				if err := spec.Set(args[i+1]); err != nil {
					fatal(err)
				}
				i++
			}
		}
		c, err := core.Create(name, spec)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("container %q created (uid=%d, network=%v, shadow %s, allocated %s, ttl %s)\n",
			c.Name, c.Uid, c.Network, core.HumanBytes(c.ShadowSize),
			core.HumanBytes(c.ShadowUsed), ttlLabel(c.TTLSeconds))
	case "ps", "list":
		all, err := core.List()
		if err != nil {
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
		fmt.Printf("%-20s %-9s %-8s %-10s %s\n", "NAME", "STATE", "SHADOW", "ALLOC", "CREATED")
		for _, c := range all {
			state := "detached"
			if c.Attached {
				state = "running"
			}
			if c.Expired {
				state = "expired"
			}
			fmt.Printf("%-20s %-9s %-8s %-10s %s ago\n", c.Name, state,
				core.HumanBytes(c.ShadowSize), core.HumanBytes(c.ShadowUsed),
				core.RelTime(c.CreatedAt))
		}
	case "run":
		if len(args) < 2 {
			fatal(fmt.Errorf("usage: ctd run <name> <cmd...>"))
		}
		code, err := core.ExecInteractive("cli", args[0], args[1:], core.ExecOptions{})
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
		// pipe stdin when not a terminal
		var stdin string
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
			b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
			stdin = string(b)
		}
		res, err := core.Exec("cli", rest[0], rest[1:], core.ExecOptions{Stdin: stdin, Timeout: 5 * time.Minute})
		if err != nil {
			fatal(err)
		}
		if jsonOut {
			printJSON(res)
		} else {
			os.Stdout.WriteString(res.Stdout)
			os.Stderr.WriteString(res.Stderr)
		}
		os.Exit(res.ExitCode)
	case "shell":
		name := "default"
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			name = args[0]
		}
		if _, err := core.Describe(name); err != nil {
			// convenience: create default shell container on first use
			if name == "default" {
				if _, cErr := core.Create("default", core.DefaultSpec()); cErr == nil {
					fmt.Fprintln(os.Stderr, "[ctd] created container \"default\" (no TTL)")
				}
			} else {
				fatal(err)
			}
		}
		code, err := core.ExecInteractive("cli", name, []string{"/bin/bash", "-i"}, core.ExecOptions{Cwd: "/Users/me"})
		if err != nil {
			fatal(err)
		}
		os.Exit(code)
	case "destroy":
		if len(args) < 1 {
			fatal(fmt.Errorf("usage: ctd destroy <name>"))
		}
		if err := core.Destroy(args[0]); err != nil {
			fatal(err)
		}
		fmt.Printf("container %q destroyed\n", args[0])
	case "template":
		// ctd template new [file] | ctd template validate <file>
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
			return
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
		c, err := core.Create(spec.Name, spec)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("deployed %q (uid=%d, network=%v, shares=%d, writable=%v, ttl=%s)\n",
			c.Name, c.Uid, c.Network, len(spec.Shares), spec.Writable, ttlLabel(c.TTLSeconds))
		if len(spec.Shares) > 0 {
			for _, sh := range spec.Shares {
				mode := sh.Mode
				if mode == "" {
					mode = "rw"
				}
				fmt.Printf("  share: %s -> %s (%s, sync-at-exec)\n", sh.Host, sh.Container, mode)
			}
		}
	case "inspect":
		if len(args) < 1 {
			fatal(fmt.Errorf("usage: ctd inspect <name>"))
		}
		c, err := core.Describe(args[0])
		if err != nil {
			fatal(err)
		}
		spec, _ := core.FullSpec(args[0])
		printJSON(map[string]any{"container": c, "spec": spec})
	case "audit":
		if len(args) < 1 {
			fatal(fmt.Errorf("usage: ctd audit <name>"))
		}
		rep, err := core.AuditContainer(args[0])
		if err != nil {
			fatal(err)
		}
		printJSON(rep)
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
		if file != "" {
			if spec, err := core.ParseTemplate(file); err == nil && name == "" {
				name = spec.Name
			}
		}
		if name == "" {
			fatal(fmt.Errorf("container name required (--name or template name:)"))
		}
		// piped stdin
		var stdin string
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
			b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
			stdin = string(b)
		}
		res, err := core.Once(name, file, argv, core.ExecOptions{Stdin: stdin, Timeout: time.Duration(timeout) * time.Second}, rm)
		if err != nil {
			fatal(err)
		}
		if jsonOut {
			printJSON(res)
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
		n, err := core.Bootstrap(args[0])
		if err != nil {
			fatal(err)
		}
		fmt.Printf("bootstrapped %q (%d binary re-signed)\n", args[0], n)
	case "gc":
		destroyed, err := core.GC()
		if err != nil {
			fatal(err)
		}
		if len(destroyed) == 0 {
			fmt.Println("nothing expired")
		} else {
			fmt.Printf("destroyed: %s\n", strings.Join(destroyed, ", "))
		}
	case "serve":
		listen := "127.0.0.1:7399"
		token := ""
		for i := 0; i < len(args); i++ {
			if args[i] == "--listen" && i+1 < len(args) {
				listen = args[i+1]
				i++
			} else if args[i] == "--token" && i+1 < len(args) {
				token = args[i+1]
				i++
			}
		}
		if token == "" {
			token = api.LoadToken()
		}
		srv := &api.Server{Token: token, GCEnabled: true}
		// Background GC every 60s.
		go func() {
			for range time.Tick(60 * time.Second) {
				_, _ = core.GC()
			}
		}()
		// HTTP + stdio on the same process: stdin lines served as RPC.
		go func() { _ = srv.ServeStdio(os.Stdin, os.Stdout) }()
		if err := srv.ServeHTTP(listen); err != nil {
			fatal(err)
		}
	case "rpc":
		srv := &api.Server{Token: ""} // stdio implies local trust
		if err := srv.ServeStdio(os.Stdin, os.Stdout); err != nil {
			fatal(err)
		}
	case "token":
		fmt.Println(api.LoadToken())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
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
	argv := append([]string{"sudo", exe}, os.Args[1:]...)
	// #nosec G204 — argv is our own executable with user subcommand args.
	if err := syscallExec(argv[0], argv, os.Environ()); err != nil {
		fatal(fmt.Errorf("need root (sudo): %v", err))
	}
}
