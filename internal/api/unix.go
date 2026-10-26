package api

import (
	"encoding/json"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"ctd/internal/core"
)

// ServeUnix serves newline-delimited JSON-RPC on the daemon socket, one
// request per connection. "container.attach" sessions switch the same
// connection into a streaming event protocol:
//
//	client → {"id","method":"container.attach","params":{name,command,cwd,env,timeout_ms}}
//	server → {"id","ok":true,"event":"started"}
//	  then  {"id","event":"stdout"|"stderr","data":"..."} chunks
//	client → {"event":"stdin","data":"..."} / {"event":"stdin_eof"} /
//	         {"event":"signal","name":"INT"}
//	last   {"id","event":"exit","code":N}   (then the connection closes)
func (s *Server) ServeUnix(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(c)
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	dec := json.NewDecoder(c)
	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		if req.Method == "container.attach" {
			s.attachSession(c, dec, req)
			return
		}
		enc := json.NewEncoder(c)
		res, err := s.bus(req.Method, req.Params)
		resp := rpcResponse{ID: req.ID, OK: true}
		if err != nil {
			resp.OK = false
			resp.Error = err.Error()
		} else if raw, mErr := json.Marshal(res); mErr != nil {
			resp.OK = false
			resp.Error = mErr.Error()
		} else {
			resp.Result = raw
		}
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

// eventWriter emits {"event":e,"data":...} frames for one stream.
type eventWriter struct {
	enc   *json.Encoder
	mu    *sync.Mutex
	id    string
	event string
}

func (w *eventWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(map[string]any{"id": w.id, "event": w.event, "data": string(p)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *Server) attachSession(c net.Conn, dec *json.Decoder, req rpcRequest) {
	enc := json.NewEncoder(c)
	var encMu sync.Mutex
	var pidMu sync.Mutex
	var pid int

	var p struct {
		Name      string            `json:"name"`
		Command   []string          `json:"command"`
		Cwd       string            `json:"cwd,omitempty"`
		Env       map[string]string `json:"env,omitempty"`
		TimeoutMs int64             `json:"timeout_ms,omitempty"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" || len(p.Command) == 0 {
		encMu.Lock()
		enc.Encode(rpcResponse{ID: req.ID, OK: false, Error: "attach needs name + command"})
		encMu.Unlock()
		return
	}

	abort := make(chan struct{})
	stdinR, stdinW := io.Pipe()

	// stdin/signal pump: keeps reading client frames until the connection dies.
	go func() {
		for {
			var ev struct {
				Event string `json:"event"`
				Data  string `json:"data,omitempty"`
				Name  string `json:"name,omitempty"`
			}
			if err := dec.Decode(&ev); err != nil {
				// Client gone: give the process EOF on stdin and kill the tree.
				stdinW.Close()
				close(abort)
				return
			}
			switch ev.Event {
			case "stdin":
				if _, err := stdinW.Write([]byte(ev.Data)); err != nil {
					return
				}
			case "stdin_eof":
				stdinW.Close()
			case "signal":
				pidMu.Lock()
				pp := pid
				pidMu.Unlock()
				if pp > 0 {
					sig := syscall.SIGINT
					if ev.Name == "TERM" {
						sig = syscall.SIGTERM
					}
					_ = syscall.Kill(-pp, sig)
				}
			}
		}
	}()

	opts := core.ExecOptions{Cwd: p.Cwd, Env: p.Env}
	if p.TimeoutMs > 0 {
		opts.Timeout = time.Duration(p.TimeoutMs) * time.Millisecond
	}
	started := func(pp int) {
		pidMu.Lock()
		pid = pp
		pidMu.Unlock()
		encMu.Lock()
		enc.Encode(map[string]any{"id": req.ID, "ok": true, "event": "started"})
		encMu.Unlock()
	}
	res, err := core.StreamExec("api", p.Name, p.Command, opts,
		stdinR,
		&eventWriter{enc: enc, mu: &encMu, id: req.ID, event: "stdout"},
		&eventWriter{enc: enc, mu: &encMu, id: req.ID, event: "stderr"},
		abort, started)
	encMu.Lock()
	if err != nil {
		enc.Encode(rpcResponse{ID: req.ID, OK: false, Error: err.Error()})
	} else {
		enc.Encode(map[string]any{"id": req.ID, "event": "exit", "code": res.ExitCode})
	}
	encMu.Unlock()
}
