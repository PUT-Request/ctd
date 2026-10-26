package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// SocketPath is the daemon's local control socket (root:0600).
const SocketPath = "/opt/ctd/ctd.sock"

const errNoDaemon = "ctd daemon is not running — start it with `sudo ctd daemon` and keep that terminal open"

// Dial connects to the running daemon socket.
func Dial() (net.Conn, error) {
	c, err := net.Dial("unix", SocketPath)
	if err != nil {
		return nil, fmt.Errorf("%s (%v)", errNoDaemon, err)
	}
	return c, nil
}

// Call performs one request/response RPC over the daemon socket.
func Call(method string, params any) (json.RawMessage, error) {
	c, err := Dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var body json.RawMessage
	if params != nil {
		if b, err := json.Marshal(params); err == nil {
			body = b
		}
	}
	enc := json.NewEncoder(c)
	if err := enc.Encode(rpcRequest{ID: newID(), Method: method, Params: body}); err != nil {
		return nil, fmt.Errorf("daemon connection: %w", err)
	}
	var resp rpcResponse
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, fmt.Errorf("daemon connection: %w", err)
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	return resp.Result, nil
}

func newID() string {
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
}

// Send serializes concurrent writes to a json.Encoder.
type sender struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (s *sender) Send(v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(v)
}

// AttachOptions configure a streamed interactive session.
type AttachOptions struct {
	Cwd     string
	Env     map[string]string
	Timeout time.Duration
}

// Attach opens a streamed session (`ctd run` / `ctd shell`): stdin and
// terminal signals are forwarded to the daemon; stdout/stderr stream back.
// Returns the container command's exit code.
func Attach(name string, argv []string, opts AttachOptions) (int, error) {
	c, err := Dial()
	if err != nil {
		return 1, err
	}
	defer c.Close()
	enc := json.NewEncoder(c)
	dec := json.NewDecoder(c)
	out := &sender{enc: enc}

	params := map[string]any{
		"name":    name,
		"command": argv,
	}
	if opts.Cwd != "" {
		params["cwd"] = opts.Cwd
	}
	if opts.Env != nil {
		params["env"] = opts.Env
	}
	if opts.Timeout > 0 {
		params["timeout_ms"] = opts.Timeout.Milliseconds()
	}
	if err := out.Send(rpcRequest{ID: newID(), Method: "container.attach", Params: mustJSON(params)}); err != nil {
		return 1, err
	}

	// stdin pump
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				out.Send(map[string]any{"event": "stdin", "data": string(buf[:n])})
			}
			if rerr != nil {
				out.Send(map[string]any{"event": "stdin_eof"})
				return
			}
		}
	}()
	// forward terminal signals (Ctrl-C) into the container process group
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigc {
			out.Send(map[string]any{"event": "signal", "name": "INT"})
		}
	}()
	defer signal.Stop(sigc)

	for {
		var msg struct {
			ID    string `json:"id"`
			OK    bool   `json:"ok"`
			Event string `json:"event"`
			Data  string `json:"data"`
			Code  int    `json:"code"`
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				return 1, errors.New("daemon closed the session")
			}
			return 1, fmt.Errorf("daemon connection: %w", err)
		}
		switch msg.Event {
		case "stdout":
			os.Stdout.Write([]byte(msg.Data))
		case "stderr":
			os.Stderr.Write([]byte(msg.Data))
		case "exit":
			return msg.Code, nil
		default:
			if msg.Error != "" {
				return 1, errors.New(msg.Error)
			}
		}
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
