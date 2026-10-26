package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ctd/internal/core"
)

// Server exposes the ctd control plane over HTTP (JSON) and stdio (JSON-RPC).
// It shares one command bus so both transports behave identically.
type Server struct {
	Token     string
	mu        sync.Mutex // serializes container mutations
	GCEnabled bool
}

// ---- command bus (shared by HTTP + stdio) ----

type CreateParams struct {
	Name string     `json:"name"`
	TTL  int        `json:"ttl_seconds"`
	Spec *core.Spec `json:"spec,omitempty"` // full template (deploy)
	YAML string     `json:"yaml,omitempty"` // raw YAML (deploy)
}

// DeployParams creates a container from a template: inline YAML or a Spec.
type DeployParams struct {
	Name string     `json:"name,omitempty"`
	YAML string     `json:"yaml,omitempty"`
	Spec *core.Spec `json:"spec,omitempty"`
	Sets []string   `json:"set,omitempty"` // dotted overrides
}

type ExecParams struct {
	Container string            `json:"container"`
	Command   []string          `json:"command"`
	Cwd       string            `json:"cwd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Stdin     string            `json:"stdin,omitempty"`
	TimeoutMs int64             `json:"timeout_ms,omitempty"`
}

type ExecResponse struct {
	core.ExecResult
	Container string `json:"container"`
}

func (s *Server) bus(method string, params json.RawMessage) (any, error) {
	switch method {
	case "ping":
		return map[string]string{"pong": "ctd", "version": "0.1.0"}, nil

	case "doctor":
		return core.Doctor(), nil

	case "base.prepare":
		var p struct {
			Force bool `json:"force"`
		}
		_ = json.Unmarshal(params, &p)
		return core.PrepareBase(p.Force)

	case "container.create":
		var p CreateParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		spec := core.DefaultSpec()
		if p.TTL > 0 {
			spec.TTLSeconds = p.TTL
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return core.Create(p.Name, spec)

	case "container.bootstrap":
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return core.Bootstrap(p.Name)

	case "template.validate":
		var p DeployParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		spec, err := specFrom(p)
		if err != nil {
			return nil, err
		}
		return spec, nil

	case "container.deploy":
		var p DeployParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		spec, err := specFrom(p)
		if err != nil {
			return nil, err
		}
		name := p.Name
		if name == "" {
			name = spec.Name
		}
		if name == "" {
			return nil, fmt.Errorf("deploy needs a name (yaml name: or params.name)")
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return core.Create(name, spec)

	case "container.inspect":
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		c, err := core.Describe(p.Name)
		if err != nil {
			return nil, err
		}
		full, err := core.FullSpec(p.Name)
		if err == nil {
			return map[string]any{"container": c, "spec": full}, nil
		}
		return c, nil

	case "container.audit":
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		return core.AuditContainer(p.Name)

	case "container.list":
		return core.List()

	case "container.destroy":
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := core.Destroy(p.Name); err != nil {
			return nil, err
		}
		return map[string]string{"destroyed": p.Name}, nil

	case "container.once":
		var p struct {
			Name      string            `json:"name"`
			YAML      string            `json:"yaml,omitempty"`
			Spec      *core.Spec        `json:"spec,omitempty"`
			Command   []string          `json:"command"`
			Cwd       string            `json:"cwd,omitempty"`
			Env       map[string]string `json:"env,omitempty"`
			Stdin     string            `json:"stdin,omitempty"`
			TimeoutMs int64             `json:"timeout_ms,omitempty"`
			Rm        bool              `json:"rm,omitempty"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		if len(p.Command) == 0 {
			return nil, fmt.Errorf("command required")
		}
		spec := p.Spec
		if spec == nil && p.YAML != "" {
			tmp, err := os.CreateTemp("", "ctd-once-*.yaml")
			if err != nil {
				return nil, err
			}
			if _, err := tmp.WriteString(p.YAML); err != nil {
				tmp.Close()
				return nil, err
			}
			tmp.Close()
			defer os.Remove(tmp.Name())
			spec, err = core.ParseTemplate(tmp.Name())
			if err != nil {
				return nil, err
			}
		}
		opts := core.ExecOptions{Cwd: p.Cwd, Env: p.Env, Stdin: p.Stdin}
		if p.TimeoutMs > 0 {
			opts.Timeout = time.Duration(p.TimeoutMs) * time.Millisecond
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return core.Once(p.Name, spec, p.Command, opts, p.Rm)

	case "container.gc":
		s.mu.Lock()
		defer s.mu.Unlock()
		return core.GC()

	case "container.exec":
		var p ExecParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("bad params: %w", err)
		}
		opts := core.ExecOptions{
			Cwd:   p.Cwd,
			Env:   p.Env,
			Stdin: p.Stdin,
		}
		if p.TimeoutMs > 0 {
			opts.Timeout = time.Duration(p.TimeoutMs) * time.Millisecond
		}
		res, err := core.Exec("api", p.Container, p.Command, opts)
		if err != nil {
			return nil, err
		}
		return ExecResponse{ExecResult: *res, Container: p.Container}, nil

	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

// specFrom builds a Spec from raw YAML and/or a structured object + overrides.
func specFrom(p DeployParams) (*core.Spec, error) {
	var spec *core.Spec
	var err error
	if p.YAML != "" {
		spec, err = core.ParseTemplateBytes([]byte(p.YAML))
	} else if p.Spec != nil {
		spec = p.Spec
		if err = spec.Normalize(); err == nil {
			err = spec.Validate()
		}
	} else {
		spec = core.DefaultSpec()
	}
	if err != nil {
		return nil, err
	}
	for _, kv := range p.Sets {
		if err := spec.Set(kv); err != nil {
			return nil, err
		}
	}
	return spec, nil
}

// ---- HTTP JSON API ----

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) authed(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") && subtleEqual(strings.TrimPrefix(h, "Bearer "), s.Token) {
		return true
	}
	// Also accept ?token= for easy curl.
	if subtleEqual(r.URL.Query().Get("token"), s.Token) {
		return true
	}
	return false
}

// constant-time-ish compare
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// Handler returns the HTTP mux for the JSON API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// REST-ish JSON endpoints mapping onto the bus.
	mux.HandleFunc("GET /v1/ping", func(w http.ResponseWriter, r *http.Request) {
		s.call(w, "ping", nil)
	})
	mux.HandleFunc("GET /v1/doctor", func(w http.ResponseWriter, r *http.Request) {
		s.call(w, "doctor", nil)
	})
	mux.HandleFunc("POST /v1/base/prepare", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Force bool `json:"force"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := json.Marshal(body)
		s.call(w, "base.prepare", b)
	})
	mux.HandleFunc("GET /v1/containers", func(w http.ResponseWriter, r *http.Request) {
		s.call(w, "container.list", nil)
	})
	mux.HandleFunc("POST /v1/containers", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, 400, envelope{Error: err.Error()})
			return
		}
		s.call(w, "container.create", body)
	})
	mux.HandleFunc("GET /v1/containers/{name}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]string{"name": r.PathValue("name")})
		s.call(w, "container.inspect", b)
	})
	mux.HandleFunc("DELETE /v1/containers/{name}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]string{"name": r.PathValue("name")})
		s.call(w, "container.destroy", b)
	})
	mux.HandleFunc("POST /v1/containers/{name}/exec", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			writeJSON(w, 400, envelope{Error: err.Error()})
			return
		}
		// Inject container name from path if absent in body.
		var p ExecParams
		if err := json.Unmarshal(body, &p); err != nil {
			writeJSON(w, 400, envelope{Error: "bad json: " + err.Error()})
			return
		}
		if p.Container == "" {
			p.Container = r.PathValue("name")
		}
		if len(p.Command) == 0 {
			writeJSON(w, 400, envelope{Error: "command required"})
			return
		}
		nb, _ := json.Marshal(p)
		s.call(w, "container.exec", nb)
	})
	mux.HandleFunc("POST /v1/gc", func(w http.ResponseWriter, r *http.Request) {
		s.call(w, "container.gc", nil)
	})

	// Escape hatch: generic {"method":...,"params":...} envelope.
	mux.HandleFunc("POST /v1/rpc", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
			writeJSON(w, 400, envelope{Error: err.Error()})
			return
		}
		s.call(w, req.Method, req.Params)
	})

	return s.wrapAuth(mux)
}

func (s *Server) wrapAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/ping" || s.authed(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, 401, envelope{Error: "unauthorized"})
	})
}

func (s *Server) call(w http.ResponseWriter, method string, params json.RawMessage) {
	res, err := s.bus(method, params)
	if err != nil {
		writeJSON(w, 400, envelope{OK: false, Error: err.Error()})
		return
	}
	raw, err := json.Marshal(res)
	if err != nil {
		writeJSON(w, 500, envelope{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, 200, envelope{OK: true, Result: raw})
}

// Serve runs the HTTP JSON API on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	if s.Token == "" {
		s.Token = LoadToken()
	}
	srv := &http.Server{Handler: s.Handler()}
	return srv.Serve(ln)
}

// ---- newline-delimited JSON-RPC ----

type rpcRequest struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type rpcResponse struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// NewToken generates a random auth token and persists it under OptDir.
func NewToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b)
	_ = core.EnsureDir(core.OptDir, 0o755)
	p := filepath.Join(core.OptDir, "api.token")
	_ = os.WriteFile(p, []byte(tok+"\n"), 0o600)
	return tok
}

// LoadToken returns a persisted token or creates one.
func LoadToken() string {
	p := filepath.Join(core.OptDir, "api.token")
	if b, err := os.ReadFile(p); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t
		}
	}
	return NewToken()
}
