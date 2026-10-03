package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"procscope/internal/proc"
	webui "procscope/web"
)

// hub fans events out to every connected dashboard.
type hub struct {
	mu      sync.Mutex
	clients map[*conn]struct{}
}

type conn struct {
	ws   *websocket.Conn
	send chan []byte
}

func newHub() *hub { return &hub{clients: map[*conn]struct{}{}} }

func (h *hub) add(c *conn) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) remove(c *conn) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

func (h *hub) broadcast(data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- data:
		default: // slow dashboard: drop rather than block the collector
		}
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true }, // local dashboard
}

func routes(h *hub, sink *sink) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := webui.Files.ReadFile("index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})
	for _, name := range []string{"app.js", "style.css"} {
		n := name
		mux.HandleFunc("/"+n, func(w http.ResponseWriter, r *http.Request) {
			data, err := webui.Files.ReadFile(n)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			ct := "application/javascript"
			if n == "style.css" {
				ct = "text/css"
			}
			w.Header().Set("Content-Type", ct+"; charset=utf-8")
			w.Write(data)
		})
	}

	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &conn{ws: ws, send: make(chan []byte, 512)}
		h.add(c)

		// replay the recent window so a fresh page is never blank
		for _, ev := range sink.window() {
			if line, err := json.Marshal(ev); err == nil {
				c.send <- line
			}
		}

		go writer(c)
		go func() {
			for { // reader pump: only observes close
				if _, _, err := ws.ReadMessage(); err != nil {
					break
				}
			}
			h.remove(c)
			close(c.send)
		}()
	})

	mux.HandleFunc("/tree", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proc.Tree())
	})

	return mux
}

func writer(c *conn) {
	for line := range c.send {
		c.ws.SetWriteDeadline(writeTimeout())
		if err := c.ws.WriteMessage(websocket.TextMessage, line); err != nil {
			return
		}
	}
}
