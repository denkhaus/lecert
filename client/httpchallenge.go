package client

import (
	"io"
	"net"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
)

type HTTPChallengeResponder struct {
	net.Listener
	*sync.RWMutex
	path, resource string
}

func NewHTTPChallengeResponder(address string) (*HTTPChallengeResponder, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	h := &HTTPChallengeResponder{
		Listener: l,
		RWMutex:  new(sync.RWMutex),
	}

	log.Debugln("Listening on", address)
	go http.Serve(l, h)
	return h, nil
}

func (h *HTTPChallengeResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.RLock()
	defer h.RUnlock()
	l := log.WithFields(log.Fields{"mode": "standalone", "host": r.Host, "path": r.URL.Path})

	if r.URL.Path != h.path {
		l.Warnln("Bad Request")
		http.NotFound(w, r)
		return
	}

	l.Debugln("Success")
	io.WriteString(w, h.resource)
}

func (h *HTTPChallengeResponder) SetResource(path, resource string) error {
	h.Lock()
	defer h.Unlock()
	log.WithFields(log.Fields{
		"mode":     "standalone",
		"path":     path,
		"resource": resource,
	}).Debugln("SetResource")

	h.path = path
	h.resource = resource
	return nil
}
