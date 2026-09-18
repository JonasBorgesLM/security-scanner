// Command reqcount is a counting reverse proxy: it sits between the scanner
// and a target, forwards every request untouched, and reports how many went
// out and what came back.
//
// It exists because stage 1's exit criterion is a number, and a number
// nobody else can reproduce is an anecdote. The scanner's own output cannot
// supply it: the whole point of that stage was that the scanner used to
// under-report what it did, so measuring it with itself would have been
// circular. See doc/security-scanner-evolucao.md §3.3 for the baseline
// these counts are compared against.
//
// # Usage
//
//	go run ./tools/reqcount -upstream http://localhost:8080 &
//	scanner scan --spec openapi.yaml --config config-through-proxy.yaml --out findings.json
//	kill -TERM %1        # prints the JSON summary
//
// The config must point target.base_url at the proxy, and list the proxy's
// host in scope.allowed_hosts.
//
// # What this costs, and why it is a measurement tool only
//
// Running the scanner through it means the ScopeGuard is validating THE
// PROXY'S address, not the target's. The allowlist still holds — nothing
// reaches a host outside it — but what it now guarantees is "the scanner
// only talked to the proxy", and the proxy will talk to whatever -upstream
// says. The boundary that matters has moved into a flag.
//
// That is an acceptable trade for a deliberate measurement against your own
// lab, and an unacceptable one for anything else. Never wire this into a
// normal run, and never point -upstream at a host you would not have put in
// scope.allowed_hosts yourself.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "address to listen on")
	upstream := flag.String("upstream", "http://localhost:8080", "target to forward to")
	out := flag.String("out", "", "write the summary here instead of stdout")
	flag.Parse()

	target, err := url.Parse(*upstream)
	if err != nil || target.Scheme == "" || target.Host == "" {
		log.Fatalf("reqcount: -upstream %q is not an absolute URL", *upstream)
	}

	c := &counter{byMethodStatus: map[string]int{}, byPath: map[string]int{}}

	srv := &http.Server{Addr: *listen, Handler: newProxy(target, c)}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		if err := c.write(*out); err != nil {
			log.Printf("reqcount: writing summary: %v", err)
		}
		os.Exit(0)
	}()

	log.Printf("reqcount: %s -> %s", *listen, target)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("reqcount: %v", err)
	}
}

// newProxy builds the forwarding handler. It is separate from main so a
// test can put a real upstream behind it and assert both halves of the
// tool's contract: that the counts are right, and that nothing the upstream
// sent was changed on the way through.
func newProxy(target *url.URL, c *counter) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Count on the way back, where the status is known. Returning nil keeps
	// the response exactly as the upstream sent it — this tool must not
	// change what the scanner sees, or it would be measuring itself.
	proxy.ModifyResponse = func(resp *http.Response) error {
		c.record(resp.Request.Method, resp.Request.URL.Path, resp.StatusCode)
		return nil
	}
	// A failed hop is still a request the scanner spent. Counting it as 599
	// keeps the total honest rather than silently dropping it.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		c.record(r.Method, r.URL.Path, 599)
		w.WriteHeader(http.StatusBadGateway)
	}
	return proxy
}

// counter tallies what crossed the proxy. Paths are recorded raw: an
// injected path parameter makes every probe a distinct path, which is noisy
// but honest, and collapsing them here would bake one reading of the data
// into the instrument that produced it.
type counter struct {
	mu             sync.Mutex
	total          int
	byMethodStatus map[string]int
	byPath         map[string]int
}

func (c *counter) record(method, path string, status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	c.byMethodStatus[fmt.Sprintf("%s -> %d", method, status)]++
	c.byPath[path]++
}

type summary struct {
	Total          int            `json:"total"`
	ByMethodStatus map[string]int `json:"by_method_status"`
	ByPath         map[string]int `json:"by_path"`
}

func (c *counter) write(path string) error {
	c.mu.Lock()
	s := summary{
		Total:          c.total,
		ByMethodStatus: maps(c.byMethodStatus),
		ByPath:         maps(c.byPath),
	}
	c.mu.Unlock()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// encoding/json escapes <, > and & by default, for HTML contexts this
	// output will never be in. Left on, the readable "GET -> 200" key turns
	// into "GET -\u003e 200" — unreadable and ungreppable in a file whose
	// only purpose is to be read.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}

	if path == "" {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// maps copies a counter map. encoding/json already sorts object keys, so
// the output is stable between runs of the same measurement — the same
// property the pipeline's own stage files are held to.
func maps(src map[string]int) map[string]int {
	dst := make(map[string]int, len(src))
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dst[k] = src[k]
	}
	return dst
}
