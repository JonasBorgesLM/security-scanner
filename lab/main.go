// Command lab-api is a deliberately vulnerable HTTP API, built only to give
// security-scanner something of its own to scan end to end. It is not part
// of the security-scanner module (see go.mod) and must never be deployed
// anywhere but the docker-compose lab in this repository.
//
// It is vulnerable on purpose in four ways, one per line in checks.enabled:
//   - GET /items?q=      boolean-based SQL injection (sqli-boolean)
//   - GET /debug         a leaked AWS-shaped key and a generic API key (exposed-secrets)
//   - every response     no security headers are ever set (missing-headers)
//   - GET /search?term=  reflected XSS with no output encoding
//
// GET /search is included even though security-scanner does not yet ship
// an active xss-reflected scan check (see the parent repo's CLAUDE.md) — it
// exists for internal/attack's xss-reflected Confirmer to be exercised
// against by hand today, and for `scanner scan` to pick up automatically
// once that check exists.
package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	_ "github.com/lib/pq"
)

var db *sql.DB

// sessions holds tokens issued by handleLogin. A lab has no need for JWTs
// or expiry — the only thing under test is what the API does with a
// request once it decides the caller is authenticated.
var sessions = struct {
	sync.Mutex
	tokens map[string]bool
}{tokens: map[string]bool{}}

var labPassword string

func main() {
	dsn := requireEnv("DATABASE_URL")
	labPassword = requireEnv("LAB_PASSWORD")

	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("ping database: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/items", handleItems)
	mux.HandleFunc("/items/", handleItemByID)
	mux.HandleFunc("/search", handleSearch)
	mux.HandleFunc("/debug", handleDebug)

	const addr = ":8080"
	log.Printf("lab-api listening on %s — deliberately vulnerable, lab use only", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if body.Username != "admin" || body.Password != labPassword {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	token, err := newToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sessions.Lock()
	sessions.tokens[token] = true
	sessions.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]string{"access_token": token},
	})
}

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func authorized(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return false
	}
	sessions.Lock()
	defer sessions.Unlock()
	return sessions.tokens[token]
}

func handleItems(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		listItems(w, r)
	case http.MethodPost:
		createItem(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// listItems is the lab's SQL injection target: q is matched against name
// by concatenating it directly into the WHERE clause instead of passing it
// as a bound parameter, so a value like `' OR '1'='1` changes what the
// query matches. This is an exact-match lookup rather than a substring
// search deliberately: wrapping q in LIKE wildcards ('%q%') would absorb a
// classic OR-based payload into the developer's own leading wildcard
// instead of breaking out of it, masking the true/false difference the
// sqli-boolean check and its payload pairs rely on.
//
// The SELECT list is ordered id, price, name (not the table's own column
// order) so the last column is text: internal/attack's UNION-based
// extraction always places its marker in the last column, and Postgres
// rejects a UNION whose columns aren't type-compatible — putting a numeric
// column last would silently defeat extraction on a real database, not
// because of anything the scanner does wrong, but because of an
// unlucky column-type accident.
//
// Scanned as sql.NullInt64/sql.NullFloat64, not plain int/float64: a UNION
// SELECT-based extraction pads every column but the one it wants except
// with NULL, and scanning a NULL into a non-nullable Go type errors out —
// which would silently swallow the very row extraction depends on.
func listItems(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	query := fmt.Sprintf("SELECT id, price, name FROM items WHERE name = '%s' ORDER BY id", q)

	rows, err := db.Query(query)
	if err != nil {
		// A naive app surfaces the driver error verbatim — itself a second,
		// smaller leak (schema/engine details), left in on purpose.
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	items := []map[string]any{}
	for rows.Next() {
		var id sql.NullInt64
		var price sql.NullFloat64
		var name string
		if err := rows.Scan(&id, &price, &name); err != nil {
			continue
		}
		items = append(items, map[string]any{"id": id.Int64, "name": name, "price": price.Float64})
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func createItem(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string  `json:"name"`
		Price float64 `json:"price"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var id int
	err := db.QueryRow("INSERT INTO items (name, price) VALUES ($1, $2) RETURNING id", body.Name, body.Price).Scan(&id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "created": true})
}

func handleItemByID(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/items/"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		getItem(w, id)
	case http.MethodPut:
		updateItem(w, r, id)
	case http.MethodDelete:
		deleteItem(w, id)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// getItem is deliberately SAFE — a bound parameter, not string
// concatenation — so the lab isn't vulnerable on every single route. A scan
// that flagged this one would be a false positive worth noticing.
func getItem(w http.ResponseWriter, id int) {
	var name string
	var price float64
	err := db.QueryRow("SELECT name, price FROM items WHERE id = $1", id).Scan(&name, &price)
	switch {
	case err == sql.ErrNoRows:
		w.WriteHeader(http.StatusNotFound)
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": name, "price": price})
	}
}

func updateItem(w http.ResponseWriter, r *http.Request, id int) {
	var body struct {
		Name  string  `json:"name"`
		Price float64 `json:"price"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := db.Exec("UPDATE items SET name = $1, price = $2 WHERE id = $3", body.Name, body.Price, id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

func deleteItem(w http.ResponseWriter, id int) {
	if _, err := db.Exec("DELETE FROM items WHERE id = $1", id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSearch reflects term straight into an HTML response with no output
// encoding — a textbook reflected-XSS sink. Unlike every other handler here
// it needs no Authorization header, matching how these bugs usually show up
// for real: on the public-facing route nobody thought to protect.
func handleSearch(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("term")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Search results</h1><p>You searched for: %s</p></body></html>", term)
}

// handleDebug simulates a diagnostics endpoint that was never meant to
// reach production — a common real-world way secrets leak. It embeds
// AWS's own published example access key ID (safe to commit: not a real
// credential, but shaped exactly like one) alongside a generic api_key
// assignment, so both exposed-secrets confidence tiers have something to
// find.
func handleDebug(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"build": "lab-1.0",
		"env": map[string]string{
			"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
			"api_key":           "lab-demo-api-key-9f8e7d6c5b4a",
		},
	})
}

// writeJSON is the only place a response header gets set beyond
// Content-Type — no CSP, no HSTS, no X-Frame-Options, no
// X-Content-Type-Options, anywhere in this API. That omission is the
// lab's missing-headers target, and it's deliberate on every route, not
// just this one.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
