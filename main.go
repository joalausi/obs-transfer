package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var (
	secret string
	base   string
)

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if secret != "" && r.Header.Get("X-Key") != secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func main() {
	addr := flag.String("addr", ":8361", "listen address")
	flag.StringVar(&base, "dir", ".", "directory to read/write")
	flag.StringVar(&secret, "key", "", "shared secret for X-Key header")
	flag.Parse()

	if err := os.MkdirAll(base, 0o755); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))

	mux.HandleFunc("/echo", auth(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		io.Copy(w, r.Body) // просто возвращаем тело запроса
	}))

	mux.HandleFunc("/upload", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" || filepath.Base(name) != name {
			http.Error(w, "bad name", 400)
			return
		}
		dst := filepath.Join(base, name)
		tmp := dst + ".tmp"

		f, err := os.Create(tmp)
		if err != nil {
			http.Error(w, err.Error(), 500); return
		}
		if _, err := io.Copy(f, r.Body); err != nil {
			f.Close(); os.Remove(tmp)
			http.Error(w, err.Error(), 500); return
		}
		f.Close()
		if err := os.Rename(tmp, dst); err != nil {
			http.Error(w, err.Error(), 500); return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("/download", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" || filepath.Base(name) != name {
			http.Error(w, "bad name", 400)
			return
		}
		http.ServeFile(w, r, filepath.Join(base, name))
	}))

	log.Printf("dir=%s listen=%s", base, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}