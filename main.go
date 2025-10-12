package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type FileEntry struct {
	Path    string `json:"path"`
	ModTime int64  `json:"mod_time"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

type Manifest struct {
	Device      string      `json:"device"`
	Vault       string      `json:"vault"`
	GeneratedAt int64       `json:"generated_at"`
	Files       []FileEntry `json:"files"`
}

var ignoreDirs = map[string]bool{
	".git":       true,
	".obsidian":  true, // оставим настройки плагинов локальными
	".trash":     true,
	".DS_Store":  true,
	"node_modules": true,
}

func isIgnored(path string) bool {
	base := filepath.Base(path)
	if ignoreDirs[base] {
		return true
	}
	// игнорируем скрытые служебные файлы
	if strings.HasPrefix(base, ".") && base != ".well-known" {
		return true
	}
	return false
}

func hashFile(path string) (string, int64, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		return "", 0, 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), fi.ModTime().Unix(), n, nil
}

func buildManifest(vault string, device string) (Manifest, error) {
	var files []FileEntry
	err := filepath.WalkDir(vault, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(vault, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if isIgnored(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if isIgnored(d.Name()) {
			return nil
		}
		sum, mtime, size, err := hashFile(p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		files = append(files, FileEntry{
			Path:    rel,
			ModTime: mtime,
			Size:    size,
			SHA256:  sum,
		})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{
		Device:      device,
		Vault:       filepath.Base(vault),
		GeneratedAt: time.Now().Unix(),
		Files:       files,
	}, nil
}

func writeFileAtomic(dst string, r io.Reader) error {
	tmp := dst + ".tmp"
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func authMiddleware(key string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if key != "" && r.Header.Get("X-Key") != key {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func runServer(vault, addr, key, device string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/manifest", func(w http.ResponseWriter, r *http.Request) {
		m, err := buildManifest(vault, device)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	})

	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("path")
		if q == "" || strings.Contains(q, "..") {
			http.Error(w, "bad path", 400)
			return
		}
		full := filepath.Join(vault, filepath.FromSlash(q))
		switch r.Method {
		case http.MethodGet:
			http.ServeFile(w, r, full)
		case http.MethodPut:
			// принимаем файл
			if err := writeFileAtomic(full, r.Body); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})

	log.Printf("Serving %s on %s", vault, addr)
	return http.ListenAndServe(addr, authMiddleware(key, mux))
}

func fetchManifest(peer, key string) (Manifest, error) {
	req, _ := http.NewRequest(http.MethodGet, strings.TrimRight(peer, "/")+"/manifest", nil)
	if key != "" {
		req.Header.Set("X-Key", key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Manifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return Manifest{}, fmt.Errorf("manifest status %d: %s", resp.StatusCode, string(body))
	}
	var m Manifest
	return m, json.NewDecoder(resp.Body).Decode(&m)
}

func downloadFile(peer, key, remotePath, dst string) error {
	url := strings.TrimRight(peer, "/") + "/file?path=" + remotePath
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if key != "" {
		req.Header.Set("X-Key", key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download status %d: %s", resp.StatusCode, string(body))
	}
	full := filepath.Join(dst, filepath.FromSlash(remotePath))
	return writeFileAtomic(full, resp.Body)
}

func localIndex(vault string) (map[string]FileEntry, error) {
	m, err := buildManifest(vault, "local")
	if err != nil {
		return nil, err
	}
	idx := make(map[string]FileEntry, len(m.Files))
	for _, f := range m.Files {
		idx[f.Path] = f
	}
	return idx, nil
}

func runPull(vault, peer, key string) error {
	log.Println("Fetching remote manifest...")
	rm, err := fetchManifest(peer, key)
	if err != nil {
		return err
	}
	lidx, err := localIndex(vault)
	if err != nil {
		return err
	}

	var toGet []FileEntry
	for _, rf := range rm.Files {
		lf, ok := lidx[rf.Path]
		if !ok {
			toGet = append(toGet, rf)
			continue
		}
		// если хеши совпадают - пропускаем
		if rf.SHA256 == lf.SHA256 {
			continue
		}
		// если удалёнка новее - тянем
		if rf.ModTime > lf.ModTime {
			toGet = append(toGet, rf)
		} else {
			// конфликт: локальный новее, а хеши разные - сохраняем копию удалённого
			conflictPath := strings.TrimSuffix(rf.Path, filepath.Ext(rf.Path)) +
				fmt.Sprintf(".conflict-%d", time.Now().Unix()) + filepath.Ext(rf.Path)
			log.Printf("Conflict on %s -> will save remote as %s", rf.Path, conflictPath)
			// скачиваем по оригинальному пути, а потом переименуем
			if err := downloadFile(peer, key, rf.Path, vault); err != nil {
				return err
			}
			old := filepath.Join(vault, filepath.FromSlash(rf.Path))
			newp := filepath.Join(vault, filepath.FromSlash(conflictPath))
			if err := os.MkdirAll(filepath.Dir(newp), 0o755); err != nil {
				return err
			}
			if err := os.Rename(old, newp); err != nil {
				return err
			}
			continue
		}
	}

	log.Printf("Need to download %d file(s)", len(toGet))
	for i, f := range toGet {
		log.Printf("[%d/%d] %s", i+1, len(toGet), f.Path)
		if err := downloadFile(peer, key, f.Path, vault); err != nil {
			return err
		}
	}
	log.Println("Pull finished.")
	return nil
}

func runPush(vault, peer, key string) error {
	// простая реализация: отправить все локальные, которые новее удалённых
	log.Println("Fetching remote manifest...")
	rm, err := fetchManifest(peer, key)
	if err != nil {
		return err
	}
	ridx := make(map[string]FileEntry, len(rm.Files))
	for _, f := range rm.Files {
		ridx[f.Path] = f
	}
	lm, err := buildManifest(vault, "local")
	if err != nil {
		return err
	}

	client := http.DefaultClient
	base := strings.TrimRight(peer, "/")

	var pushed int
	for _, lf := range lm.Files {
		rf, ok := ridx[lf.Path]
		shouldPush := !ok || (lf.SHA256 != rf.SHA256 && lf.ModTime > rf.ModTime)
		if !shouldPush {
			continue
		}
		full := filepath.Join(vault, filepath.FromSlash(lf.Path))
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		req, _ := http.NewRequest(http.MethodPut, base+"/file?path="+lf.Path, bytes.NewReader(data))
		if key != "" {
			req.Header.Set("X-Key", key)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("push %s failed: %s", lf.Path, resp.Status)
		}
		pushed++
		log.Printf("Pushed %s", lf.Path)
	}
	log.Printf("Push finished. Updated %d file(s).", pushed)
	return nil
}

func main() {
	log.SetFlags(0)

	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		vault := fs.String("vault", ".", "path to Obsidian vault")
		addr := fs.String("addr", ":8361", "listen address")
		key := fs.String("key", "", "shared secret (X-Key)")
		device := fs.String("device", "obs-transfer", "device name")
		_ = fs.Parse(os.Args[2:])
		if err := runServer(*vault, *addr, *key, *device); err != nil {
			log.Fatal(err)
		}
	case "pull":
		fs := flag.NewFlagSet("pull", flag.ExitOnError)
		vault := fs.String("vault", ".", "path to Obsidian vault")
		peer := fs.String("peer", "", "peer base URL, e.g. http://192.168.1.10:8361")
		key := fs.String("key", "", "shared secret (X-Key)")
		_ = fs.Parse(os.Args[2:])
		if *peer == "" {
			log.Fatal("peer is required")
		}
		if err := runPull(*vault, *peer, *key); err != nil {
			log.Fatal(err)
		}
	case "push":
		fs := flag.NewFlagSet("push", flag.ExitOnError)
		vault := fs.String("vault", ".", "path to Obsidian vault")
		peer := fs.String("peer", "", "peer base URL, e.g. http://192.168.1.10:8361")
		key := fs.String("key", "", "shared secret (X-Key)")
		_ = fs.Parse(os.Args[2:])
		if *peer == "" {
			log.Fatal("peer is required")
		}
		if err := runPush(*vault, *peer, *key); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Println("Usage:")
		fmt.Println("  go run . serve -vault /path/to/vault -addr :8361 -key SECRET")
		fmt.Println("  go run . pull  -vault /path/to/vault -peer http://IP:8361 -key SECRET")
		fmt.Println("  go run . push  -vault /path/to/vault -peer http://IP:8361 -key SECRET")
	}
	os.Exit(0)
}