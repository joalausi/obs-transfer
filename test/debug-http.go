package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    log.SetFlags(0)

    http.HandleFunc("/manifest", func(w http.ResponseWriter, r *http.Request) {
        log.Printf("DEBUG: got /manifest from %s", r.RemoteAddr)
        fmt.Fprintln(w, "ok from debug server")
    })

    log.Println("DEBUG: listening on 0.0.0.0:8361")
    log.Fatal(http.ListenAndServe("0.0.0.0:8361", nil))
}
