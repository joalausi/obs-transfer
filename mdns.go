package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

// ====== server registration ======

func startMDNS(device, label, vault string, listenAddr string) (*zeroconf.Server, error) {
	// listenAddr формата ":8361" или "0.0.0.0:8361"
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("bad addr %q: %w", listenAddr, err)
	}
	port, _ := strconv.Atoi(portStr)

	txt := []string{
		"label=" + label,
		"device=" + device,
		"vault=" + filepath.Base(vault),
	}
	// name формата "device@vault"
	name := fmt.Sprintf("%s@%s", device, filepath.Base(vault))
	// _obs-transfer._tcp.local.
	return zeroconf.Register(name, "_obs-transfer._tcp", "local.", port, txt, nil)
}

// ====== service discovery (on client) ======

type Peer struct {
	Name   string // name in mDNS
	IP     string // IPv4
	Port   int
	Label  string
	Device string
	Vault  string
	URL    string // http://IP:port
}

func discoverPeers(label string, timeout time.Duration) ([]Peer, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, err
	}
	entries := make(chan *zeroconf.ServiceEntry)
	var peers []Peer

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	go func() {
		for e := range entries {
			kv := make(map[string]string)
			for _, t := range e.Text {
				if i := strings.IndexByte(t, '='); i > 0 {
					kv[t[:i]] = t[i+1:]
				}
			}
			if label != "" && kv["label"] != label {
				continue
			}
			ip := ""
			if len(e.AddrIPv4) > 0 {
				ip = e.AddrIPv4[0].String()
			} else if len(e.AddrIPv6) > 0 {
				// для IPv6 нужен формат [ip]:port
				ip = "[" + e.AddrIPv6[0].String() + "]"
			} else {
				continue
			}
			peers = append(peers, Peer{
				Name:   e.Instance,
				IP:     ip,
				Port:   e.Port,
				Label:  kv["label"],
				Device: kv["device"],
				Vault:  kv["vault"],
				URL:    "http://" + ip + ":" + strconv.Itoa(e.Port),
			})
		}
	}()

	if err := resolver.Browse(ctx, "_obs-transfer._tcp", "local.", entries); err != nil {
		return nil, err
	}
	<-ctx.Done() // timeout
	return peers, nil
}
