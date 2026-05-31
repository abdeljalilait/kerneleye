package main

import (
	"net"
)

// Aggregator whitelist management.
// Provides per-IP whitelisting to allow traffic from
// trusted sources to bypass threat scoring and blocking.

func (a *Aggregator) isWhitelistedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	a.whitelistMu.RLock()
	defer a.whitelistMu.RUnlock()
	return a.whitelistedIPs[ip.String()]
}

func (a *Aggregator) IsWhitelistedIPString(ip string) bool {
	key := normalizeIPString(ip)
	if key == "" {
		return false
	}
	a.whitelistMu.RLock()
	defer a.whitelistMu.RUnlock()
	return a.whitelistedIPs[key]
}

func (a *Aggregator) SetWhitelistIP(ip string, whitelisted bool) {
	key := normalizeIPString(ip)
	if key == "" {
		return
	}
	a.whitelistMu.Lock()
	defer a.whitelistMu.Unlock()
	if whitelisted {
		a.whitelistedIPs[key] = true
		return
	}
	delete(a.whitelistedIPs, key)
}

// ProcessEvent processes a single eBPF event (thread-safe via SafeStats)
