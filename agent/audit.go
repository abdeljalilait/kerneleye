package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry represents a single audit log record for remediation actions.
type AuditEntry struct {
	Timestamp      string `json:"timestamp"`
	Action         string `json:"action"`
	IP             string `json:"ip"`
	Reason         string `json:"reason"`
	DurationSec    int64  `json:"duration_seconds,omitempty"`
	Source         string `json:"source"`
	SignatureValid bool   `json:"signature_valid"`
	Error          string `json:"error,omitempty"`
}

var (
	auditLogger   *AuditLogger
	auditInitOnce sync.Once
)

// AuditLogger writes structured JSON audit logs for all block/unblock/ratelimit actions.
type AuditLogger struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

func getAuditLogger() *AuditLogger {
	auditInitOnce.Do(func() {
		var err error
		auditLogger, err = newAuditLogger()
		if err != nil {
			Logger.Errorf("Audit logging unavailable: %v", err)
		}
	})
	return auditLogger
}

func auditLogPath() string {
	if p := os.Getenv("KERNELEYE_AUDIT_LOG"); p != "" {
		return p
	}
	return filepath.Join("/var/log", "kerneleye-audit.log")
}

func newAuditLogger() (*AuditLogger, error) {
	path := auditLogPath()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log %s: %w", path, err)
	}
	Logger.Infof("📝 Audit logging to %s", path)
	return &AuditLogger{f: f, enc: json.NewEncoder(f)}, nil
}

func (a *AuditLogger) log(entry AuditEntry) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	if err := a.enc.Encode(entry); err != nil {
		Logger.Errorf("Failed to write audit entry: %v", err)
	}
}

func (a *AuditLogger) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.f.Close()
}

// AuditLogCommandAccepted records a command that passed verification and was executed.
func AuditLogCommandAccepted(action, ip, reason string, durationSeconds int64) {
	getAuditLogger().log(AuditEntry{
		Action:         action,
		IP:             ip,
		Reason:         reason,
		DurationSec:    durationSeconds,
		Source:         "backend_command",
		SignatureValid: true,
	})
}

// AuditLogCommandRejected records a command that failed verification and was NOT executed.
func AuditLogCommandRejected(action, ip, reason string, err error) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	getAuditLogger().log(AuditEntry{
		Action:         action,
		IP:             ip,
		Reason:         reason,
		Source:         "backend_command",
		SignatureValid: false,
		Error:          errStr,
	})
}

// AuditLogLocalBlock records a locally-initiated block (auto-blocker or manual).
func AuditLogLocalBlock(action, ip, reason string, durationSeconds int64) {
	getAuditLogger().log(AuditEntry{
		Action:         action,
		IP:             ip,
		Reason:         reason,
		DurationSec:    durationSeconds,
		Source:         "local_auto_block",
		SignatureValid: true,
	})
}

// AuditLogLocalUnblock records a locally-initiated unblock.
func AuditLogLocalUnblock(action, ip, reason string) {
	getAuditLogger().log(AuditEntry{
		Action:         action,
		IP:             ip,
		Reason:         reason,
		Source:         "local_auto_unblock",
		SignatureValid: true,
	})
}

// CloseAuditLog flushes and closes the audit log file.
func CloseAuditLog() {
	al := getAuditLogger()
	if al != nil {
		al.close()
	}
}
