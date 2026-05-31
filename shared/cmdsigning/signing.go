// Package cmdsigning provides HMAC-based command signing and verification
// for KernelEye agent/backend block commands.
//
// Commands are signed with HMAC-SHA256 using a shared secret key.
// A monotonic nonce is included to prevent replay attacks.
package cmdsigning

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
)

var (
	ErrInvalidSignature = errors.New("invalid command signature")
	ErrReplayedNonce    = errors.New("replayed command nonce")
	ErrMissingNonce     = errors.New("missing command nonce")
)

// Key returns the command signing key from the environment variable
// CMD_SIGNING_KEY. If not set, returns an empty string and signing/verification
// is effectively disabled (unsigned commands are accepted, but a warning is logged).
func Key() string {
	return os.Getenv("CMD_SIGNING_KEY")
}

// Sign computes an HMAC-SHA256 signature over the canonical representation
// of a command. The nonce must be included in the payload to bind signature to nonce.
// Returns the signature bytes.
func Sign(key string, nonce int64, payload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	binary.Write(mac, binary.BigEndian, nonce)
	mac.Write(payload)
	return mac.Sum(nil)
}

// Verify checks the HMAC-SHA256 signature of a command.
// Returns nil if valid, ErrInvalidSignature if the signature does not match,
// or ErrMissingNonce if no signature is present (unsigned command).
func Verify(key string, nonce int64, payload, signature []byte) error {
	if len(signature) == 0 {
		return ErrMissingNonce
	}
	if nonce <= 0 {
		return ErrMissingNonce
	}
	expected := Sign(key, nonce, payload)
	if !hmac.Equal(expected, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// NonceTracker tracks the last observed nonce to detect replay attacks.
type NonceTracker struct {
	mu       sync.Mutex
	lastSeen int64
}

// Check validates that the given nonce is strictly greater than the last
// observed nonce. Returns true if the nonce is fresh. The caller should then
// call Record() to persist the nonce after the command is validated.
func (t *NonceTracker) Check(nonce int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return nonce > t.lastSeen
}

// Record persists the nonce as the last observed value.
func (t *NonceTracker) Record(nonce int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if nonce > t.lastSeen {
		t.lastSeen = nonce
	}
}

// Last returns the last observed nonce (for debugging/info).
func (t *NonceTracker) Last() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastSeen
}

// BuildCanonicalPayload serializes command fields into a canonical byte
// representation for signing. The format is deterministic: each field is
// prefixed with its length and separated by null bytes.
// Fields included: action(4B) + ip(4B/16B) + duration(8B) + reason + block_id + issued_at
// signature(NOT included) + nonce(NOT signed separately — included in HMAC payload).
func BuildCanonicalPayload(action int32, ipAddress string, durationSeconds int64, reason, blockID string, issuedAtUnixNano int64) []byte {
	var buf []byte

	// Action (32-bit)
	buf = append(buf, byte(action>>24), byte(action>>16), byte(action>>8), byte(action))

	// IP address (variable length prefix + bytes)
	ipBytes := []byte(ipAddress)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(ipBytes)))
	buf = append(buf, ipBytes...)

	// Duration (64-bit)
	buf = binary.BigEndian.AppendUint64(buf, uint64(durationSeconds))

	// Reason (length prefix + bytes)
	reasonBytes := []byte(reason)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(reasonBytes)))
	buf = append(buf, reasonBytes...)

	// Block ID (length prefix + bytes)
	blockIDBytes := []byte(blockID)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(blockIDBytes)))
	buf = append(buf, blockIDBytes...)

	// Issued at (64-bit unix nano)
	buf = binary.BigEndian.AppendUint64(buf, uint64(issuedAtUnixNano))

	return buf
}

// MustGetenvInt64 reads an int64 env var, returning a default if unset or invalid.
func MustGetenvInt64(key string, defaultVal int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		// Fallback to default on parse error
		return defaultVal
	}
	return n
}

// BuildBlockListPayload creates a canonical byte representation of a block list
// for signing. Each entry is serialized as: ip(null)type(null)duration(null)reason(null).
// Entries are separated by newlines.
func BuildBlockListPayload(entries []BlockListEntry) []byte {
	var buf []byte
	for i, e := range entries {
		if i > 0 {
			buf = append(buf, '\n')
		}
		buf = append(buf, e.IPAddress...)
		buf = append(buf, 0)
		buf = append(buf, byte(e.BlockType))
		buf = append(buf, 0)
		buf = binary.BigEndian.AppendUint64(buf, uint64(e.DurationSeconds))
		buf = append(buf, 0)
		buf = append(buf, e.Reason...)
	}
	return buf
}

// BlockListEntry is a simplified representation for signing block lists.
type BlockListEntry struct {
	IPAddress       string
	DurationSeconds int64
	Reason          string
	BlockType       int32
}

// Logf is a logging function that can be set by consumers.
// Default to fmt.Fprintf to os.Stderr.
var Logf = func(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
