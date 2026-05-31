package remediation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Map listing, flushing, and blocked packet reading for the XDP firewall.
// Provides read-only access to pinned maps for CLI inspection and
// real-time blocked-packet event streaming from the XDP ring buffer.

// real-time blocked-packet event streaming from the XDP ring buffer.

func (r *XDPRemediator) StartBlockedPacketReader() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.attached || r.objs == nil || r.objs.XdpBlockEvents == nil {
		return errNotAttached
	}

	if r.ringbufReader != nil {
		return nil // Already started
	}

	reader, err := ringbuf.NewReader(r.objs.XdpBlockEvents)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	r.ringbufReader = reader
	r.ringbufCancel = make(chan struct{})
	r.ringbufWg.Add(1)

	go r.readBlockedPackets()

	logger.Infof("✅ XDP blocked packet reader started")
	return nil
}

// StopBlockedPacketReader stops the ring buffer reader
func (r *XDPRemediator) StopBlockedPacketReader() error {
	r.mu.Lock()
	if r.ringbufReader == nil {
		r.mu.Unlock()
		return nil
	}

	close(r.ringbufCancel)
	reader := r.ringbufReader
	r.ringbufReader = nil
	r.mu.Unlock()

	// Close the reader to unblock any pending Read() call
	if err := reader.Close(); err != nil {
		logger.Warnf("Failed to close ring buffer reader: %v", err)
	}

	// Wait for the goroutine to finish
	r.ringbufWg.Wait()

	logger.Infof("✅ XDP blocked packet reader stopped")
	return nil
}

// readBlockedPackets is the goroutine that reads from the ring buffer
func (r *XDPRemediator) readBlockedPackets() {
	defer r.ringbufWg.Done()

	for {
		select {
		case <-r.ringbufCancel:
			return
		default:
		}

		record, err := r.ringbufReader.Read()
		if err != nil {
			select {
			case <-r.ringbufCancel:
				return
			default:
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				logger.Warnf("Ring buffer read error: %v", err)
				continue
			}
		}

		// Parse the blocked packet event
		if len(record.RawSample) < 32 {
			continue // Invalid sample size
		}

		var event BlockedPacketEvent
		// Parse the event from the ring buffer
		// C struct layout: src_ip (4), src_ip6 (16), ip_version (1), dest_port (2), protocol (1), reason (1), timestamp (8)
		event.SrcIP = binary.LittleEndian.Uint32(record.RawSample[0:4])
		copy(event.SrcIP6[:], record.RawSample[4:20])
		event.IPVersion = record.RawSample[20]
		event.DestPort = binary.LittleEndian.Uint16(record.RawSample[21:23])
		event.Protocol = record.RawSample[23]
		event.Reason = record.RawSample[24]
		event.Timestamp = binary.LittleEndian.Uint64(record.RawSample[25:33])

		// Convert IP to string
		var ipStr string
		if event.IPVersion == 6 {
			ip := net.IP(event.SrcIP6[:])
			ipStr = ip.String()
		} else {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, event.SrcIP)
			ipStr = ip.String()
		}

		// Call the callback if set
		if r.OnBlockedPacket != nil {
			r.OnBlockedPacket(ipStr, event.DestPort, event.Protocol, event.Reason)
		}
	}
}

// Unblock removes IP from blocklist
func (r *XDPRemediator) ListCurrentlyBlocked() ([]BlockedEntry, error) {
	v4Map, v6Map, cleanup, err := r.openBlocklistMaps()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	now := uint64(monotonicNs())
	var entries []BlockedEntry

	// IPv4 — key is BigEndian uint32, value is blockEntry
	var k4 uint32
	var v4val blockEntry
	iter4 := v4Map.Iterate()
	for iter4.Next(&k4, &v4val) {
		if v4val.ExpiresNs != 0 && v4val.ExpiresNs < now {
			continue // expired
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, k4)
		entries = append(entries, BlockedEntry{
			IP:        net.IP(b),
			BlockType: BlockTypeBlocklist,
			Version:   4,
		})
	}
	if err := iter4.Err(); err != nil {
		return nil, fmt.Errorf("iterating xdp_blocklist: %w", err)
	}

	// IPv6 — key is [16]byte, value is blockEntry
	var k6 [16]byte
	var v6val blockEntry
	iter6 := v6Map.Iterate()
	for iter6.Next(&k6, &v6val) {
		if v6val.ExpiresNs != 0 && v6val.ExpiresNs < now {
			continue // expired
		}
		ip := make(net.IP, 16)
		copy(ip, k6[:])
		entries = append(entries, BlockedEntry{
			IP:        ip,
			BlockType: BlockTypeBlocklist,
			Version:   6,
		})
	}
	if err := iter6.Err(); err != nil {
		return nil, fmt.Errorf("iterating xdp_blocklist_v6: %w", err)
	}

	return entries, nil
}

// FlushBlocklistMaps removes all entries from the XDP blocklist BPF maps.
// Works both on a live (attached) remediator and standalone (opens pinned maps
// from /sys/fs/bpf/kerneleye). This is what --flush-blocklists uses.
func (r *XDPRemediator) FlushBlocklistMaps() error {
	v4Map, v6Map, cleanup, err := r.openBlocklistMaps()
	if err != nil {
		return fmt.Errorf("open XDP blocklist maps: %w", err)
	}
	defer cleanup()

	// Collect then delete — cannot delete while iterating.
	var v4Keys []uint32
	var k4 uint32
	var v4val blockEntry
	iter4 := v4Map.Iterate()
	for iter4.Next(&k4, &v4val) {
		v4Keys = append(v4Keys, k4)
	}
	if err := iter4.Err(); err != nil {
		return fmt.Errorf("iterating xdp_blocklist: %w", err)
	}
	for _, k := range v4Keys {
		_ = v4Map.Delete(k)
	}

	var v6Keys [][16]byte
	var k6 [16]byte
	var v6val blockEntry
	iter6 := v6Map.Iterate()
	for iter6.Next(&k6, &v6val) {
		v6Keys = append(v6Keys, k6)
	}
	if err := iter6.Err(); err != nil {
		return fmt.Errorf("iterating xdp_blocklist_v6: %w", err)
	}
	for _, k := range v6Keys {
		_ = v6Map.Delete(k)
	}

	logger.Infof("🧹 XDP blocklist flushed (%d IPv4, %d IPv6 entries removed)",
		len(v4Keys), len(v6Keys))
	return nil
}

// openBlocklistMaps returns references to xdp_blocklist and xdp_blocklist_v6.
// If the remediator is attached and live, the existing map handles are returned
// directly (no-op cleanup). Otherwise, the pinned maps are opened from the BPF
// filesystem and the caller must call cleanup() to close them.
func (r *XDPRemediator) openBlocklistMaps() (v4Map, v6Map *ebpf.Map, cleanup func(), err error) {
	r.mu.RLock()
	if r.attached && r.objs != nil {
		v4 := r.objs.XdpBlocklist
		v6 := r.objs.XdpBlocklistV6
		r.mu.RUnlock()
		return v4, v6, func() {}, nil
	}
	pinPath := r.pinPath
	r.mu.RUnlock()

	readOnly := &ebpf.LoadPinOptions{ReadOnly: true}
	v4, err2 := ebpf.LoadPinnedMap(filepath.Join(pinPath, "xdp_blocklist"), readOnly)
	if err2 != nil {
		return nil, nil, func() {}, fmt.Errorf("open pinned xdp_blocklist: %w", err2)
	}
	v6, err2 := ebpf.LoadPinnedMap(filepath.Join(pinPath, "xdp_blocklist_v6"), readOnly)
	if err2 != nil {
		v4.Close()
		return nil, nil, func() {}, fmt.Errorf("open pinned xdp_blocklist_v6: %w", err2)
	}
	return v4, v6, func() { v4.Close(); v6.Close() }, nil
}

// cleanupMapV6 removes expired entries from an IPv6 blocklist map
