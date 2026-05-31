// KernelEye Agent — eBPF/XDP monitoring and remediation daemon for Linux.
//
// File organization (all files share package main):
//
//   Core runtime:
//     main.go              — Entry point, event loop, shutdown
//     config.go            — CLI/env configuration
//     grpc.go              — TLS/mTLS transport, registration
//     ebpf.go              — Traffic probe eBPF loading
//     tc.go                — TC bandwidth hooks
//
//   Aggregator (prefix: aggregator_*, flush_*, safemap, buffer, history):
//     aggregator.go        — Aggregator struct, construct/destroy
//     aggregator_event.go  — ProcessEvent, traffic filtering
//     aggregator_connect.go — gRPC connection, reconnection, heartbeat
//     aggregator_report.go — Block reporting, blocklist sync
//     aggregator_whitelist.go — IP whitelist management
//     flush.go             — Batch submission to backend
//     flush_proto.go       — Protobuf conversion helpers
//     safemap.go           — Thread-safe IP statistics map
//     buffer.go            — SQLite buffer for fault tolerance
//     history_store.go     — Persistent history for scoring
//
//   Block command client (prefix: block_command_*):
//     block_command_client.go — Stream setup, lifecycle
//     block_command_verify.go — HMAC signature verification, dispatch
//     block_command_sync.go   — Reconciliation, blocklist sync, nonce persistence
//
//   Shared utilities:
//     types.go             — Event and statistics structs
//     network.go           — IP conversion, public IP detection
//     logger.go            — Zap logger initialization
//     audit.go             — Structured JSON audit logging
//     map_integrity.go     — eBPF map identity verification and attestation
//     apikey.go            — Client-side API key helpers
//     boottime.go          — System boot time detection
//     cli.go               — CLI-only operations (version, flush, list)
//
//   Remediation subpackage:
//     remediation/         — XDP, ipset, hybrid blocking; analyzer; map trust model
package main
