module github.com/kerneleye/agent

go 1.25.5

require (
	github.com/cilium/ebpf v0.12.3
	github.com/kerneleye/proto v0.0.0-00010101000000-000000000000
	github.com/mattn/go-sqlite3 v1.14.32
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.39.0
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect
	golang.org/x/net v0.46.1-0.20251013234738-63d1a5100f82 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251022142026-3a174f9686a8 // indirect
)

replace github.com/kerneleye/proto => ../proto/gen/go
