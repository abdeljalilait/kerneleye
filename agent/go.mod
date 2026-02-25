module github.com/kerneleye/agent

go 1.25.5

require (
	github.com/cilium/ebpf v0.20.0
	github.com/joho/godotenv v1.5.1
	github.com/kerneleye/proto v0.0.0-00010101000000-000000000000
	github.com/kerneleye/shared/scoring v0.1.0
	github.com/vishvananda/netlink v1.3.1
	go.uber.org/zap v1.27.1
	golang.org/x/sys v0.39.0
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.11
	modernc.org/sqlite v1.46.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/net v0.46.1-0.20251013234738-63d1a5100f82 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251022142026-3a174f9686a8 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/kerneleye/proto => ../proto/gen/go

replace github.com/kerneleye/shared/scoring => ../shared/scoring
