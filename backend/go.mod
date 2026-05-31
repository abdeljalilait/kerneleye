module github.com/kerneleye/backend

go 1.25.5

require (
	github.com/gofiber/contrib/websocket v1.3.4
	github.com/gofiber/fiber/v2 v2.52.6
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.6
	github.com/joho/godotenv v1.5.1
	github.com/kerneleye/proto v0.0.0-00010101000000-000000000000
	github.com/kerneleye/shared/cmdsigning v0.0.0
	github.com/kerneleye/shared/scoring v0.1.0
	github.com/oschwald/maxminddb-golang/v2 v2.1.1
	github.com/redis/go-redis/v9 v9.18.0
	golang.org/x/crypto v0.46.0 // indirect
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fasthttp/websocket v1.5.8 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/savsgio/gotils v0.0.0-20240303185622-093b76447511 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.52.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251022142026-3a174f9686a8 // indirect
)

replace github.com/kerneleye/proto => ../proto/gen/go

replace github.com/kerneleye/shared/cmdsigning => ../shared/cmdsigning

replace github.com/kerneleye/shared/scoring => ../shared/scoring
