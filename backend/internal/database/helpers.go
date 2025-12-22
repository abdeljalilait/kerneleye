package database

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Helper functions to convert between types

func ToPgUUID(s string) pgtype.UUID {
	u, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{
		Bytes: u,
		Valid: true,
	}
}

func FromPgUUID(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func ToPgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{
		String: s,
		Valid:  true,
	}
}

func ToPgBool(b bool) pgtype.Bool {
	return pgtype.Bool{
		Bool:  b,
		Valid: true,
	}
}

func ToPgTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{
		Time:  t,
		Valid: true,
	}
}

func ToNetAddr(s string) (netip.Addr, error) {
	return netip.ParseAddr(s)
}

func GenerateUUID() string {
	return uuid.New().String()
}
