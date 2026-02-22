package database

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
)

type CreateServerWithIDAndAPIKeyParams struct {
	ID          pgtype.UUID `json:"id"`
	UserID      pgtype.UUID `json:"user_id"`
	Hostname    string      `json:"hostname"`
	ApiKey      pgtype.Text `json:"api_key"`
	ClientToken pgtype.Text `json:"client_token"`
	IpAddress   *netip.Addr `json:"ip_address"`
	Status      string      `json:"status"`
}

const createServerWithIDAndAPIKey = `
INSERT INTO servers (id, user_id, hostname, api_key, client_token, ip_address, status, last_seen)
VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
RETURNING id, user_id, hostname, ip_address, api_key, status, last_seen, agent_version, metadata, created_at, updated_at, client_token, config
`

func (q *Queries) CreateServerWithIDAndAPIKey(ctx context.Context, arg CreateServerWithIDAndAPIKeyParams) (Server, error) {
	row := q.db.QueryRow(ctx, createServerWithIDAndAPIKey,
		arg.ID,
		arg.UserID,
		arg.Hostname,
		arg.ApiKey,
		arg.ClientToken,
		arg.IpAddress,
		arg.Status,
	)
	var i Server
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Hostname,
		&i.IpAddress,
		&i.ApiKey,
		&i.Status,
		&i.LastSeen,
		&i.AgentVersion,
		&i.Metadata,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.ClientToken,
		&i.Config,
	)
	return i, err
}
