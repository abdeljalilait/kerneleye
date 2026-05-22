import { useState, useCallback, useRef, useEffect } from 'react'
import { Badge, Button, Card, Space, Tag, Tooltip, Typography, theme } from 'antd'
import { Activity, Trash2, WifiOff } from 'lucide-react'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import { useWebSocket } from '../context/WebSocketContext'
import { useWebSocketEvent } from '../hooks/useWebSocketEvent'

dayjs.extend(relativeTime)

const { Text } = Typography
const MAX_EVENTS = 100

interface NewBlockData {
  id?: string
  block_id?: string
  ip_address: string
  server_id?: string
  server_name?: string
  threat_score?: number
  threat_level?: string
  reasons?: string[]
  reason?: string
  threat_type?: string
  country_code?: string
  country_name?: string
  country?: string
  city?: string
  is_datacenter?: boolean
  blocked_at?: string
}

interface LiveBlockEvent extends NewBlockData {
  _key: string
  _ts: number
}

const countryFlag = (code?: string) => {
  if (!code || code.length !== 2) return '🌐'
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => c.charCodeAt(0) + 127397))
}

const reasonLabels: Record<string, string> = {
  service_abuse: 'Service Abuse',
  port_scan: 'Port Scan',
  syn_flood: 'SYN Flood',
  ddos: 'DDoS',
  brute_force: 'Brute Force',
  connection_burst: 'Conn. Burst',
  failed_handshake: 'Failed Handshake',
  ssh_bruteforce: 'SSH BF',
  http_flood: 'HTTP Flood',
  dns_amplification: 'DNS Amp',
  ipset_block: 'IPSet',
  ipset_ratelimit: 'IPSet RL',
  xdp_block: 'XDP',
}

const reasonLabel = (r: string) =>
  reasonLabels[r] || r.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())

const reasonColor = (r: string) => {
  switch (r) {
    case 'syn_flood': case 'ddos': case 'http_flood': case 'ipset_block': case 'xdp_block': return 'red'
    case 'port_scan': return 'orange'
    case 'service_abuse': case 'brute_force': case 'ssh_bruteforce': return 'volcano'
    case 'connection_burst': case 'ipset_ratelimit': return 'gold'
    case 'failed_handshake': return 'purple'
    default: return 'default'
  }
}

const normalizeReason = (reason: string) => reason.toLowerCase().trim()

const scoreColor = (score: number) => {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f59e0b'
  if (score >= 30) return '#eab308'
  return '#10b981'
}

export default function LiveBlockFeed() {
  const { isConnected } = useWebSocket()
  const [events, setEvents] = useState<LiveBlockEvent[]>([])
  const [flashKey, setFlashKey] = useState<string | null>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const seenIds = useRef(new Set<string>())
  const { token } = theme.useToken()

  const handleNewBlock = useCallback((data: NewBlockData) => {
    const reasons = data.reasons && data.reasons.length > 0
      ? data.reasons
      : data.reason
        ? [data.reason]
        : data.threat_type
          ? [data.threat_type]
          : []
    const key = data.id || data.block_id || `${data.ip_address}-${Date.now()}`
    if (seenIds.current.has(key)) return
    seenIds.current.add(key)

    const event: LiveBlockEvent = {
      ...data,
      id: data.id || data.block_id,
      reasons,
      country_name: data.country_name || data.country,
      _key: key,
      _ts: Date.now(),
    }
    setEvents(prev => [event, ...prev].slice(0, MAX_EVENTS))
    setFlashKey(key)
    setTimeout(() => setFlashKey(null), 1200)
  }, [])

  useWebSocketEvent<NewBlockData>('new_block', handleNewBlock)

  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = 0
    }
  }, [events.length])

  const handleClear = () => {
    setEvents([])
    seenIds.current.clear()
  }

  return (
    <Card
      styles={{ body: { padding: '12px 16px' } }}
      style={{ marginBottom: 24 }}
      title={
        <Space>
          <Activity size={16} style={{ color: isConnected ? token.colorSuccess : token.colorTextQuaternary }} />
          <Text strong style={{ fontSize: 14 }}>Live Block Feed</Text>
          <Badge
            status={isConnected ? 'processing' : 'default'}
            color={isConnected ? token.colorSuccess : token.colorTextQuaternary}
            text={
              <Text style={{ color: isConnected ? token.colorSuccess : token.colorTextQuaternary, fontSize: 12 }}>
                {isConnected ? 'Connected' : 'Disconnected'}
              </Text>
            }
          />
          {events.length > 0 && <Tag style={{ fontSize: 11 }}>{events.length} event{events.length !== 1 ? 's' : ''}</Tag>}
        </Space>
      }
      extra={
        events.length > 0 && (
          <Tooltip title="Clear feed">
            <Button size="small" icon={<Trash2 size={13} />} onClick={handleClear} />
          </Tooltip>
        )
      }
    >
      {!isConnected && events.length === 0 ? (
        <div style={{ padding: '12px 0', textAlign: 'center' }}>
          <WifiOff size={20} style={{ color: token.colorTextQuaternary, marginBottom: 6 }} />
          <br />
          <Text type="secondary" style={{ fontSize: 13 }}>
            WebSocket disconnected — live events will appear here when connected
          </Text>
        </div>
      ) : events.length === 0 ? (
        <div style={{ padding: '12px 0', textAlign: 'center' }}>
          <Badge status="success" />
          <br />
          <Text type="secondary" style={{ fontSize: 13 }}>Waiting for new block events…</Text>
        </div>
      ) : (
        <div ref={listRef} style={{ maxHeight: 320, overflowY: 'auto', overflowX: 'hidden' }}>
          {events.map(evt => (
            <div
              key={evt._key}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '7px 4px',
                borderBottom: `1px solid ${token.colorBorderSecondary}`,
                borderRadius: 4,
                flexWrap: 'wrap',
                transition: 'background-color 0.3s',
                backgroundColor: evt._key === flashKey ? 'rgba(239, 68, 68, 0.12)' : 'transparent',
              }}
            >
              {/* Flag + IP */}
              <div style={{ minWidth: 150, display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 18, lineHeight: 1 }}>{countryFlag(evt.country_code)}</span>
                <Text style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 600 }}>
                  {evt.ip_address}
                </Text>
              </div>

              {/* Reasons */}
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', flex: 1, minWidth: 100 }}>
                {(evt.reasons && evt.reasons.length > 0 ? evt.reasons : ['unknown']).map(r => (
                  <Tag key={r} color={reasonColor(normalizeReason(r))} style={{ fontSize: 11, margin: 0 }}>
                    {reasonLabel(normalizeReason(r))}
                  </Tag>
                ))}
              </div>

              {/* Threat score */}
              {evt.threat_score !== undefined && (
                <Text
                  style={{
                    fontFamily: 'monospace',
                    fontSize: 13,
                    fontWeight: 700,
                    color: scoreColor(evt.threat_score),
                    minWidth: 32,
                    textAlign: 'right',
                  }}
                >
                  {evt.threat_score}
                </Text>
              )}

              {/* Server */}
              {evt.server_name && (
                <Text style={{ color: token.colorTextSecondary, fontSize: 12, minWidth: 80 }}>
                  {evt.server_name}
                </Text>
              )}

              {/* Country/City */}
              {(evt.country_name || evt.city) && (
                <Text style={{ color: token.colorTextTertiary, fontSize: 12, minWidth: 80 }}>
                  {[evt.city, evt.country_name].filter(Boolean).join(', ')}
                </Text>
              )}

              {/* Timestamp */}
              <Tooltip title={dayjs(evt.blocked_at || evt._ts).format('YYYY-MM-DD HH:mm:ss')}>
                <Text style={{ color: token.colorTextTertiary, fontSize: 11, marginLeft: 'auto', whiteSpace: 'nowrap' }}>
                  {dayjs(evt.blocked_at || evt._ts).fromNow()}
                </Text>
              </Tooltip>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
