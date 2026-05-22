import { useState, useEffect, useRef } from 'react'
import { Card, Typography, Badge, Space, Tag, theme } from 'antd'
import { useWebSocket } from '../context/WebSocketContext'
import { Radio, Activity, Terminal } from 'lucide-react'

const { Text } = Typography

interface TrafficLog {
  id: string
  source_ip: string
  destination_ip: string
  destination_port: number
  protocol: string
  direction: string
  syn_count: number
  server_ip: string
  server_hostname: string
  timestamp: string
  severity: 'normal' | 'suspicious' | 'critical'
  is_blocked?: boolean
  block_reason?: 'blocklist' | 'cidr' | 'rate_limit' | 'unknown'
}

const severityColors: Record<string, string> = {
  critical: '#ef4444',
  suspicious: '#f59e0b',
  normal: '#10b981',
}

export default function LiveStream() {
  const [logs, setLogs] = useState<TrafficLog[]>([])
  const { lastMessage } = useWebSocket()
  const scrollRef = useRef<HTMLDivElement>(null)
  const { token } = theme.useToken()

  useEffect(() => {
    if (lastMessage?.type === 'new_traffic') {
      const log = lastMessage.data as any
      const synCount = log.syn_count || 0
      let severity: 'normal' | 'suspicious' | 'critical' = 'normal'
      if (synCount > 50) severity = 'critical'
      else if (synCount > 10) severity = 'suspicious'

      setLogs(prev => {
        const newLogs = [
          ...prev,
          {
            id: `${Date.now()}-${Math.random()}`,
            source_ip: log.source_ip,
            destination_ip: log.destination_ip || log.server_ip || '',
            destination_port: log.destination_port,
            protocol: log.protocol || 'TCP',
            direction: log.direction || 'inbound',
            syn_count: synCount,
            server_ip: log.server_ip || '',
            server_hostname: log.server_hostname || '',
            timestamp: new Date().toLocaleTimeString([], { hour12: false }),
            severity,
          },
        ]
        return newLogs.slice(-100)
      })
    } else if (lastMessage?.type === 'blocked_packet') {
      const data = lastMessage.data as any
      setLogs(prev => {
        const newLogs = [
          ...prev,
          {
            id: `${Date.now()}-${Math.random()}`,
            source_ip: data.source_ip,
            destination_ip: '',
            destination_port: data.destination_port || 0,
            protocol: data.protocol || 'TCP',
            direction: 'inbound',
            syn_count: 0,
            server_ip: '',
            server_hostname: data.server_hostname || '',
            timestamp: new Date().toLocaleTimeString([], { hour12: false }),
            severity: 'critical' as const,
            is_blocked: true,
            block_reason: data.reason || 'unknown',
          },
        ]
        return newLogs.slice(-100)
      })
    }
  }, [lastMessage])

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [logs])

  return (
    <Card
      styles={{ body: { padding: 0 } }}
      title={
        <Space size={12}>
          <div
            style={{
              width: 36, height: 36,
              background: `rgba(16, 185, 129, 0.12)`,
              borderRadius: token.borderRadius,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Radio size={18} color={token.colorSuccess} />
          </div>
          <div>
            <Text strong style={{ fontSize: 16 }}>Live Stream</Text>
            <br />
            <Space size={8}>
              <Badge status="processing" color={token.colorSuccess} />
              <Text style={{ fontSize: 11, color: token.colorTextTertiary }}>Real-time traffic</Text>
            </Space>
          </div>
        </Space>
      }
      extra={
        <Tag
          style={{
            background: token.colorFillAlter,
            border: `1px solid ${token.colorBorderSecondary}`,
            color: token.colorTextTertiary,
            fontSize: 11,
          }}
        >
          {logs.length} events
        </Tag>
      }
    >
      {/* Terminal header bar */}
      <div
        style={{
          padding: '10px 16px',
          background: token.colorFillAlter,
          borderBottom: `1px solid ${token.colorBorderSecondary}`,
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}
      >
        <Terminal size={14} color={token.colorTextTertiary} />
        <Text style={{ fontSize: 11, color: token.colorTextTertiary, fontFamily: 'monospace' }}>
          tcpdump -i eth0 -n
        </Text>
        <div style={{ flex: 1 }} />
        <Space size={8}>
          <Badge status="success" />
          <Text style={{ fontSize: 11, color: token.colorSuccess }}>CONNECTED</Text>
        </Space>
      </div>

      {/* Terminal content */}
      <div
        ref={scrollRef}
        style={{
          height: 320,
          overflowY: 'auto',
          padding: 16,
          background: '#09090b',
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 12,
        }}
      >
        {logs.length === 0 ? (
          <div
            style={{
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              color: token.colorTextTertiary,
            }}
          >
            <Activity size={32} color={token.colorTextQuaternary} style={{ opacity: 0.3, marginBottom: 12 }} />
            <Text style={{ color: token.colorTextTertiary }}>Waiting for traffic...</Text>
            <Text style={{ color: token.colorTextQuaternary, fontSize: 11, marginTop: 4 }}>
              Events will appear here in real-time
            </Text>
          </div>
        ) : (
          logs.map((log, index) => {
            const color = severityColors[log.severity]
            return (
              <div
                key={log.id}
                style={{
                  marginBottom: 6,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  opacity: 1 - (logs.length - index - 1) * 0.008,
                }}
              >
                <span style={{ color: token.colorTextQuaternary, minWidth: 60, fontSize: 11 }}>
                  {log.timestamp}
                </span>

                <Tag
                  style={{
                    margin: 0,
                    fontSize: 10,
                    fontWeight: 600,
                    background: log.is_blocked ? 'rgba(239,68,68,0.25)' : `${color}20`,
                    color: log.is_blocked ? '#ef4444' : color,
                    border: 'none',
                  }}
                >
                  {log.is_blocked
                    ? `BLOCK${log.block_reason ? ` (${log.block_reason.toUpperCase()})` : ''}`
                    : log.severity === 'critical'
                      ? 'FLAG'
                      : log.severity === 'suspicious'
                        ? 'WARN'
                        : 'ALLOW'}
                </Tag>

                <span style={{ color: token.colorTextSecondary }}>{log.source_ip}</span>
                <span style={{ color: token.colorTextQuaternary }}>→</span>
                <span style={{ color: token.colorWarning }}>{log.destination_ip}:{log.destination_port}</span>

                <Tag
                  style={{
                    margin: 0,
                    fontSize: 10,
                    background: token.colorPrimaryBg,
                    color: token.colorPrimary,
                    border: 'none',
                  }}
                >
                  {log.direction === 'outbound' ? '↑ OUT' : '↓ IN'}
                </Tag>

                <span style={{ color: token.colorTextQuaternary }}>[{log.protocol}]</span>
              </div>
            )
          })
        )}
      </div>
    </Card>
  )
}
