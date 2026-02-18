import { useState, useEffect, useRef } from 'react'
import { Card, Typography, Badge, Space, Tag } from 'antd'
import { useWebSocket } from '../context/WebSocketContext'
import { Radio, Activity, Terminal, Wifi } from 'lucide-react'

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
}

export default function LiveStream() {
  const [logs, setLogs] = useState<TrafficLog[]>([])
  const [isConnected, setIsConnected] = useState(true)
  const { lastMessage } = useWebSocket()
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (lastMessage?.type === 'new_traffic') {
      const log = lastMessage.data as any
      const synCount = log.syn_count || 0
      let severity: 'normal' | 'suspicious' | 'critical' = 'normal'
      if (synCount > 50) severity = 'critical'
      else if (synCount > 10) severity = 'suspicious'

      setLogs((prev: TrafficLog[]) => {
        const newLogs = [...prev, {
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
        }]
        return newLogs.slice(-100)
      })
    }
  }, [lastMessage])

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [logs])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return { text: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' }
      case 'suspicious':
        return { text: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' }
      default:
        return { text: '#10b981', bg: 'rgba(16, 185, 129, 0.15)' }
    }
  }

  return (
    <Card
      variant="borderless"
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        backdropFilter: 'blur(10px)',
        height: '100%',
      }}
      bodyStyle={{ padding: 0, height: '100%' }}
      title={
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Space size={12}>
            <div 
              style={{
                width: 36,
                height: 36,
                background: 'rgba(16, 185, 129, 0.15)',
                borderRadius: 10,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Radio size={18} color="#10b981" />
            </div>
            <div>
              <Text strong style={{ color: 'var(--text-primary)', fontSize: 16, display: 'block' }}>
                Live Stream
              </Text>
              <Space size={8}>
                <Badge 
                  status="processing" 
                  color="#10b981"
                  style={{ animation: 'pulse 2s infinite' }}
                />
                <Text style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
                  Real-time traffic
                </Text>
              </Space>
            </div>
          </Space>
          
          <Tag 
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-tertiary)',
              fontSize: 11,
            }}
          >
            {logs.length} events
          </Tag>
        </div>
      }
    >
      {/* Terminal Header */}
      <div 
        style={{
          padding: '12px 16px',
          background: 'var(--bg-tertiary)',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}
      >
        <Terminal size={14} color="var(--text-tertiary)" />
        <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
          tcpdump -i eth0 -n
        </Text>
        <div style={{ flex: 1 }} />
        <Space size={8}>
          <Wifi size={12} color="#10b981" />
          <Text style={{ fontSize: 11, color: '#10b981' }}>CONNECTED</Text>
        </Space>
      </div>

      {/* Terminal Content */}
      <div 
        ref={scrollRef}
        style={{ 
          height: 320, 
          overflowY: 'auto', 
          padding: 16,
          background: '#08080c',
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 12,
        }}
      >
        {logs.length === 0 ? (
          <div style={{ 
            height: '100%', 
            display: 'flex', 
            flexDirection: 'column',
            alignItems: 'center', 
            justifyContent: 'center',
            color: 'var(--text-tertiary)',
          }}>
            <div style={{ marginBottom: 12 }}>
              <Activity size={32} color="var(--text-muted)" opacity={0.3} />
            </div>
            <Text style={{ color: 'var(--text-tertiary)' }}>Waiting for traffic...</Text>
            <Text style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 4 }}>
              Events will appear here in real-time
            </Text>
          </div>
        ) : (
          logs.map((log, index) => {
            const colors = getSeverityColor(log.severity)
            return (
              <div 
                key={log.id}
                style={{ 
                  marginBottom: 6, 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: 10,
                  opacity: 1 - (logs.length - index - 1) * 0.008,
                  animation: 'fadeIn 0.2s ease',
                }}
              >
                <span style={{ color: '#475569', minWidth: 60, fontSize: 11 }}>
                  {log.timestamp}
                </span>
                
                <Tag 
                  style={{
                    margin: 0,
                    padding: '0 6px',
                    fontSize: 10,
                    fontWeight: 600,
                    background: colors.bg,
                    color: colors.text,
                    border: 'none',
                  }}
                >
                  {log.severity === 'critical' ? 'FLAG' : log.severity === 'suspicious' ? 'WARN' : 'ALLOW'}
                </Tag>
                
                <span style={{ color: '#64748b' }}>{log.source_ip}</span>
                
                <span style={{ color: '#475569' }}>→</span>
                
                <span style={{ color: '#f59e0b' }}>
                  {log.destination_ip}:{log.destination_port}
                </span>
                
                <Tag 
                  style={{
                    margin: 0,
                    padding: '0 6px',
                    fontSize: 10,
                    background: 'rgba(99, 102, 241, 0.15)',
                    color: '#818cf8',
                    border: 'none',
                  }}
                >
                  {log.direction === 'outbound' ? '↑ OUT' : '↓ IN'}
                </Tag>
                
                <span style={{ color: '#475569' }}>[{log.protocol}]</span>
              </div>
            )
          })
        )}
      </div>
    </Card>
  )
}
