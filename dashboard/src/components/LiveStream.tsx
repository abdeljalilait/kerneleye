import { useState, useEffect, useRef } from 'react'
import { Card, Typography, List, Badge } from 'antd'
import { useWebSocket } from '../context/WebSocketContext'

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
}

export default function LiveStream() {
  const [logs, setLogs] = useState<TrafficLog[]>([])
  const { lastMessage } = useWebSocket()
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (lastMessage?.type === 'new_traffic') {
      const log = lastMessage.data as any
      setLogs((prev: TrafficLog[]) => {
        const newLogs = [...prev, {
          id: `${Date.now()}-${Math.random()}`,
          source_ip: log.source_ip,
          destination_ip: log.destination_ip || log.server_ip || '',
          destination_port: log.destination_port,
          protocol: log.protocol || 'TCP',
          direction: log.direction || 'inbound',
          syn_count: log.syn_count,
          server_ip: log.server_ip || '',
          server_hostname: log.server_hostname || '',
          timestamp: new Date().toLocaleTimeString()
        }]
        return newLogs.slice(-50) // Keep last 50
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
       title={
           <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
               <Text strong><Badge status="processing" color="green" /> Live Stream</Text>
               <Text type="secondary" style={{ fontSize: 10 }}>Real-time</Text>
           </div>
       }
       variant="borderless"
       styles={{ body: { padding: 0 } }}
       style={{ maxHeight: 600, display: 'flex', flexDirection: 'column' }}
    >
      <div 
        ref={scrollRef}
        style={{ 
            height: 300, 
            overflowY: 'auto', 
            padding: 16, 
            background: '#000', 
            fontFamily: 'monospace',
            fontSize: 12
        }}
      >
        <List
            size="small"
            dataSource={logs}
            locale={{ emptyText: <Text type="secondary">Waiting for traffic...</Text> }}
            renderItem={(log) => (
                <div style={{ marginBottom: 4, display: 'flex', gap: 8, opacity: 0.9, flexWrap: 'wrap' }}>
                    <span style={{ color: 'gray' }}>[{log.timestamp}]</span>
                    <span style={{ color: log.syn_count > 10 ? '#faad14' : '#52c41a' }}>
                        {log.syn_count > 10 ? 'FLAGGED' : 'ALLOW'}
                    </span>
                    <span>
                        <span style={{ color: '#a0a0a0' }}>{log.source_ip}</span>
                        <span style={{ color: 'gray', margin: '0 4px' }}>→</span>
                        <span style={{ color: '#f59e0b' }} title={log.server_hostname}>
                          {log.destination_ip}
                        </span>
                        <span style={{ color: '#6366f1' }}>:{log.destination_port}</span>
                    </span>
                    <span style={{ color: log.direction === 'outbound' ? '#3b82f6' : '#22c55e' }}>
                        {log.direction === 'outbound' ? '↑OUT' : '↓IN'}
                    </span>
                    <span style={{ color: 'gray' }}>[{log.protocol}]</span>
                </div>
            )}
        />
      </div>
    </Card>
  )
}
