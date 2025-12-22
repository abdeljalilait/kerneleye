import { useEffect } from 'react'
import { Typography, Button, Spin, Alert } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { Threat } from '../types'
import ThreatsList from '../components/ThreatsList'
import { useWebSocket } from '../context/WebSocketContext'
import { useThreats } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

export default function Threats() {
  const { data: threats, isLoading: loading, error } = useThreats()
  const { lastMessage } = useWebSocket()

  useEffect(() => {
    if (lastMessage?.type === 'new_threat') {
      const newThreat = lastMessage.data as Threat
      queryClient.setQueryData(['threats'], (old: Threat[] | undefined) => {
        return old ? [newThreat, ...old] : [newThreat]
      })
    }
  }, [lastMessage])

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 256 }}>
        <Spin size="large" />
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <Title level={2} style={{ marginBottom: 8 }}>Detected Threats</Title>
          <Text type="secondary">Real-time threat monitoring and analysis</Text>
        </div>
        <Button 
          icon={<ReloadOutlined />}
          onClick={() => queryClient.invalidateQueries({ queryKey: ['threats'] })}
        >
          Refresh
        </Button>
      </div>

      {error && (
        <Alert 
          message="Failed to load threats" 
          type="error" 
          showIcon 
          style={{ marginBottom: 16 }}
        />
      )}

      <ThreatsList threats={threats || []} />
    </div>
  )
}
