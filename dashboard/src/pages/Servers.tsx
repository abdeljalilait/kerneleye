import { useState, useEffect } from 'react'
import { Button, Row, Col, Typography, Alert, Spin } from 'antd'
import { Plus, RefreshCcw } from 'lucide-react'
import ServersList from '../components/ServersList'
import AddAgentModal from '../components/AddAgentModal'
import PendingAgentsList from '../components/PendingAgentsList'
import { useWebSocket } from '../context/WebSocketContext'
import { useServers } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

export default function Servers() {
  const { data: servers, isLoading: loading, error } = useServers()
  const { lastMessage } = useWebSocket()
  const [showAddModal, setShowAddModal] = useState(false)

  useEffect(() => {
    if (lastMessage?.type === 'stats_update') {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
    }
  }, [lastMessage])

  if (loading) {
     return <div style={{ display: 'flex', justifyContent: 'center', marginTop: 40 }}><Spin size="large" /></div>
  }

  return (
    <div>
      <Row justify="space-between" align="middle" style={{ marginBottom: 24 }}>
        <Col>
          <Title level={2} style={{ margin: 0 }}>Servers</Title>
          <Text type="secondary">Manage and monitor connected agents</Text>
        </Col>
        <Col>
            <Button 
                onClick={() => queryClient.invalidateQueries({ queryKey: ['servers'] })}
                style={{ marginRight: 8 }}
                icon={<RefreshCcw size={16} />}
            >
                Refresh
            </Button>
            <Button 
                type="primary" 
                onClick={() => setShowAddModal(true)}
                icon={<Plus size={16} />}
            >
                Install Agent
            </Button>
        </Col>
      </Row>

      {error ? (
        <Alert message="Failed to load servers" type="error" showIcon style={{ marginBottom: 24 }} />
      ) : null}

      <PendingAgentsList 
        servers={servers || []} 
        onRefresh={() => queryClient.invalidateQueries({ queryKey: ['servers'] })}
      />

      <ServersList servers={servers || []} />

      <AddAgentModal 
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
      />
    </div>
  )
}
