import { useState, useEffect } from 'react'
import { Button, Row, Col, Typography, Alert, Spin, Card, Space, theme } from 'antd'
import { Plus, RefreshCcw, Server as ServerIcon, CheckCircle2, Clock, XCircle, AlertTriangle } from 'lucide-react'
import ServersList from '../components/ServersList'
import AddServerConfiguratorModal from '../components/AddServerConfiguratorModal'
import PendingAgentsList from '../components/PendingAgentsList'
import { useWebSocket } from '../context/WebSocketContext'
import { useServers, useSystemStatus } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

const statusCards = [
  { key: 'active', label: 'Online', color: '#10b981', Icon: CheckCircle2 },
  { key: 'pending', label: 'Pending', color: '#f59e0b', Icon: Clock },
  { key: 'offline', label: 'Offline', color: '#ef4444', Icon: XCircle },
]

export default function Servers() {
  const { data: servers, isLoading: loading, error } = useServers()
  const { data: systemStatus } = useSystemStatus()
  const { lastMessage } = useWebSocket()
  const [showAddModal, setShowAddModal] = useState(false)
  const { token } = theme.useToken()

  const needsAttention = systemStatus && (systemStatus.status === 'warning' || systemStatus.status === 'error')

  useEffect(() => {
    if (lastMessage?.type === 'stats_update') {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
    }
  }, [lastMessage])

  const counts = {
    active: servers?.filter(s => s.status === 'active').length || 0,
    pending: servers?.filter(s => s.status === 'pending').length || 0,
    offline: servers?.filter(s => s.status === 'offline').length || 0,
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <Spin size="large" />
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <Row justify="space-between" align="middle" style={{ marginBottom: token.marginLG }}>
        <Col>
          <Space direction="vertical" size={4}>
            <Title level={2} style={{ margin: 0 }}>Servers</Title>
            <Text type="secondary">Manage and monitor your security agents</Text>
          </Space>
        </Col>
        <Col>
          <Space>
            <Button
              onClick={() => queryClient.invalidateQueries({ queryKey: ['servers'] })}
              icon={<RefreshCcw size={16} />}
            >
              Refresh
            </Button>
            <Button type="primary" onClick={() => setShowAddModal(true)} icon={<Plus size={16} />}>
              Install Agent
            </Button>
          </Space>
        </Col>
      </Row>

      {/* System Status Alert */}
      {needsAttention && (
        <Alert
          message={
            <Space>
              <AlertTriangle size={18} color={systemStatus.status === 'error' ? '#ef4444' : '#f59e0b'} />
              <span style={{ fontWeight: 600 }}>System Status: Attention Required</span>
            </Space>
          }
          description={
            <Text type="secondary">
              {systemStatus.message}. Last heartbeat {systemStatus.lastHeartbeatAgo}.
            </Text>
          }
          type={systemStatus.status === 'error' ? 'error' : 'warning'}
          showIcon={false}
          style={{ marginBottom: 24 }}
        />
      )}

      {/* Status Cards */}
      <Row gutter={[20, 20]} style={{ marginBottom: token.marginLG }}>
        {statusCards.map(({ key, label, color, Icon }) => (
          <Col xs={24} sm={8} key={key}>
            <Card styles={{ body: { padding: token.paddingMD } }}>
              <Space size={16}>
                <div
                  style={{
                    width: 48, height: 48,
                    background: `${color}20`,
                    borderRadius: token.borderRadius,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}
                >
                  <Icon size={24} color={color} />
                </div>
                <div>
                  <Text type="secondary" style={{ fontSize: 12, display: 'block' }}>{label}</Text>
                  <Title level={3} style={{ margin: 0, color }}>{counts[key as keyof typeof counts]}</Title>
                </div>
              </Space>
            </Card>
          </Col>
        ))}
      </Row>

      {error && <Alert message="Failed to load servers" type="error" showIcon style={{ marginBottom: 24 }} />}

      {/* Pending Agents */}
      {counts.pending > 0 && (
        <PendingAgentsList
          servers={servers || []}
          onRefresh={() => queryClient.invalidateQueries({ queryKey: ['servers'] })}
        />
      )}

      {/* Servers Table */}
      <Card
        styles={{ body: { padding: 0 } }}
        title={
          <Space>
            <ServerIcon size={18} color={token.colorPrimary} />
            <Text strong>All Servers</Text>
          </Space>
        }
      >
        <ServersList servers={servers || []} showCard={false} />
      </Card>

      <AddServerConfiguratorModal isOpen={showAddModal} onClose={() => setShowAddModal(false)} />
    </div>
  )
}
