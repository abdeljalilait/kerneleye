import { useState, useEffect } from 'react'
import { Button, Row, Col, Typography, Alert, Spin, Card, Space, Badge } from 'antd'
import { Plus, RefreshCcw, Server as ServerIcon, CheckCircle2, Clock, XCircle, Sparkles, AlertTriangle } from 'lucide-react'
import { useNavigate } from '@tanstack/react-router'
import ServersList from '../components/ServersList'
import AddServerConfiguratorModal from '../components/AddServerConfiguratorModal'
import PendingAgentsList from '../components/PendingAgentsList'
import { useWebSocket } from '../context/WebSocketContext'
import { useServers, useSubscriptionStatus, useSystemStatus } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

export default function Servers() {
  const { data: servers, isLoading: loading, error } = useServers()
  const { data: subscription } = useSubscriptionStatus()
  const { data: systemStatus } = useSystemStatus()
  const { lastMessage } = useWebSocket()
  const [showAddModal, setShowAddModal] = useState(false)
  const navigate = useNavigate()

  const noSubscription = subscription && subscription.plan === 'none'
  const needsAttention = systemStatus && (systemStatus.status === 'warning' || systemStatus.status === 'error')

  useEffect(() => {
    if (lastMessage?.type === 'stats_update') {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
    }
  }, [lastMessage])

  const activeCount = servers?.filter(s => s.status === 'active').length || 0
  const pendingCount = servers?.filter(s => s.status === 'pending').length || 0
  const offlineCount = servers?.filter(s => s.status === 'offline').length || 0

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
      <Row justify="space-between" align="middle" style={{ marginBottom: 32 }}>
        <Col>
          <Space direction="vertical" size={4}>
            <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
              Servers
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>
              Manage and monitor your security agents
            </Text>
          </Space>
        </Col>
        <Col>
          <Space>
            <Button 
              onClick={() => queryClient.invalidateQueries({ queryKey: ['servers'] })}
              icon={<RefreshCcw size={16} />}
              style={{
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
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
            <Text style={{ color: 'var(--text-secondary)' }}>
              {systemStatus.message}. Last heartbeat {systemStatus.lastHeartbeatAgo}.
            </Text>
          }
          type={systemStatus.status === 'error' ? 'error' : 'warning'}
          showIcon={false}
          style={{ 
            marginBottom: 24, 
            background: systemStatus.status === 'error' 
              ? 'rgba(239, 68, 68, 0.1)' 
              : 'rgba(245, 158, 11, 0.1)', 
            border: `1px solid ${systemStatus.status === 'error' 
              ? 'rgba(239, 68, 68, 0.3)' 
              : 'rgba(245, 158, 11, 0.3)'}`,
            borderRadius: 'var(--radius-lg)',
          }}
        />
      )}

      {/* Subscription Banner */}
      {noSubscription && (
        <Alert
          message="Start Your Free Trial"
          description={
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <Text>
                You need an active subscription to add and monitor servers. Start your 7-day free trial with a credit card. You won't be charged until after the trial ends.
              </Text>
              <Button 
                type="primary" 
                icon={<Sparkles size={16} />}
                onClick={() => navigate({ to: '/dashboard/subscription' })}
              >
                Start Free Trial
              </Button>
            </Space>
          }
          type="info"
          showIcon
          style={{ 
            marginBottom: 24, 
            background: 'rgba(99, 102, 241, 0.1)', 
            border: '1px solid rgba(99, 102, 241, 0.3)' 
          }}
        />
      )}

      {/* Stats Cards */}
      <Row gutter={[20, 20]} style={{ marginBottom: 32 }}>
        <Col xs={24} sm={8}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space size={16}>
              <div 
                style={{
                  width: 48,
                  height: 48,
                  background: 'rgba(16, 185, 129, 0.15)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <CheckCircle2 size={24} color="#10b981" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Online
                </Text>
                <Title level={3} style={{ margin: 0, color: '#10b981' }}>
                  {activeCount}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space size={16}>
              <div 
                style={{
                  width: 48,
                  height: 48,
                  background: 'rgba(245, 158, 11, 0.15)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Clock size={24} color="#f59e0b" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Pending
                </Text>
                <Title level={3} style={{ margin: 0, color: '#f59e0b' }}>
                  {pendingCount}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space size={16}>
              <div 
                style={{
                  width: 48,
                  height: 48,
                  background: 'rgba(239, 68, 68, 0.15)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <XCircle size={24} color="#ef4444" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Offline
                </Text>
                <Title level={3} style={{ margin: 0, color: '#ef4444' }}>
                  {offlineCount}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      {error && (
        <Alert 
          message="Failed to load servers" 
          type="error" 
          showIcon 
          style={{ marginBottom: 24 }} 
        />
      )}

      {/* Pending Agents Section */}
      {pendingCount > 0 && (
        <div style={{ marginBottom: 32 }}>
          <PendingAgentsList 
            servers={servers || []} 
            onRefresh={() => queryClient.invalidateQueries({ queryKey: ['servers'] })}
          />
        </div>
      )}

      {/* Servers Table */}
      <Card
        variant="borderless"
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
        }}
        bodyStyle={{ padding: 0 }}
        title={
          <Space>
            <ServerIcon size={18} color="#818cf8" />
            <Text strong style={{ color: 'var(--text-primary)' }}>
              All Servers
            </Text>
            <Badge 
              count={servers?.length || 0} 
              style={{ 
                background: 'var(--bg-tertiary)',
                color: 'var(--text-secondary)',
              }}
            />
          </Space>
        }
      >
        <ServersList servers={servers || []} showCard={false} />
      </Card>

      <AddServerConfiguratorModal 
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
      />
    </div>
  )
}
