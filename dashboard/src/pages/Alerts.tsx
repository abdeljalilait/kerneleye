import { useEffect } from 'react'
import { Typography, Button, Spin, Alert as AntAlert, Table, Tag, Space, Card, Row, Col, Badge } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { 
  ReloadOutlined, 
  InfoCircleOutlined} from '@ant-design/icons'
import { Bell, Shield, AlertTriangle, CheckCircle, Clock, Server } from 'lucide-react'
import { Alert } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useAlerts } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

export default function Alerts() {
  const { data: alerts, isLoading: loading, error } = useAlerts()
  const { lastMessage } = useWebSocket()

  useEffect(() => {
    if (lastMessage?.type === 'new_alert') {
      const newAlert = lastMessage.data as Alert
      queryClient.setQueryData(['alerts'], (old: Alert[] | undefined) => {
        return old ? [newAlert, ...old] : [newAlert]
      })
    }
  }, [lastMessage])

  const activeCount = alerts?.filter(a => a.status === 'active').length || 0
  const resolvedCount = alerts?.filter(a => a.status === 'resolved').length || 0

  const getSeverityConfig = (severity: string) => {
    const configs: Record<string, { color: string; icon: any; bg: string }> = {
      info: {
        color: '#3b82f6',
        icon: InfoCircleOutlined,
        bg: 'rgba(59, 130, 246, 0.15)',
      },
      warning: {
        color: '#f59e0b',
        icon: AlertTriangle,
        bg: 'rgba(245, 158, 11, 0.15)',
      },
      critical: { 
        color: '#ef4444', 
        icon: AlertTriangle, 
        bg: 'rgba(239, 68, 68, 0.15)' 
      },
      high: { 
        color: '#f97316', 
        icon: AlertTriangle, 
        bg: 'rgba(249, 115, 22, 0.15)' 
      },
      medium: { 
        color: '#f59e0b', 
        icon: InfoCircleOutlined, 
        bg: 'rgba(245, 158, 11, 0.15)' 
      },
    }
    return configs[severity] || configs.info
  }

  const getStatusConfig = (status: string) => {
    if (status === 'active') {
      return { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)', icon: Clock }
    }
    if (status === 'acknowledged') {
      return { color: '#3b82f6', bg: 'rgba(59, 130, 246, 0.15)', icon: InfoCircleOutlined }
    }
    if (status === 'resolved') {
      return { color: '#10b981', bg: 'rgba(16, 185, 129, 0.15)', icon: CheckCircle }
    }
    return { color: '#64748b', bg: 'rgba(100, 116, 139, 0.15)', icon: InfoCircleOutlined }
  }

  const columns: ColumnsType<Alert> = [
    {
      title: 'Time',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (date) => (
        <Space direction="vertical" size={0}>
          <Text style={{ color: 'var(--text-primary)', fontSize: 13 }}>
            {new Date(date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </Text>
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>
            {new Date(date).toLocaleDateString([], { month: 'short', day: 'numeric' })}
          </Text>
        </Space>
      )
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 140,
      render: (severity) => {
        const config = getSeverityConfig(severity)
        const Icon = config.icon
        return (
          <Tag 
            style={{
              margin: 0,
              padding: '4px 12px',
              fontSize: 12,
              fontWeight: 600,
              background: config.bg,
              color: config.color,
              border: 'none',
              textTransform: 'uppercase',
            }}
          >
            <Space size={4}>
              <Icon size={12} />
              {severity}
            </Space>
          </Tag>
        )
      }
    },
    {
      title: 'Source',
      dataIndex: 'source_ip',
      key: 'source_ip',
      width: 140,
      render: (ip) => (
        <Text code style={{ 
          fontSize: 12, 
          background: 'var(--bg-tertiary)',
          color: 'var(--text-secondary)',
        }}>
          {ip}
        </Text>
      )
    },
    {
      title: 'Server',
      dataIndex: 'server_hostname',
      key: 'server_hostname',
      width: 180,
      render: (hostname) => (
        <Space size={8}>
          <Server size={14} color="var(--text-tertiary)" />
          <Text style={{ color: 'var(--text-secondary)' }}>
            {hostname || 'Unknown server'}
          </Text>
        </Space>
      )
    },
    {
      title: 'Description',
      dataIndex: 'reason',
      key: 'reason',
      render: (reason) => (
        <div>
          <Text style={{ color: 'var(--text-primary)', fontSize: 14 }}>
            {reason}
          </Text>
        </div>
      )
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 130,
      render: (status) => {
        const config = getStatusConfig(status)
        const Icon = config.icon
        return (
          <Tag 
            style={{
              margin: 0,
              padding: '4px 12px',
              fontSize: 12,
              fontWeight: 600,
              background: config.bg,
              color: config.color,
              border: 'none',
              textTransform: 'uppercase',
            }}
          >
            <Space size={4}>
              <Icon size={12} />
              {status}
            </Space>
          </Tag>
        )
      }
    }
  ]

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh' }}>
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
              Alerts
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>
              Remediation incidents created when threats trigger an operator-facing action
            </Text>
          </Space>
        </Col>
        <Col>
          <Button 
            icon={<ReloadOutlined />}
            onClick={() => queryClient.invalidateQueries({ queryKey: ['alerts'] })}
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
            }}
          >
            Refresh
          </Button>
        </Col>
      </Row>

      {/* Stats Cards */}
      <Row gutter={[20, 20]} style={{ marginBottom: 32 }}>
        <Col xs={24} sm={12}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 24 }}
          >
            <Row align="middle" justify="space-between">
              <Col>
                <Space align="center" size={16}>
                  <div 
                    style={{
                      width: 56,
                      height: 56,
                      background: 'rgba(245, 158, 11, 0.15)',
                      borderRadius: 14,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Bell size={28} color="#f59e0b" />
                  </div>
                  <div>
                    <Text style={{ color: 'var(--text-tertiary)', fontSize: 13, display: 'block' }}>
                      Active Alerts
                    </Text>
                    <Title level={2} style={{ margin: '4px 0', color: '#f59e0b' }}>
                      {activeCount}
                    </Title>
                  </div>
                </Space>
              </Col>
              <Col>
                <div 
                  style={{
                    width: 60,
                    height: 60,
                    borderRadius: '50%',
                    border: '4px solid rgba(245, 158, 11, 0.2)',
                    borderTopColor: '#f59e0b',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Text style={{ color: '#f59e0b', fontWeight: 700 }}>
                    {activeCount > 0 ? '!' : '✓'}
                  </Text>
                </div>
              </Col>
            </Row>
          </Card>
        </Col>
        <Col xs={24} sm={12}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 24 }}
          >
            <Row align="middle" justify="space-between">
              <Col>
                <Space align="center" size={16}>
                  <div 
                    style={{
                      width: 56,
                      height: 56,
                      background: 'rgba(16, 185, 129, 0.15)',
                      borderRadius: 14,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Shield size={28} color="#10b981" />
                  </div>
                  <div>
                    <Text style={{ color: 'var(--text-tertiary)', fontSize: 13, display: 'block' }}>
                      Resolved Incidents
                    </Text>
                    <Title level={2} style={{ margin: '4px 0', color: '#10b981' }}>
                      {resolvedCount}
                    </Title>
                  </div>
                </Space>
              </Col>
              <Col>
                <div 
                  style={{
                    width: 60,
                    height: 60,
                    borderRadius: '50%',
                    border: '4px solid rgba(16, 185, 129, 0.2)',
                    borderTopColor: '#10b981',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Text style={{ color: '#10b981', fontWeight: 700 }}>
                    {Math.round((resolvedCount / (alerts?.length || 1)) * 100)}%
                  </Text>
                </div>
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>

      {error && (
        <AntAlert 
          message="Failed to load alerts" 
          type="error" 
          showIcon 
          style={{ marginBottom: 16 }}
        />
      )}

      {/* Alerts Table */}
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
            <AlertTriangle size={18} color="#f59e0b" />
            <Text strong style={{ color: 'var(--text-primary)' }}>
              Remediation Alerts
            </Text>
            <Badge 
              count={alerts?.length || 0} 
              style={{ 
                background: 'var(--bg-tertiary)',
                color: 'var(--text-secondary)',
              }}
            />
          </Space>
        }
      >
        <Table 
          columns={columns} 
          dataSource={alerts || []} 
          rowKey="id"
          pagination={{ 
            pageSize: 10,
            style: { margin: '16px 24px' }
          }}
          locale={{ 
            emptyText: (
              <div style={{ padding: '60px 0', textAlign: 'center' }}>
                <div style={{ marginBottom: 16 }}>
                  <Shield size={64} color="var(--text-muted)" opacity={0.3} />
                </div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 16 }}>
                  No remediation alerts
                </Text>
                <br />
                <Text style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                  Threats will still appear on the Threats page even when no alert has been created
                </Text>
              </div>
            ) 
          }}
        />
      </Card>
    </div>
  )
}
