import { useEffect } from 'react'
import { Typography, Button, Spin, Alert as AntAlert, Table, Tag, Space, Card, Row, Col, theme, Empty } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined, InfoCircleOutlined } from '@ant-design/icons'
import { Bell, Shield, AlertTriangle, CheckCircle, Clock, Server } from 'lucide-react'
import { Alert } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useAlerts } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

const severityConfigMap: Record<string, { color: string; Icon: any; bg: string }> = {
  info: { color: '#3b82f6', Icon: InfoCircleOutlined, bg: 'rgba(59,130,246,0.12)' },
  warning: { color: '#f59e0b', Icon: AlertTriangle, bg: 'rgba(245,158,11,0.12)' },
  critical: { color: '#ef4444', Icon: AlertTriangle, bg: 'rgba(239,68,68,0.12)' },
  high: { color: '#f97316', Icon: AlertTriangle, bg: 'rgba(249,115,22,0.12)' },
  medium: { color: '#f59e0b', Icon: InfoCircleOutlined, bg: 'rgba(245,158,11,0.12)' },
}

const statusConfigMap: Record<string, { color: string; bg: string; Icon: any }> = {
  active: { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', Icon: Clock },
  acknowledged: { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)', Icon: InfoCircleOutlined },
  resolved: { color: '#10b981', bg: 'rgba(16,185,129,0.12)', Icon: CheckCircle },
}

function getSeverityConfig(severity: string) {
  return severityConfigMap[severity] || severityConfigMap.info
}

function getStatusConfig(status: string) {
  return statusConfigMap[status] || { color: '#64748b', bg: 'rgba(100,116,139,0.12)', Icon: InfoCircleOutlined }
}

export default function Alerts() {
  const { data: alerts, isLoading: loading, error } = useAlerts()
  const { lastMessage } = useWebSocket()
  const { token } = theme.useToken()

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

  const columns: ColumnsType<Alert> = [
    {
      title: 'Time',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (date) => (
        <Space direction="vertical" size={0}>
          <Text style={{ fontSize: 13 }}>{new Date(date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</Text>
          <Text type="secondary" style={{ fontSize: 11 }}>{new Date(date).toLocaleDateString([], { month: 'short', day: 'numeric' })}</Text>
        </Space>
      ),
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 140,
      render: (severity) => {
        const config = getSeverityConfig(severity)
        const Icon = config.Icon
        return (
          <Tag style={{ background: config.bg, color: config.color, border: 'none', fontWeight: 600, textTransform: 'uppercase', fontSize: 11 }}>
            <Icon style={{ marginRight: 4 }} />
            {severity}
          </Tag>
        )
      },
    },
    {
      title: 'Source',
      dataIndex: 'source_ip',
      key: 'source_ip',
      width: 140,
      render: (ip) => <Text code style={{ fontSize: 12 }}>{ip}</Text>,
    },
    {
      title: 'Server',
      dataIndex: 'server_hostname',
      key: 'server_hostname',
      width: 180,
      render: (hostname) => (
        <Space size={8}>
          <Server size={14} color={token.colorTextTertiary} />
          <Text type="secondary">{hostname || 'Unknown server'}</Text>
        </Space>
      ),
    },
    {
      title: 'Description',
      dataIndex: 'reason',
      key: 'reason',
      render: (reason) => <Text style={{ fontSize: 14 }}>{reason}</Text>,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 130,
      render: (status) => {
        const config = getStatusConfig(status)
        const Icon = config.Icon
        return (
          <Tag style={{ background: config.bg, color: config.color, border: 'none', fontWeight: 600, textTransform: 'uppercase', fontSize: 11 }}>
            <Icon style={{ marginRight: 4 }} />
            {status}
          </Tag>
        )
      },
    },
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
      <Row justify="space-between" align="middle" style={{ marginBottom: token.marginLG }}>
        <Col>
          <Space direction="vertical" size={4}>
            <Title level={2} style={{ margin: 0 }}>Alerts</Title>
            <Text type="secondary">Remediation incidents created when threats trigger an operator-facing action</Text>
          </Space>
        </Col>
        <Col>
          <Button icon={<ReloadOutlined />} onClick={() => queryClient.invalidateQueries({ queryKey: ['alerts'] })}>
            Refresh
          </Button>
        </Col>
      </Row>

      {/* Stats Cards */}
      <Row gutter={[20, 20]} style={{ marginBottom: token.marginLG }}>
        <Col xs={24} sm={12}>
          <Card styles={{ body: { padding: token.paddingLG } }}>
            <Row align="middle" justify="space-between">
              <Col>
                <Space size={16}>
                  <div style={{
                    width: 56, height: 56, background: 'rgba(245,158,11,0.12)',
                    borderRadius: token.borderRadius, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Bell size={28} color="#f59e0b" />
                  </div>
                  <div>
                    <Text type="secondary" style={{ fontSize: 13, display: 'block' }}>Active Alerts</Text>
                    <Title level={2} style={{ margin: '4px 0', color: '#f59e0b' }}>{activeCount}</Title>
                  </div>
                </Space>
              </Col>
              <Col>
                <div style={{
                  width: 60, height: 60, borderRadius: '50%',
                  border: '4px solid rgba(245,158,11,0.2)', borderTopColor: '#f59e0b',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <Text style={{ color: '#f59e0b', fontWeight: 700 }}>{activeCount > 0 ? '!' : '✓'}</Text>
                </div>
              </Col>
            </Row>
          </Card>
        </Col>
        <Col xs={24} sm={12}>
          <Card styles={{ body: { padding: token.paddingLG } }}>
            <Row align="middle" justify="space-between">
              <Col>
                <Space size={16}>
                  <div style={{
                    width: 56, height: 56, background: 'rgba(16,185,129,0.12)',
                    borderRadius: token.borderRadius, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Shield size={28} color="#10b981" />
                  </div>
                  <div>
                    <Text type="secondary" style={{ fontSize: 13, display: 'block' }}>Resolved Incidents</Text>
                    <Title level={2} style={{ margin: '4px 0', color: '#10b981' }}>{resolvedCount}</Title>
                  </div>
                </Space>
              </Col>
              <Col>
                <div style={{
                  width: 60, height: 60, borderRadius: '50%',
                  border: '4px solid rgba(16,185,129,0.2)', borderTopColor: '#10b981',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <Text style={{ color: '#10b981', fontWeight: 700 }}>
                    {Math.round((resolvedCount / (alerts?.length || 1)) * 100)}%
                  </Text>
                </div>
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>

      {error && <AntAlert message="Failed to load alerts" type="error" showIcon style={{ marginBottom: 16 }} />}

      {/* Alerts Table */}
      <Card
        styles={{ body: { padding: 0 } }}
        title={
          <Space>
            <AlertTriangle size={18} color="#f59e0b" />
            <Text strong>Remediation Alerts</Text>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={alerts || []}
          rowKey="id"
          pagination={{ pageSize: 10, style: { margin: '16px 24px' } }}
          locale={{
            emptyText: (
              <Empty
                image={<Shield size={64} color={token.colorTextQuaternary} style={{ opacity: 0.3 }} />}
                description="No remediation alerts"
              >
                Threats will still appear on the Threats page even when no alert has been created
              </Empty>
            ),
          }}
        />
      </Card>
    </div>
  )
}
