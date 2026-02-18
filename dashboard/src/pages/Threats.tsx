import { useEffect } from 'react'
import { Typography, Button, Spin, Alert, Row, Col, Card, Space } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { Shield as ShieldIcon, Target, AlertTriangle, CheckCircle } from 'lucide-react'
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

  const criticalCount = threats?.filter(t => t.threat_score >= 70).length || 0
  const highCount = threats?.filter(t => t.threat_score >= 40 && t.threat_score < 70).length || 0
  const mediumCount = threats?.filter(t => t.threat_score >= 20 && t.threat_score < 40).length || 0
  const lowCount = threats?.filter(t => t.threat_score < 20).length || 0

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
              Threat Detection
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>
              Real-time threat monitoring and analysis
            </Text>
          </Space>
        </Col>
        <Col>
          <Button 
            icon={<ReloadOutlined />}
            onClick={() => queryClient.invalidateQueries({ queryKey: ['threats'] })}
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

      {/* Threat Level Stats */}
      <Row gutter={[20, 20]} style={{ marginBottom: 32 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space align="start" size={16}>
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
                <ShieldIcon size={24} color="#ef4444" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Critical
                </Text>
                <Title level={3} style={{ margin: '4px 0', color: '#ef4444' }}>
                  {criticalCount}
                </Title>
                <Text style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Score ≥ 70
                </Text>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space align="start" size={16}>
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
                <AlertTriangle size={24} color="#f59e0b" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  High Risk
                </Text>
                <Title level={3} style={{ margin: '4px 0', color: '#f59e0b' }}>
                  {highCount}
                </Title>
                <Text style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Score 40-69
                </Text>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space align="start" size={16}>
              <div 
                style={{
                  width: 48,
                  height: 48,
                  background: 'rgba(251, 191, 36, 0.15)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Target size={24} color="#fbbf24" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Suspicious
                </Text>
                <Title level={3} style={{ margin: '4px 0', color: '#fbbf24' }}>
                  {mediumCount}
                </Title>
                <Text style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Score 20-39
                </Text>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space align="start" size={16}>
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
                <CheckCircle size={24} color="#10b981" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Low Risk
                </Text>
                <Title level={3} style={{ margin: '4px 0', color: '#10b981' }}>
                  {lowCount}
                </Title>
                <Text style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Score &lt; 20
                </Text>
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      {error && (
        <Alert 
          message="Failed to load threats" 
          type="error" 
          showIcon 
          style={{ marginBottom: 16 }}
        />
      )}

      {/* Threats Table */}
      <ThreatsList threats={threats || []} />
    </div>
  )
}
