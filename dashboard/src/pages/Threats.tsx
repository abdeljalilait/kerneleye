import { useEffect } from 'react'
import { Typography, Button, Spin, Alert, Row, Col, Card, Space, Statistic, theme } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { Shield, AlertTriangle, Target, CheckCircle } from 'lucide-react'
import { Threat } from '../types'
import ThreatsList from '../components/ThreatsList'
import { useWebSocket } from '../context/WebSocketContext'
import { useThreats } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

const severityConfig = [
  { key: 'critical', label: 'Critical', color: '#ef4444', Icon: Shield, scoreNote: 'Score ≥ 70' },
  { key: 'high', label: 'High Risk', color: '#f59e0b', Icon: AlertTriangle, scoreNote: 'Score 40-69' },
  { key: 'medium', label: 'Suspicious', color: '#fbbf24', Icon: Target, scoreNote: 'Score 20-39' },
  { key: 'low', label: 'Low Risk', color: '#10b981', Icon: CheckCircle, scoreNote: 'Score < 20' },
]

export default function Threats() {
  const { data: threats, isLoading: loading, error } = useThreats()
  const { lastMessage } = useWebSocket()
  const { token } = theme.useToken()

  useEffect(() => {
    if (lastMessage?.type === 'new_threat') {
      const newThreat = lastMessage.data as Threat
      queryClient.setQueryData(['threats'], (old: Threat[] | undefined) => {
        return old ? [newThreat, ...old] : [newThreat]
      })
    }
  }, [lastMessage])

  const counts = {
    critical: threats?.filter(t => t.threat_score >= 70).length || 0,
    high: threats?.filter(t => t.threat_score >= 40 && t.threat_score < 70).length || 0,
    medium: threats?.filter(t => t.threat_score >= 20 && t.threat_score < 40).length || 0,
    low: threats?.filter(t => t.threat_score < 20).length || 0,
  }

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
            <Title level={2} style={{ margin: 0 }}>Threat Detection</Title>
            <Text type="secondary">All suspicious and malicious traffic scored from observed network activity</Text>
          </Space>
        </Col>
        <Col>
          <Button icon={<ReloadOutlined />} onClick={() => queryClient.invalidateQueries({ queryKey: ['threats'] })}>
            Refresh
          </Button>
        </Col>
      </Row>

      {/* Threat Level Stats */}
      <Row gutter={[20, 20]} style={{ marginBottom: token.marginLG }}>
        {severityConfig.map(({ key, label, color, Icon, scoreNote }) => (
          <Col xs={24} sm={12} lg={6} key={key}>
            <Card styles={{ body: { padding: token.paddingMD } }}>
              <Space size={16} align="start">
                <div
                  style={{
                    width: 48, height: 48,
                    background: `${color}20`,
                    borderRadius: token.borderRadius,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Icon size={24} color={color} />
                </div>
                <div>
                  <Text type="secondary" style={{ fontSize: 12, display: 'block' }}>{label}</Text>
                  <Title level={3} style={{ margin: '4px 0', color }}>{counts[key as keyof typeof counts]}</Title>
                  <Text style={{ fontSize: 11, color: token.colorTextQuaternary }}>{scoreNote}</Text>
                </div>
              </Space>
            </Card>
          </Col>
        ))}
      </Row>

      {error && <Alert message="Failed to load threats" type="error" showIcon style={{ marginBottom: 16 }} />}

      <ThreatsList threats={threats || []} />
    </div>
  )
}
