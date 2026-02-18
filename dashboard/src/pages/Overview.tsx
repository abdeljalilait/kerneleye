import { useEffect } from 'react'
import { Server as ServerIcon, Activity, Shield, AlertTriangle, Zap, TrendingUp } from 'lucide-react'
import { Row, Col, Typography, Card, Space, Badge } from 'antd'
import StatCard from '../components/StatCard'
import TrafficChart from '../components/TrafficChart'
import ThreatsList from '../components/ThreatsList'
import ServersList from '../components/ServersList'
import LiveStream from '../components/LiveStream'
import { Threat, StatsOverview } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useServers, useThreats, useStats } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

export default function Overview() {
  const { data: statsData } = useStats()
  const { data: serversData } = useServers()
  const { data: threatsData } = useThreats()
  const { lastMessage } = useWebSocket()

  const stats = statsData || {
    total_servers: 0,
    active_servers: 0,
    total_events: 0,
    total_alerts: 0,
    active_threats: 0,
    blocked_ips: 0,
    events_last_24h: 0,
    alerts_last_24h: 0,
  }
  const servers = serversData || []
  const threats = threatsData || []

  useEffect(() => {
    if (lastMessage?.type === 'stats_update' || lastMessage?.type === 'new_alert') {
      queryClient.invalidateQueries({ queryKey: ['stats'] })
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    }
    if (lastMessage?.type === 'new_threat') {
      const newThreat = lastMessage.data as Threat
      queryClient.setQueryData(['threats'], (old: Threat[] | undefined) => {
        return old ? [newThreat, ...old] : [newThreat]
      })
      queryClient.setQueryData(['stats'], (old: StatsOverview | undefined) => {
        return old ? { ...old, active_threats: old.active_threats + 1 } : old
      })
    }
  }, [lastMessage])

  return (
    <div style={{ paddingBottom: 32 }}>
      {/* Welcome Section */}
      <div style={{ marginBottom: 32 }}>
        <Row justify="space-between" align="middle">
          <Col>
            <Space direction="vertical" size={4}>
              <Space size={12} align="center">
                <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
                  Dashboard
                </Title>
                <Badge 
                  count="LIVE" 
                  style={{ 
                    background: 'rgba(16, 185, 129, 0.15)', 
                    color: '#10b981',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    fontSize: 10,
                    fontWeight: 600,
                  }}
                />
              </Space>
              <Text style={{ color: 'var(--text-secondary)', fontSize: 15 }}>
                Real-time security monitoring and threat detection overview
              </Text>
            </Space>
          </Col>
          <Col>
            <Space size={16}>
              <Card 
                variant="borderless" 
                style={{ 
                  background: 'var(--bg-tertiary)', 
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 12,
                }}
                bodyStyle={{ padding: '12px 20px' }}
              >
                <Space size={12}>
                  <div 
                    style={{
                      width: 32,
                      height: 32,
                      background: 'rgba(99, 102, 241, 0.15)',
                      borderRadius: 8,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Zap size={16} color="#818cf8" />
                  </div>
                  <div>
                    <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', display: 'block' }}>
                      Events/sec
                    </Text>
                    <Text strong style={{ fontSize: 16, color: 'var(--text-primary)' }}>
                      {(stats.events_last_24h / 86400).toFixed(1)}
                    </Text>
                  </div>
                </Space>
              </Card>
              <Card 
                variant="borderless" 
                style={{ 
                  background: 'var(--bg-tertiary)', 
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 12,
                }}
                bodyStyle={{ padding: '12px 20px' }}
              >
                <Space size={12}>
                  <div 
                    style={{
                      width: 32,
                      height: 32,
                      background: 'rgba(16, 185, 129, 0.15)',
                      borderRadius: 8,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <TrendingUp size={16} color="#10b981" />
                  </div>
                  <div>
                    <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', display: 'block' }}>
                      Uptime
                    </Text>
                    <Text strong style={{ fontSize: 16, color: 'var(--text-primary)' }}>
                      99.9%
                    </Text>
                  </div>
                </Space>
              </Card>
            </Space>
          </Col>
        </Row>
      </div>

      {/* KPI Cards */}
      <Row gutter={[20, 20]}>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            title="Monitored Servers"
            value={stats.total_servers.toString()}
            subtext={`${stats.active_servers} active online`}
            icon={ServerIcon}
            trend={stats.total_servers > 0 ? 'up' : 'neutral'}
            color="primary"
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            title="Active Threats"
            value={stats.active_threats.toString()}
            subtext="Require attention"
            icon={AlertTriangle}
            trend={stats.active_threats > 0 ? 'up' : 'neutral'}
            color={stats.active_threats > 0 ? 'error' : 'success'}
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            title="Events (24h)"
            value={stats.events_last_24h.toLocaleString()}
            subtext="Total traffic events"
            icon={Shield}
            trend="neutral"
            color="cyan"
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            title="Alerts (24h)"
            value={stats.alerts_last_24h.toString()}
            subtext="Security incidents"
            icon={Activity}
            trend={stats.alerts_last_24h > 5 ? 'down' : 'neutral'}
            color="warning"
          />
        </Col>
      </Row>

      {/* Charts Row */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={16}>
          <TrafficChart />
        </Col>
        <Col xs={24} lg={8}>
          <ServersList servers={servers.slice(0, 5)} />
        </Col>
      </Row>

      {/* Threats & Live Stream */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={16}>
          <ThreatsList threats={threats.slice(0, 5)} />
        </Col>
        <Col xs={24} lg={8}>
          <LiveStream />
        </Col>
      </Row>

      {/* Quick Actions Footer */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24}>
          <Card
            variant="borderless"
            style={{
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(139, 92, 246, 0.05))',
              border: '1px solid rgba(99, 102, 241, 0.2)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 24 }}
          >
            <Row justify="space-between" align="middle">
              <Col>
                <Space size={16} align="center">
                  <div 
                    style={{
                      width: 48,
                      height: 48,
                      background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                      borderRadius: 12,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      boxShadow: '0 4px 14px rgba(99, 102, 241, 0.4)',
                    }}
                  >
                    <Shield size={24} color="white" />
                  </div>
                  <div>
                    <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>
                      System Status: Protected
                    </Title>
                    <Text style={{ color: 'var(--text-secondary)' }}>
                      All systems operational. Last scan completed 2 minutes ago.
                    </Text>
                  </div>
                </Space>
              </Col>
              <Col>
                <Space size={12}>
                  <Text style={{ color: 'var(--text-tertiary)' }}>
                    Next scheduled scan:
                  </Text>
                  <Badge 
                    count="5 min" 
                    style={{ 
                      background: 'var(--bg-tertiary)', 
                      color: 'var(--text-secondary)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  />
                </Space>
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>
    </div>
  )
}
