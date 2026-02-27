import { useEffect } from 'react'
import { Server as ServerIcon, Shield, AlertTriangle, Zap, Crown, Sparkles, Activity, CheckCircle, AlertCircle, XCircle } from 'lucide-react'
import { Row, Col, Typography, Card, Space, Badge, Tag } from 'antd'
import { useNavigate } from '@tanstack/react-router'
import StatCard from '../components/StatCard'
import TrafficChart from '../components/TrafficChart'
import ThreatsList from '../components/ThreatsList'
import ServersList from '../components/ServersList'
import LiveStream from '../components/LiveStream'
import { Threat, StatsOverview } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useServers, useThreats, useStats, useSubscriptionStatus, useSystemStatus } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

// System Status Card Component
function SystemStatusCard() {
  const { data: systemStatus, isLoading } = useSystemStatus()

  if (isLoading || !systemStatus) {
    return (
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 24 }}
          >
            <Text style={{ color: 'var(--text-secondary)' }}>Loading system status...</Text>
          </Card>
        </Col>
      </Row>
    )
  }

  const statusConfig = {
    healthy: {
      icon: CheckCircle,
      color: '#10b981',
      bgColor: 'rgba(16, 185, 129, 0.1)',
      title: 'System Status: Protected',
    },
    warning: {
      icon: AlertCircle,
      color: '#f59e0b',
      bgColor: 'rgba(245, 158, 11, 0.1)',
      title: 'System Status: Warning',
    },
    error: {
      icon: XCircle,
      color: '#ef4444',
      bgColor: 'rgba(239, 68, 68, 0.1)',
      title: 'System Status: Attention Required',
    },
  }

  const config = statusConfig[systemStatus.status]
  const StatusIcon = config.icon

  return (
    <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
      <Col xs={24}>
        <Card
          variant="borderless"
          style={{
            background: config.bgColor,
            border: `1px solid ${config.color}30`,
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
                    background: config.color,
                    borderRadius: 12,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: `0 4px 14px ${config.color}40`,
                  }}
                >
                  <StatusIcon size={24} color="white" />
                </div>
                <div>
                  <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>
                    {config.title}
                  </Title>
                  <Text style={{ color: 'var(--text-secondary)' }}>
                    {systemStatus.message}. Last heartbeat {systemStatus.lastHeartbeatAgo}.
                  </Text>
                </div>
              </Space>
            </Col>
            <Col>
              <Space size={12}>
                <Text style={{ color: 'var(--text-tertiary)' }}>
                  Active agents:
                </Text>
                <Badge 
                  count={`${systemStatus.activeServers}/${systemStatus.totalServers}`}
                  style={{ 
                    background: systemStatus.activeServers === systemStatus.totalServers ? '#10b981' : '#f59e0b',
                    color: 'white',
                  }}
                />
              </Space>
            </Col>
          </Row>
        </Card>
      </Col>
    </Row>
  )
}

export default function Overview() {
  const { data: statsData } = useStats()
  const { data: serversData } = useServers()
  const { data: threatsData } = useThreats()
  const { data: subscription } = useSubscriptionStatus()
  const { lastMessage } = useWebSocket()
  const navigate = useNavigate()

  const noSubscription = subscription && subscription.plan === 'none'
  const hasActiveTrial = subscription && subscription.is_trialing

  const rawStats: Partial<StatsOverview> = statsData || {}
  const stats: StatsOverview = {
    total_servers: rawStats.total_servers ?? 0,
    active_servers: rawStats.active_servers ?? 0,
    total_events: rawStats.total_events ?? 0,
    total_alerts: rawStats.total_alerts ?? 0,
    active_threats: rawStats.active_threats ?? 0,
    blocked_ips: rawStats.blocked_ips ?? 0,
    events_last_24h: rawStats.events_last_24h ?? 0,
    alerts_last_24h: rawStats.alerts_last_24h ?? 0,
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
          <Card
            variant="borderless"
            style={{
              background: noSubscription 
                ? 'linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(139, 92, 246, 0.1))' 
                : hasActiveTrial 
                  ? 'linear-gradient(135deg, rgba(245, 158, 11, 0.15), rgba(245, 158, 11, 0.05))'
                  : 'var(--bg-card)',
              border: `1px solid ${noSubscription || hasActiveTrial ? 'transparent' : 'var(--border-subtle)'}`,
              borderRadius: 'var(--radius-lg)',
              cursor: noSubscription ? 'pointer' : 'default',
              height: '100%',
            }}
            bodyStyle={{ padding: 20, height: '100%' }}
            onClick={noSubscription ? () => navigate({ to: '/dashboard/subscription' }) : undefined}
          >
            <Space size={16}>
              <div 
                style={{
                  width: 48,
                  height: 48,
                  background: noSubscription 
                    ? 'rgba(99, 102, 241, 0.2)' 
                    : hasActiveTrial 
                      ? 'rgba(245, 158, 11, 0.2)'
                      : 'rgba(16, 185, 129, 0.15)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {noSubscription ? <Crown size={24} color="#818cf8" /> : 
                 hasActiveTrial ? <Sparkles size={24} color="#f59e0b" /> :
                 <Crown size={24} color="#10b981" />}
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Current Plan
                </Text>
                <Title level={3} style={{ margin: 0, color: noSubscription ? '#818cf8' : hasActiveTrial ? '#f59e0b' : '#10b981', fontSize: 20 }}>
                  {subscription?.plan_display_name || 'Loading...'}
                </Title>
                {noSubscription && (
                  <Text style={{ color: '#818cf8', fontSize: 12 }}>Click to start trial →</Text>
                )}
                {hasActiveTrial && (
                  <Tag color="gold" style={{ marginTop: 4, fontSize: 10 }}>Trial Active</Tag>
                )}
              </div>
            </Space>
          </Card>
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

      {/* System Status */}
      <SystemStatusCard />

    </div>
  )
}
