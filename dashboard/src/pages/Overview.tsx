import { useEffect } from 'react'
import { Server as ServerIcon, Shield, AlertTriangle, Crown, Sparkles } from 'lucide-react'
import { Row, Col, Typography, Card, Space, Tag, theme } from 'antd'
import { useNavigate } from '@tanstack/react-router'
import StatCard from '../components/StatCard'
import TrafficChart from '../components/TrafficChart'
import ThreatsList from '../components/ThreatsList'
import ServersList from '../components/ServersList'
import LiveStream from '../components/LiveStream'
import { Threat, StatsOverview } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useServers, useThreats, useStats, useSubscriptionStatus } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

function SubscriptionCard() {
  const { data: subscription } = useSubscriptionStatus()
  const navigate = useNavigate()
  const { token } = theme.useToken()

  const noSubscription = subscription && subscription.plan === 'none'
  const hasActiveTrial = subscription && subscription.is_trialing
  const isClickable = noSubscription

  const accentColor = noSubscription ? token.colorPrimary : hasActiveTrial ? token.colorWarning : token.colorSuccess
  const bgAlpha = noSubscription ? 0.1 : 0.06
  const Icon = noSubscription ? Crown : hasActiveTrial ? Sparkles : Crown

  return (
    <Card
      hoverable={!!isClickable}
      onClick={isClickable ? () => navigate({ to: '/dashboard/subscription' }) : undefined}
      styles={{ body: { padding: token.paddingMD, display: 'flex', alignItems: 'center', gap: 16 } }}
    >
      <div
        style={{
          width: 48,
          height: 48,
          background: `rgba(99, 102, 241, ${bgAlpha})`,
          borderRadius: token.borderRadius,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}
      >
        <Icon size={24} color={accentColor} />
      </div>
      <div>
        <Text style={{ color: token.colorTextTertiary, fontSize: 12, display: 'block' }}>
          Current Plan
        </Text>
        <Title level={5} style={{ margin: 0, color: accentColor }}>
          {subscription?.plan_display_name || 'Loading...'}
        </Title>
        {noSubscription && (
          <Text style={{ color: token.colorPrimary, fontSize: 12 }}>Click to start trial</Text>
        )}
        {hasActiveTrial && (
          <Tag color="gold" style={{ marginTop: 4, fontSize: 10 }}>Trial Active</Tag>
        )}
      </div>
    </Card>
  )
}

export default function Overview() {
  const { data: statsData } = useStats()
  const { data: serversData } = useServers()
  const { data: threatsData } = useThreats()
  const { lastMessage } = useWebSocket()
  const { token } = theme.useToken()

  const threats = threatsData || []
  const rawStats: Partial<StatsOverview> = statsData || {}
  const stats: StatsOverview = {
    total_servers: rawStats.total_servers ?? 0,
    active_servers: rawStats.active_servers ?? 0,
    total_events: rawStats.total_events ?? 0,
    total_alerts: rawStats.total_alerts ?? 0,
    active_threats: rawStats.active_threats ?? threats.length,
    blocked_ips: rawStats.blocked_ips ?? 0,
    events_last_24h: rawStats.events_last_24h ?? 0,
    alerts_last_24h: rawStats.alerts_last_24h ?? rawStats.total_alerts ?? 0,
  }
  const servers = serversData || []

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
    <div style={{ paddingBottom: token.paddingXL }}>
      {/* Page header */}
      <div style={{ marginBottom: token.marginLG }}>
        <Space direction="vertical" size={4}>
          <Space size={12} align="center">
            <Title level={2} style={{ margin: 0 }}>
              Dashboard
            </Title>
            <Tag color="success" style={{ fontWeight: 600, letterSpacing: '0.05em' }}>LIVE</Tag>
          </Space>
          <Text type="secondary" style={{ fontSize: 15 }}>
            Real-time security monitoring and threat detection overview
          </Text>
        </Space>
      </div>

      {/* KPI Cards row */}
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
            subtext="Suspicious or malicious IPs"
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
          <SubscriptionCard />
        </Col>
      </Row>

      {/* Charts + Servers row */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={16}>
          <TrafficChart />
        </Col>
        <Col xs={24} lg={8}>
          <ServersList servers={servers.slice(0, 5)} />
        </Col>
      </Row>

      {/* Threats + Live Stream row */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={16}>
          <ThreatsList threats={threats.slice(0, 5)} />
        </Col>
        <Col xs={24} lg={8}>
          <LiveStream />
        </Col>
      </Row>
    </div>
  )
}
