import { useEffect } from 'react'
import { Server as ServerIcon, Activity, Shield, AlertTriangle } from 'lucide-react'
import { Row, Col, Typography } from 'antd'
import StatCard from '../components/StatCard'
import TrafficChart from '../components/TrafficChart'
import ThreatsList from '../components/ThreatsList'
import ServersList from '../components/ServersList'
import LiveStream from '../components/LiveStream'
import { Threat, StatsOverview } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useServers, useThreats, useStats } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title } = Typography

export default function Overview() {
  const { data: statsData } = useStats()
  const { data: serversData } = useServers()
  const { data: threatsData } = useThreats()
  const { lastMessage } = useWebSocket()

  // Default values to prevent crashes if data is loading/missing
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
    // If we get any major update, invalidate queries to refetch
    if (lastMessage?.type === 'stats_update' || lastMessage?.type === 'new_alert') {
      queryClient.invalidateQueries({ queryKey: ['stats'] })
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    }
    // Optimistic update for new threats
    if (lastMessage?.type === 'new_threat') {
      const newThreat = lastMessage.data as Threat
      // Update threats cache
      queryClient.setQueryData(['threats'], (old: Threat[] | undefined) => {
        return old ? [newThreat, ...old] : [newThreat]
      })
      // Update active threats count in stats (optimistic)
      queryClient.setQueryData(['stats'], (old: StatsOverview | undefined) => {
        return old ? { ...old, active_threats: old.active_threats + 1 } : old
      })
    }
  }, [lastMessage])

  return (
    <div style={{ paddingBottom: 24 }}>
      <Title level={2} style={{ marginBottom: 24 }}>System Overview</Title>
      
      {/* KPI Cards */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            title="Monitored Servers"
            value={stats.total_servers.toString()}
            subtext={`${stats.active_servers} active`}
            icon={ServerIcon}
            trend={stats.total_servers > 0 ? 'up' : 'neutral'}
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            title="Active Threats"
            value={stats.active_threats.toString()}
            subtext="Detected"
            icon={AlertTriangle}
            trend={stats.active_threats > 0 ? 'up' : 'neutral'}
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            title="Events (24h)"
            value={stats.events_last_24h.toLocaleString()}
            subtext="Total traffic events"
            icon={Shield}
            trend="neutral"
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            title="Alerts (24h)"
            value={stats.alerts_last_24h.toString()}
            subtext="Security alerts"
            icon={Activity}
            trend={stats.alerts_last_24h > 5 ? 'down' : 'neutral'}
          />
        </Col>
      </Row>

      {/* Charts Row */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={16}>
          <TrafficChart />
        </Col>
        <Col xs={24} lg={8}>
          <ServersList servers={servers} />
        </Col>
      </Row>

      {/* Threats & Live Stream */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={16}>
          <ThreatsList threats={threats} />
        </Col>
        <Col xs={24} lg={8}>
          <LiveStream />
        </Col>
      </Row>
    </div>
  )
}
