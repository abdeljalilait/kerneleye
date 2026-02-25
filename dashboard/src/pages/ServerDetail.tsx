import { useParams, Link } from '@tanstack/react-router'
import { Typography, Card, Row, Col, Table, Tag, Spin, Alert, Button, Badge, Popconfirm, App, Tooltip, Progress, Space, Avatar, Modal } from 'antd'
import { ArrowLeft, Server, Activity, Shield, Globe, Trash2, RefreshCw, Clock, MapPin, Wifi, Users } from 'lucide-react'
import type { ColumnsType } from 'antd/es/table'
import { useServer, useServerStats, useServerTraffic, useDeleteServer } from '../hooks/useQueries'
import { useWebSocket } from '../context/WebSocketContext'
import { useEffect, useState, useMemo } from 'react'
import DataGrid from 'react-data-grid'
import 'react-data-grid/lib/styles.css'

const { Title, Text } = Typography

const formatDate = (date: string | null | undefined): string => {
  if (!date) return '-'
  const d = new Date(date)
  if (isNaN(d.getTime()) || d.getFullYear() < 2000 || d.getFullYear() > 2100) return '-'
  return d.toLocaleString()
}

interface TrafficEvent {
  id: string
  source_ip: string
  destination_ip?: string
  destination_port: number
  protocol: string
  direction?: string
  syn_count: number
  ack_count: number
  failed_handshakes: number
  unique_ports: number
  bytes_in: number
  bytes_out: number
  threat_score: number
  threat_level: string
  country: string | null
  city: string | null
  isp: string | null
  hit_count: number
  first_seen: string
  last_seen: string
  created_at: string
}

interface PortTraffic {
  key: string
  port: number
  protocol: string
  sources: TrafficEvent[]
  total_bytes_in: number
  total_bytes_out: number
  total_hits: number
  total_syn: number
  total_ack: number
  max_threat_score: number
  max_threat_level: string
  unique_ips: number
  last_seen: string
}

export default function ServerDetail() {
  const { id } = useParams({ strict: false })
  const { lastMessage, isConnected } = useWebSocket()
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [ipModalOpen, setIpModalOpen] = useState(false)
  const [selectedPortTraffic, setSelectedPortTraffic] = useState<PortTraffic | null>(null)
  
  const { data: server, isLoading: serverLoading, error: serverError, refetch: refetchServer } = useServer(id)
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useServerStats(id)
  const { data: traffic, isLoading: trafficLoading, refetch: refetchTraffic } = useServerTraffic(id, 100)
  
  const deleteMutation = useDeleteServer()
  const { message } = App.useApp()

  const loading = serverLoading || statsLoading || trafficLoading
  const error = serverError ? (serverError as any).response?.data?.error || 'Failed to load server data' : ''

  useEffect(() => {
    if (lastMessage && lastMessage.type === 'new_traffic' && id) {
      const payload = lastMessage.data as any
      if (payload?.server_id === id) {
        refetchTraffic()
        refetchStats()
      }
    }
  }, [lastMessage, id, refetchTraffic, refetchStats])

  const handleRefresh = async () => {
    setIsRefreshing(true)
    try {
      await Promise.all([refetchServer(), refetchStats(), refetchTraffic()])
      message.success('Data refreshed')
    } catch {
      message.error('Failed to refresh')
    } finally {
      setIsRefreshing(false)
    }
  }

  const handleDelete = () => {
    if (!id) return
    deleteMutation.mutate(id, {
      onSuccess: () => {
        message.success('Server deleted successfully')
        window.history.back()
      },
      onError: () => {
        message.error('Failed to delete server')
      }
    })
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const portTraffic = useMemo((): PortTraffic[] => {
    if (!traffic) return []
    const groups = new Map<string, PortTraffic>()
    
    for (const event of (traffic as TrafficEvent[])) {
      const portKey = `${event.destination_port}-${event.protocol}`
      const existing = groups.get(portKey)
      if (existing) {
        existing.sources.push(event)
        existing.total_bytes_in += event.bytes_in || 0
        existing.total_bytes_out += event.bytes_out || 0
        existing.total_hits += event.hit_count || 0
        existing.total_syn += event.syn_count || 0
        existing.total_ack += event.ack_count || 0
        existing.unique_ips = existing.sources.length
        if (event.threat_score > existing.max_threat_score) {
          existing.max_threat_score = event.threat_score
          existing.max_threat_level = event.threat_level
        }
        if (new Date(event.last_seen) > new Date(existing.last_seen)) {
          existing.last_seen = event.last_seen
        }
      } else {
        groups.set(portKey, {
          key: portKey,
          port: event.destination_port,
          protocol: event.protocol,
          sources: [event],
          total_bytes_in: event.bytes_in || 0,
          total_bytes_out: event.bytes_out || 0,
          total_hits: event.hit_count || 0,
          total_syn: event.syn_count || 0,
          total_ack: event.ack_count || 0,
          max_threat_score: event.threat_score,
          max_threat_level: event.threat_level,
          unique_ips: 1,
          last_seen: event.last_seen,
        })
      }
    }
    
    return Array.from(groups.values()).sort(
      (a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime()
    )
  }, [traffic])

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'active':
        return { color: '#10b981', bg: 'rgba(16, 185, 129, 0.15)', text: 'ONLINE' }
      case 'offline':
        return { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)', text: 'OFFLINE' }
      case 'pending':
        return { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)', text: 'PENDING' }
      default:
        return { color: '#64748b', bg: 'rgba(100, 116, 139, 0.15)', text: 'UNKNOWN' }
    }
  }

  const getThreatTag = (level: string) => {
    const configs: Record<string, { color: string; bg: string }> = {
      normal: { color: '#10b981', bg: 'rgba(16, 185, 129, 0.15)' },
      suspicious: { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
      malicious: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
    }
    const config = configs[level] || configs.normal
    return (
      <Tag style={{ background: config.bg, color: config.color, border: 'none', fontWeight: 600 }}>
        {level.toUpperCase()}
      </Tag>
    )
  }

  const portColumns: ColumnsType<PortTraffic> = [
    {
      title: 'Port',
      dataIndex: 'port',
      key: 'port',
      width: 80,
      sorter: (a, b) => a.port - b.port,
      render: (port) => <Text strong style={{ fontFamily: 'monospace', color: 'var(--primary-400)' }}>{port}</Text>,
    },
    {
      title: 'Protocol',
      dataIndex: 'protocol',
      key: 'protocol',
      width: 100,
      render: (proto) => <Tag style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)' }}>{proto}</Tag>,
    },
    {
      title: 'Sources',
      dataIndex: 'unique_ips',
      key: 'sources',
      width: 100,
      render: (count, record) => (
        <Button
          type="link"
          size="small"
          icon={<Users size={14} />}
          onClick={() => {
            setSelectedPortTraffic(record)
            setIpModalOpen(true)
          }}
          style={{ 
            padding: '2px 8px', 
            height: 'auto',
            color: '#3b82f6',
            background: 'rgba(59, 130, 246, 0.15)',
            borderRadius: 4,
          }}
        >
          {count} IP{count > 1 ? 's' : ''}
        </Button>
      ),
    },
    {
      title: 'Bytes In',
      dataIndex: 'total_bytes_in',
      key: 'bytes_in',
      width: 110,
      render: (bytes) => <Text style={{ color: 'var(--text-secondary)' }}>{formatBytes(bytes || 0)}</Text>,
      sorter: (a, b) => a.total_bytes_in - b.total_bytes_in,
    },
    {
      title: 'Bytes Out',
      dataIndex: 'total_bytes_out',
      key: 'bytes_out',
      width: 110,
      render: (bytes) => <Text style={{ color: 'var(--text-secondary)' }}>{formatBytes(bytes || 0)}</Text>,
      sorter: (a, b) => a.total_bytes_out - b.total_bytes_out,
    },
    {
      title: 'Hits',
      dataIndex: 'total_hits',
      key: 'hits',
      width: 80,
      sorter: (a, b) => a.total_hits - b.total_hits,
      render: (hits) => <Text strong style={{ color: 'var(--text-primary)' }}>{hits.toLocaleString()}</Text>,
    },
    {
      title: 'SYN/ACK',
      key: 'syn_ack',
      width: 100,
      render: (_, record) => (
        <Text type="secondary">
          <Text style={{ color: record.total_syn > 10 ? '#ef4444' : 'var(--text-secondary)' }}>{record.total_syn}</Text>
          <span style={{ color: 'var(--text-muted)', margin: '0 4px' }}>/</span>
          <Text style={{ color: 'var(--text-secondary)' }}>{record.total_ack}</Text>
        </Text>
      ),
    },
    {
      title: 'Max Score',
      dataIndex: 'max_threat_score',
      key: 'score',
      width: 100,
      render: (score) => (
        <Progress 
          percent={score} 
          size="small" 
          showInfo={false}
          strokeColor={score > 50 ? '#ef4444' : score > 20 ? '#f59e0b' : '#10b981'}
          trailColor="rgba(255, 255, 255, 0.05)"
          style={{ width: 60 }}
        />
      ),
      sorter: (a, b) => a.max_threat_score - b.max_threat_score,
    },
    {
      title: 'Level',
      dataIndex: 'max_threat_level',
      key: 'level',
      width: 100,
      render: (level) => getThreatTag(level),
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'time',
      render: (date) => <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>{formatDate(date)}</Text>,
      width: 170,
      sorter: (a, b) => new Date(a.last_seen).getTime() - new Date(b.last_seen).getTime(),
      defaultSortOrder: 'descend',
    },
  ]

  const sourceColumns: ColumnsType<TrafficEvent> = [
    {
      title: 'Remote IP',
      key: 'remote_ip',
      width: 150,
      render: (_: unknown, record: TrafficEvent) => {
        const remoteIP = record.direction === 'outbound' ? (record.destination_ip || record.source_ip) : record.source_ip
        const isYou = server?.ip_address && remoteIP === server.ip_address
        return (
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Text code style={{ fontSize: 13, background: 'var(--bg-tertiary)' }}>{remoteIP}</Text>
            {isYou && <Tag color="purple" style={{ margin: 0, fontSize: 10 }}>YOU</Tag>}
          </span>
        )
      },
    },
    {
      title: 'Dir',
      dataIndex: 'direction',
      key: 'direction',
      width: 80,
      render: (dir: string) => (
        dir === 'outbound' 
          ? <Tag style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6', border: 'none' }}>↑ OUT</Tag>
          : <Tag style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: 'none' }}>↓ IN</Tag>
      ),
    },
    {
      title: 'Location',
      key: 'location',
      width: 150,
      render: (_, record) => (
        <Space size={4}>
          <MapPin size={12} style={{ opacity: 0.5 }} />
          <span>
            {record.country ? <Text style={{ color: 'var(--text-secondary)' }}>{record.country}</Text> : <Text type="secondary">-</Text>}
            {record.city && <Text type="secondary"> / {record.city}</Text>}
          </span>
        </Space>
      ),
    },
    {
      title: 'Bytes In',
      dataIndex: 'bytes_in',
      key: 'bytes_in',
      width: 100,
      render: (bytes) => <Text style={{ color: 'var(--text-secondary)' }}>{formatBytes(bytes || 0)}</Text>,
    },
    {
      title: 'Bytes Out',
      dataIndex: 'bytes_out',
      key: 'bytes_out',
      width: 100,
      render: (bytes) => <Text style={{ color: 'var(--text-secondary)' }}>{formatBytes(bytes || 0)}</Text>,
    },
    {
      title: 'SYN/ACK',
      key: 'syn_ack',
      width: 90,
      render: (_, record) => (
        <span>
          <Text style={{ color: record.syn_count > 10 ? '#ef4444' : 'var(--text-secondary)' }}>{record.syn_count}</Text>
          <span style={{ color: 'var(--text-muted)', margin: '0 4px' }}>/</span>
          {record.ack_count}
        </span>
      ),
    },
    {
      title: 'Hits',
      dataIndex: 'hit_count',
      key: 'hits',
      width: 70,
    },
    {
      title: 'Score',
      dataIndex: 'threat_score',
      key: 'score',
      width: 70,
      render: (score) => (
        <Text style={{ color: score > 50 ? '#ef4444' : score > 20 ? '#f59e0b' : '#10b981', fontWeight: 600 }}>
          {score}
        </Text>
      ),
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 160,
      render: (date) => <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>{formatDate(date)}</Text>,
    },
  ]

  // DataGrid columns for the IP modal
  const ipGridColumns = [
    { key: 'source_ip', name: 'Remote IP', width: 140, frozen: true },
    { 
      key: 'direction', 
      name: 'Dir', 
      width: 70,
      formatter: ({ row }: { row: TrafficEvent }) => (
        row.direction === 'outbound' 
          ? <Tag style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6', border: 'none', fontSize: 10 }}>↑ OUT</Tag>
          : <Tag style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: 'none', fontSize: 10 }}>↓ IN</Tag>
      )
    },
    { key: 'country', name: 'Country', width: 100, formatter: ({ row }: { row: TrafficEvent }) => row.country || '-' },
    { key: 'city', name: 'City', width: 100, formatter: ({ row }: { row: TrafficEvent }) => row.city || '-' },
    { 
      key: 'bytes_in', 
      name: 'Bytes In', 
      width: 90,
      formatter: ({ row }: { row: TrafficEvent }) => formatBytes(row.bytes_in || 0)
    },
    { 
      key: 'bytes_out', 
      name: 'Bytes Out', 
      width: 90,
      formatter: ({ row }: { row: TrafficEvent }) => formatBytes(row.bytes_out || 0)
    },
    { 
      key: 'syn_count', 
      name: 'SYN', 
      width: 60,
      formatter: ({ row }: { row: TrafficEvent }) => (
        <span style={{ color: row.syn_count > 10 ? '#ef4444' : 'inherit' }}>{row.syn_count}</span>
      )
    },
    { key: 'ack_count', name: 'ACK', width: 60 },
    { key: 'hit_count', name: 'Hits', width: 70 },
    { 
      key: 'threat_score', 
      name: 'Score', 
      width: 70,
      formatter: ({ row }: { row: TrafficEvent }) => (
        <span style={{ 
          color: row.threat_score > 50 ? '#ef4444' : row.threat_score > 20 ? '#f59e0b' : '#10b981',
          fontWeight: 600 
        }}>
          {row.threat_score}
        </span>
      )
    },
    { 
      key: 'last_seen', 
      name: 'Last Seen', 
      width: 150,
      formatter: ({ row }: { row: TrafficEvent }) => formatDate(row.last_seen)
    },
  ]

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <Spin size="large" />
      </div>
    )
  }

  if (error) {
    return (
      <Alert 
        message="Error" 
        description={error} 
        type="error" 
        showIcon 
        style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)' }}
      />
    )
  }

  const statusConfig = getStatusConfig(server?.status || '')

  return (
    <div>
      {/* Back Button */}
      <div style={{ marginBottom: 24 }}>
        <Link to="/dashboard/servers">
          <Button 
            icon={<ArrowLeft size={16} />} 
            type="text"
            style={{ color: 'var(--text-secondary)' }}
          >
            Back to Servers
          </Button>
        </Link>
      </div>

      {/* Header */}
      <Row justify="space-between" align="middle" style={{ marginBottom: 32 }}>
        <Col>
          <Space size={20} align="center">
            <Avatar
              size={64}
              style={{
                background: statusConfig.bg,
                border: `2px solid ${statusConfig.color}40`,
              }}
              icon={<Server size={32} color={statusConfig.color} />}
            />
            <div>
              <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
                {server?.hostname}
              </Title>
              <Space size={12} style={{ marginTop: 8 }}>
                <Tag 
                  style={{ 
                    background: statusConfig.bg, 
                    color: statusConfig.color, 
                    border: 'none',
                    fontWeight: 600,
                    fontSize: 12,
                  }}
                >
                  {statusConfig.text}
                </Tag>
                <Tooltip title={isConnected ? 'Live updates active' : 'Live updates disconnected'}>
                  <Space size={6}>
                    <span 
                      style={{ 
                        width: 8, 
                        height: 8, 
                        borderRadius: '50%', 
                        background: isConnected ? '#10b981' : '#64748b',
                        boxShadow: isConnected ? '0 0 8px #10b981' : 'none',
                      }} 
                    />
                    <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                      {isConnected ? 'Live' : 'Offline'}
                    </Text>
                  </Space>
                </Tooltip>
              </Space>
            </div>
          </Space>
        </Col>
        <Col>
          <Space>
            <Tooltip title="Refresh data">
              <Button 
                icon={<RefreshCw size={16} />} 
                onClick={handleRefresh}
                loading={isRefreshing}
                style={{
                  background: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-secondary)',
                }}
              >
                Refresh
              </Button>
            </Tooltip>
            <Popconfirm
              title="Delete Server"
              description="Are you sure you want to delete this server? This action cannot be undone."
              onConfirm={handleDelete}
              okText="Yes, Delete"
              cancelText="No"
              okButtonProps={{ danger: true, loading: deleteMutation.isPending }}
            >
              <Button 
                danger 
                icon={<Trash2 size={16} />} 
                loading={deleteMutation.isPending}
              >
                Delete
              </Button>
            </Popconfirm>
          </Space>
        </Col>
      </Row>

      {/* Server Info Card */}
      <Card
        variant="borderless"
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          marginBottom: 24,
        }}
        bodyStyle={{ padding: 24 }}
      >
        <Row gutter={[32, 16]}>
          <Col xs={24} sm={12} md={6}>
            <Space direction="vertical" size={4}>
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                IP Address
              </Text>
              <Text code style={{ fontSize: 14, background: 'var(--bg-tertiary)', padding: '4px 12px', borderRadius: 6 }}>
                {server?.ip_address || '-'}
              </Text>
            </Space>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Space direction="vertical" size={4}>
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Agent Version
              </Text>
              <Text strong style={{ color: 'var(--text-primary)', fontSize: 14 }}>
                {server?.agent_version || '-'}
              </Text>
            </Space>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Space direction="vertical" size={4}>
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Last Seen
              </Text>
              <Space size={6}>
                <Clock size={14} style={{ opacity: 0.5 }} />
                <Text style={{ color: 'var(--text-secondary)', fontSize: 14 }}>
                  {server?.last_seen ? new Date(server.last_seen).toLocaleString() : '-'}
                </Text>
              </Space>
            </Space>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Space direction="vertical" size={4}>
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Connection
              </Text>
              <Space size={6}>
                <Wifi size={14} color={isConnected ? '#10b981' : '#ef4444'} />
                <Text style={{ color: isConnected ? '#10b981' : '#ef4444', fontSize: 14 }}>
                  {isConnected ? 'Connected' : 'Disconnected'}
                </Text>
              </Space>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* Stats Grid */}
      <Row gutter={[20, 20]} style={{ marginBottom: 24 }}>
        <Col xs={12} sm={6}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space align="center" size={12}>
              <div style={{ width: 40, height: 40, background: 'rgba(99, 102, 241, 0.15)', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Activity size={20} color="#818cf8" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 11, display: 'block' }}>Total Events</Text>
                <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>
                  {(stats?.total_events || 0).toLocaleString()}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space align="center" size={12}>
              <div style={{ width: 40, height: 40, background: 'rgba(6, 182, 212, 0.15)', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Clock size={20} color="#06b6d4" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 11, display: 'block' }}>Events (24h)</Text>
                <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>
                  {(stats?.events_last_24h || 0).toLocaleString()}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space align="center" size={12}>
              <div style={{ width: 40, height: 40, background: 'rgba(239, 68, 68, 0.15)', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Shield size={20} color="#ef4444" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 11, display: 'block' }}>Threat Events</Text>
                <Title level={4} style={{ margin: 0, color: (stats?.threat_events || 0) > 0 ? '#ef4444' : 'var(--text-primary)' }}>
                  {(stats?.threat_events || 0).toLocaleString()}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space align="center" size={12}>
              <div style={{ width: 40, height: 40, background: 'rgba(16, 185, 129, 0.15)', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Globe size={20} color="#10b981" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 11, display: 'block' }}>Total Traffic</Text>
                <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>
                  {formatBytes((stats?.total_bytes_in || 0) + (stats?.total_bytes_out || 0))}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      {/* Traffic Table */}
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
            <Globe size={18} color="#818cf8" />
            <Text strong style={{ color: 'var(--text-primary)' }}>Recent Traffic Events</Text>
          </Space>
        }
        extra={
          <Space>
            <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
              {isConnected ? '● Live' : '○ Paused'}
            </Text>
            <Badge 
              count={portTraffic.length} 
              style={{ background: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
            />
          </Space>
        }
      >
        <Table
          columns={portColumns}
          dataSource={portTraffic}
          rowKey="key"
          pagination={{ pageSize: 15, size: 'small' }}
          size="small"
          scroll={{ x: 1100 }}
          locale={{ 
            emptyText: (
              <div style={{ padding: '60px 0', textAlign: 'center' }}>
                <div style={{ marginBottom: 16 }}>
                  <Globe size={64} color="var(--text-muted)" opacity={0.3} />
                </div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 16 }}>
                  No traffic events yet
                </Text>
              </div>
            ) 
          }}
        />
      </Card>

      {/* IP List Modal with react-data-grid */}
      <Modal
        title={
          <Space>
            <Users size={20} color="#3b82f6" />
            <span>
              Source IPs for Port {selectedPortTraffic?.port}/{selectedPortTraffic?.protocol}
            </span>
            <Badge 
              count={selectedPortTraffic?.sources.length || 0} 
              style={{ background: '#3b82f6' }}
            />
          </Space>
        }
        open={ipModalOpen}
        onCancel={() => setIpModalOpen(false)}
        footer={null}
        width={1200}
        style={{ top: 50 }}
        bodyStyle={{ padding: 0, height: 600 }}
      >
        {selectedPortTraffic && (
          <DataGrid
            columns={ipGridColumns}
            rows={selectedPortTraffic.sources}
            rowKeyGetter={(row) => row.id}
            style={{ height: '100%' }}
            className="rdg-dark"
            headerRowHeight={40}
            rowHeight={36}
          />
        )}
      </Modal>
    </div>
  )
}
