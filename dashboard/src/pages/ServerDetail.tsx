import { useParams, Link } from '@tanstack/react-router'
import { Typography, Card, Row, Col, Table, Tag, Spin, Alert, Button, Statistic, Descriptions, Badge, Popconfirm, App, Tooltip } from 'antd'
import { ArrowLeft, Server, Activity, Shield, Globe, Trash2, RefreshCw } from 'lucide-react'
import type { ColumnsType } from 'antd/es/table'
import { useServer, useServerStats, useServerTraffic, useDeleteServer } from '../hooks/useQueries'
import { useWebSocket } from '../context/WebSocketContext'
import { useEffect, useState, useMemo } from 'react'

const { Title, Text } = Typography

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

// Port-centric traffic data - ports in foreground with expandable IP details
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
  
  const { data: server, isLoading: serverLoading, error: serverError, refetch: refetchServer } = useServer(id)
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useServerStats(id)
  const { data: traffic, isLoading: trafficLoading, refetch: refetchTraffic } = useServerTraffic(id, 100)
  
  const deleteMutation = useDeleteServer()
  const { message } = App.useApp()

  const loading = serverLoading || statsLoading || trafficLoading
  const error = serverError ? (serverError as any).response?.data?.error || 'Failed to load server data' : ''

  // Listen for WebSocket updates for this server
  useEffect(() => {
    if (lastMessage && lastMessage.type === 'new_traffic' && id) {
      // Check if the traffic event is for this server
      const payload = lastMessage.data as any
      if (payload?.server_id === id) {
        // Refetch traffic and stats when new traffic comes in
        refetchTraffic()
        refetchStats()
      }
    }
  }, [lastMessage, id, refetchTraffic, refetchStats])

  // Manual refresh handler
  const handleRefresh = async () => {
    setIsRefreshing(true)
    try {
      await Promise.all([
        refetchServer(),
        refetchStats(),
        refetchTraffic()
      ])
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
        window.history.back() // Simple back or navigate to /dashboard/servers
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

  // Group traffic by port for expandable rows - ports in foreground
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
    
    // Sort by last_seen descending
    return Array.from(groups.values()).sort(
      (a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime()
    )
  }, [traffic])


  const getThreatTag = (level: string) => {
    const colors: Record<string, string> = {
      normal: 'green',
      suspicious: 'orange',
      malicious: 'red',
    }
    return <Tag color={colors[level] || 'default'}>{level}</Tag>
  }

  // Columns for the main table - one row per port
  const portColumns: ColumnsType<PortTraffic> = [
    {
      title: 'Port',
      dataIndex: 'port',
      key: 'port',
      width: 80,
      sorter: (a, b) => a.port - b.port,
    },
    {
      title: 'Protocol',
      dataIndex: 'protocol',
      key: 'protocol',
      width: 100,
      render: (proto) => <Tag>{proto}</Tag>,
    },
    {
      title: 'Sources',
      dataIndex: 'unique_ips',
      key: 'sources',
      width: 80,
      render: (count) => <Tag color="blue">{count} IP{count > 1 ? 's' : ''}</Tag>,
    },
    {
      title: 'Bytes In',
      dataIndex: 'total_bytes_in',
      key: 'bytes_in',
      width: 100,
      render: (bytes) => formatBytes(bytes || 0),
      sorter: (a, b) => a.total_bytes_in - b.total_bytes_in,
    },
    {
      title: 'Bytes Out',
      dataIndex: 'total_bytes_out',
      key: 'bytes_out',
      width: 100,
      render: (bytes) => formatBytes(bytes || 0),
      sorter: (a, b) => a.total_bytes_out - b.total_bytes_out,
    },
    {
      title: 'Hits',
      dataIndex: 'total_hits',
      key: 'hits',
      width: 60,
      sorter: (a, b) => a.total_hits - b.total_hits,
    },
    {
      title: 'SYN/ACK',
      key: 'syn_ack',
      width: 90,
      render: (_, record) => (
        <Text type="secondary">
          <Text style={{ color: record.total_syn > 10 ? '#ff4d4f' : undefined }}>{record.total_syn}</Text>
          {' / '}
          <Text>{record.total_ack}</Text>
        </Text>
      ),
    },
    {
      title: 'Max Score',
      dataIndex: 'max_threat_score',
      key: 'score',
      width: 80,
      render: (score) => (
        <Text style={{ color: score > 50 ? '#ff4d4f' : score > 20 ? '#faad14' : '#52c41a' }}>
          {score}
        </Text>
      ),
      sorter: (a, b) => a.max_threat_score - b.max_threat_score,
    },
    {
      title: 'Level',
      dataIndex: 'max_threat_level',
      key: 'level',
      width: 90,
      render: (level) => getThreatTag(level),
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'time',
      render: (date) => new Date(date).toLocaleString(),
      width: 160,
      sorter: (a, b) => new Date(a.last_seen).getTime() - new Date(b.last_seen).getTime(),
      defaultSortOrder: 'descend',
    },
  ]

  // Columns for the expanded (child) rows - one row per source IP
  const sourceColumns: ColumnsType<TrafficEvent> = [
    {
      title: 'Remote IP',
      key: 'remote_ip',
      width: 150,
      render: (_: unknown, record: TrafficEvent) => {
        // For inbound: source_ip is the remote caller
        // For outbound: destination_ip is the remote server we connected to
        const remoteIP = record.direction === 'outbound' 
          ? (record.destination_ip || record.source_ip) 
          : record.source_ip
        const isYou = server?.ip_address && remoteIP === server.ip_address
        return (
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Text code style={{ fontSize: 13 }}>{remoteIP}</Text>
            {isYou && <Tag color="purple" style={{ margin: 0 }}>YOU</Tag>}
          </span>
        )
      },
    },
    {
      title: 'Dir',
      dataIndex: 'direction',
      key: 'direction',
      width: 70,
      render: (dir: string) => (
        dir === 'outbound' 
          ? <Tag color="blue">↑ OUT</Tag>
          : <Tag color="green">↓ IN</Tag>
      ),
    },
    {
      title: 'Location',
      key: 'location',
      width: 150,
      render: (_, record) => (
        <span>
          {record.country && <Text>{record.country}</Text>}
          {record.city && <Text type="secondary"> / {record.city}</Text>}
          {!record.country && <Text type="secondary">-</Text>}
        </span>
      ),
    },
    {
      title: 'Bytes In',
      dataIndex: 'bytes_in',
      key: 'bytes_in',
      width: 100,
      render: (bytes) => formatBytes(bytes || 0),
    },
    {
      title: 'Bytes Out',
      dataIndex: 'bytes_out',
      key: 'bytes_out',
      width: 100,
      render: (bytes) => formatBytes(bytes || 0),
    },
    {
      title: 'SYN/ACK',
      key: 'syn_ack',
      width: 90,
      render: (_, record) => (
        <span>
          <Text style={{ color: record.syn_count > 10 ? '#ff4d4f' : undefined }}>{record.syn_count}</Text>
          {' / '}
          {record.ack_count}
        </span>
      ),
    },
    {
      title: 'Hits',
      dataIndex: 'hit_count',
      key: 'hits',
      width: 60,
    },
    {
      title: 'Score',
      dataIndex: 'threat_score',
      key: 'score',
      width: 60,
      render: (score) => (
        <Text style={{ color: score > 50 ? '#ff4d4f' : score > 20 ? '#faad14' : '#52c41a' }}>
          {score}
        </Text>
      ),
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 160,
      render: (date) => new Date(date).toLocaleString(),
    },
  ]

  // Render expanded row content with source IP details
  const expandedRowRender = (record: PortTraffic) => (
    <Table
      columns={sourceColumns}
      dataSource={record.sources}
      rowKey="id"
      pagination={false}
      size="small"
      style={{ margin: '8px 0' }}
    />
  )

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 300 }}>
        <Spin size="large" />
      </div>
    )
  }

  if (error) {
    return <Alert message="Error" description={error} type="error" showIcon />
  }

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Link to="/dashboard/servers">
          <Button icon={<ArrowLeft size={16} />} type="text">Back to Servers</Button>
        </Link>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ 
            width: 48, height: 48, borderRadius: 8, 
            background: server?.status === 'active' ? '#52c41a' : '#faad14',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <Server size={24} color="white" />
          </div>
          <div>
            <Title level={2} style={{ margin: 0 }}>{server?.hostname}</Title>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Badge 
                status={server?.status === 'active' ? 'success' : 'warning'} 
                text={server?.status} 
              />
              <Tooltip title={isConnected ? 'Live updates active' : 'Live updates disconnected'}>
                <Badge 
                  status={isConnected ? 'processing' : 'default'} 
                  text={isConnected ? 'Live' : 'Offline'} 
                />
              </Tooltip>
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Tooltip title="Refresh data">
            <Button 
              icon={<RefreshCw size={16} className={isRefreshing ? 'spin-animation' : ''} />} 
              onClick={handleRefresh}
              loading={isRefreshing}
            >
              Refresh
            </Button>
          </Tooltip>
          <Popconfirm
            title="Delete Server"
            description="Are you sure you want to delete this server? The agent will terminate itself and all data will be lost."
            onConfirm={handleDelete}
            okText="Yes, Delete"
            cancelText="No"
            okButtonProps={{ danger: true, loading: deleteMutation.isPending }}
          >
            <Button danger icon={<Trash2 size={16} />} loading={deleteMutation.isPending}>
              Delete Server
            </Button>
          </Popconfirm>
        </div>
      </div>

      {/* Server Info */}
      <Card style={{ marginBottom: 24 }}>
        <Descriptions column={{ xs: 1, sm: 2, md: 4 }} size="small">
          <Descriptions.Item label="IP Address">{server?.ip_address || '-'}</Descriptions.Item>
          <Descriptions.Item label="Agent Version">{server?.agent_version || '-'}</Descriptions.Item>
          <Descriptions.Item label="Last Seen">{server?.last_seen ? new Date(server.last_seen).toLocaleString() : '-'}</Descriptions.Item>
        </Descriptions>
      </Card>

      {/* Stats */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic 
              title="Total Events" 
              value={stats?.total_events || 0} 
              prefix={<Activity size={16} />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic 
              title="Events (24h)" 
              value={stats?.events_last_24h || 0}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic 
              title="Threat Events" 
              value={stats?.threat_events || 0} 
              valueStyle={{ color: (stats?.threat_events || 0) > 0 ? '#ff4d4f' : undefined }}
              prefix={<Shield size={16} />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic 
              title="Traffic" 
              value={formatBytes((stats?.total_bytes_in || 0) + (stats?.total_bytes_out || 0))}
              prefix={<Globe size={16} />}
            />
          </Card>
        </Col>
      </Row>

      {/* Traffic Events Table */}
      <Card 
        title="Recent Traffic Events"
        extra={
          <Text type="secondary" style={{ fontSize: 12 }}>
            {isConnected ? '🟢 Live updates enabled' : '⚪ Updates paused'}
          </Text>
        }
      >
        <Table
          columns={portColumns}
          dataSource={portTraffic}
          rowKey="key"
          pagination={{ pageSize: 20 }}
          size="small"
          scroll={{ x: 1000 }}
          expandable={{
            expandedRowRender,
            rowExpandable: (record) => record.sources.length > 0,
          }}
          locale={{ emptyText: 'No traffic events yet' }}
        />
      </Card>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .spin-animation {
          animation: spin 1s linear infinite;
        }
      `}</style>
    </div>
  )
}
