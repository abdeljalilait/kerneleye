import { useParams, Link } from '@tanstack/react-router'
import { Typography, Card, Row, Col, Table, Tag, Spin, Alert, Button, Badge, Popconfirm, App, Tooltip, Progress, Space, Avatar, Modal, Input } from 'antd'
import { ArrowLeft, Server, Activity, Shield, Globe, Trash2, RefreshCw, Clock, MapPin, Wifi, Users, Search, ArrowUpDown, ArrowDownLeft, ArrowUpRight, Flag, AlertTriangle, AlertCircle, CheckCircle2 } from 'lucide-react'
import type { ColumnsType } from 'antd/es/table'
import { useServer, useServerStats, useServerPortTraffic, useDeleteServer } from '../hooks/useQueries'
import type { PortTraffic, PortSourceIP } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useEffect, useState, useMemo } from 'react'
import { DataGrid } from 'react-data-grid'
import 'react-data-grid/lib/styles.css'
import type { SortColumn } from 'react-data-grid'

const { Title, Text } = Typography

const formatDate = (date: string | null | undefined): string => {
  if (!date) return '-'
  const d = new Date(date)
  if (isNaN(d.getTime()) || d.getFullYear() < 2000 || d.getFullYear() > 2100) return '-'
  return d.toLocaleString()
}



interface PortTrafficWithKey extends PortTraffic {
  key: string
}

export default function ServerDetail() {
  const { id } = useParams({ strict: false })
  const { lastMessage, isConnected } = useWebSocket()
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [ipModalOpen, setIpModalOpen] = useState(false)
  const [selectedPortTraffic, setSelectedPortTraffic] = useState<PortTraffic | null>(null)
  const [ipFilter, setIpFilter] = useState('')
  const [sortColumns, setSortColumns] = useState<readonly SortColumn[]>([])
  
  const { data: server, isLoading: serverLoading, error: serverError, refetch: refetchServer } = useServer(id)
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useServerStats(id)
  const [trafficParams, setTrafficParams] = useState({ page: 1, page_size: 50, search: '', sort_by: 'last_seen' })
  const { data: trafficResponse, isLoading: trafficLoading, refetch: refetchTraffic } = useServerPortTraffic(id, trafficParams)
  const portTraffic: PortTrafficWithKey[] = useMemo(() => {
    return (trafficResponse?.data || []).map(p => ({
      ...p,
      key: `${p.port}-${p.protocol}`,
    }))
  }, [trafficResponse])
  const trafficPagination = trafficResponse?.pagination
  
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

  // Sort function for DataGrid
  function getComparator(sortColumn: string) {
    return (a: PortSourceIP, b: PortSourceIP) => {
      let aVal: any, bVal: any
      
      switch (sortColumn) {
        case 'source_ip':
          aVal = a.source_ip
          bVal = b.source_ip
          break
        case 'direction':
          aVal = a.direction || ''
          bVal = b.direction || ''
          break
        case 'country':
          aVal = a.country || ''
          bVal = b.country || ''
          break
        case 'city':
          aVal = a.city || ''
          bVal = b.city || ''
          break
        case 'bytes_in':
          aVal = a.bytes_in || 0
          bVal = b.bytes_in || 0
          break
        case 'bytes_out':
          aVal = a.bytes_out || 0
          bVal = b.bytes_out || 0
          break
        case 'syn_count':
          aVal = a.syn_count || 0
          bVal = b.syn_count || 0
          break
        case 'ack_count':
          aVal = a.ack_count || 0
          bVal = b.ack_count || 0
          break
        case 'hit_count':
          aVal = a.hit_count || 0
          bVal = b.hit_count || 0
          break
        case 'threat_score':
          aVal = a.threat_score || 0
          bVal = b.threat_score || 0
          break
        case 'last_seen':
          aVal = new Date(a.last_seen || 0).getTime()
          bVal = new Date(b.last_seen || 0).getTime()
          break
        default:
          return 0
      }
      
      if (typeof aVal === 'string') {
        return aVal.localeCompare(bVal)
      }
      return aVal - bVal
    }
  }

  // Filter and sort the IP data
  const filteredAndSortedRows = useMemo(() => {
    if (!selectedPortTraffic) return []
    
    let rows = [...selectedPortTraffic.sources]
    
    // Apply filter
    if (ipFilter.trim()) {
      const filter = ipFilter.toLowerCase()
      rows = rows.filter(row => 
        row.source_ip?.toLowerCase().includes(filter) ||
        row.country?.toLowerCase().includes(filter) ||
        row.city?.toLowerCase().includes(filter)
      )
    }
    
    // Apply sorting
    if (sortColumns.length > 0) {
      const { columnKey, direction } = sortColumns[0]
      const comparator = getComparator(columnKey)
      rows.sort((a, b) => {
        const comp = comparator(a, b)
        return direction === 'DESC' ? -comp : comp
      })
    }
    
    return rows
  }, [selectedPortTraffic, ipFilter, sortColumns])

  // Get threat icon based on score
  const getThreatIcon = (score: number) => {
    if (score >= 50) return <AlertTriangle size={14} style={{ color: '#ef4444' }} />;
    if (score >= 20) return <AlertCircle size={14} style={{ color: '#f59e0b' }} />;
    return <CheckCircle2 size={14} style={{ color: '#10b981' }} />;
  };

  // Get threat color for background/badge
  const getThreatColor = (score: number) => {
    if (score >= 50) return { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444', border: 'rgba(239, 68, 68, 0.3)' };
    if (score >= 20) return { bg: 'rgba(245, 158, 11, 0.15)', text: '#f59e0b', border: 'rgba(245, 158, 11, 0.3)' };
    return { bg: 'rgba(16, 185, 129, 0.15)', text: '#10b981', border: 'rgba(16, 185, 129, 0.3)' };
  };

  // DataGrid columns for the IP modal - using flex to fill width
  const ipGridColumns = [
    { 
      key: 'source_ip', 
      name: 'Remote IP', 
      minWidth: 140, 
      width: '16%', 
      frozen: true, 
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Globe size={14} style={{ color: 'var(--text-muted)', opacity: 0.7 }} />
          <Text code style={{ fontSize: 12, background: 'var(--bg-tertiary)', padding: '2px 6px', borderRadius: 4, fontFamily: 'monospace' }}>
            {row.source_ip}
          </Text>
        </div>
      )
    },
    { 
      key: 'direction', 
      name: 'Dir', 
      minWidth: 75,
      width: '7%',
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => {
        const isOutbound = row.direction === 'outbound';
        return (
          <div style={{ 
            display: 'inline-flex', 
            alignItems: 'center', 
            gap: 4,
            padding: '4px 8px',
            borderRadius: 12,
            background: isOutbound ? 'rgba(59, 130, 246, 0.15)' : 'rgba(16, 185, 129, 0.15)',
            border: `1px solid ${isOutbound ? 'rgba(59, 130, 246, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
          }}>
            {isOutbound ? (
              <ArrowUpRight size={12} style={{ color: '#3b82f6' }} />
            ) : (
              <ArrowDownLeft size={12} style={{ color: '#10b981' }} />
            )}
            <span style={{ 
              fontSize: 10, 
              fontWeight: 600,
              color: isOutbound ? '#3b82f6' : '#10b981',
              textTransform: 'uppercase'
            }}>
              {isOutbound ? 'OUT' : 'IN'}
            </span>
          </div>
        );
      }
    },
    { 
      key: 'country', 
      name: 'Country', 
      minWidth: 110, 
      width: '11%', 
      sortable: true, 
      formatter: ({ row }: { row: PortSourceIP }) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Flag size={13} style={{ color: 'var(--text-muted)', opacity: 0.7 }} />
          <span style={{ color: row.country ? 'var(--text-primary)' : 'var(--text-muted)' }}>
            {row.country || 'Unknown'}
          </span>
        </div>
      )
    },
    { 
      key: 'city', 
      name: 'City', 
      minWidth: 100, 
      width: '10%', 
      sortable: true, 
      formatter: ({ row }: { row: PortSourceIP }) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <MapPin size={13} style={{ color: 'var(--text-muted)', opacity: 0.7 }} />
          <span style={{ color: row.city ? 'var(--text-secondary)' : 'var(--text-muted)' }}>
            {row.city || '-'}
          </span>
        </div>
      )
    },
    { 
      key: 'bytes_in', 
      name: '↓ In', 
      minWidth: 85,
      width: '9%',
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <ArrowDownLeft size={12} style={{ color: '#10b981', opacity: 0.7 }} />
          <span style={{ 
            color: (row.bytes_in || 0) > 1000000 ? '#10b981' : 'var(--text-secondary)',
            fontWeight: (row.bytes_in || 0) > 1000000 ? 600 : 400,
            fontSize: 12
          }}>
            {formatBytes(row.bytes_in || 0)}
          </span>
        </div>
      )
    },
    { 
      key: 'bytes_out', 
      name: '↑ Out', 
      minWidth: 85,
      width: '9%',
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <ArrowUpRight size={12} style={{ color: '#3b82f6', opacity: 0.7 }} />
          <span style={{ 
            color: (row.bytes_out || 0) > 1000000 ? '#3b82f6' : 'var(--text-secondary)',
            fontWeight: (row.bytes_out || 0) > 1000000 ? 600 : 400,
            fontSize: 12
          }}>
            {formatBytes(row.bytes_out || 0)}
          </span>
        </div>
      )
    },
    { 
      key: 'syn_count', 
      name: 'SYN', 
      minWidth: 55,
      width: '5%',
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => (
        <div style={{ 
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '2px 8px',
          borderRadius: 10,
          background: row.syn_count > 10 ? 'rgba(239, 68, 68, 0.15)' : 'var(--bg-tertiary)',
          border: `1px solid ${row.syn_count > 10 ? 'rgba(239, 68, 68, 0.3)' : 'var(--border-subtle)'}`,
        }}>
          <span style={{ 
            color: row.syn_count > 10 ? '#ef4444' : 'var(--text-secondary)',
            fontWeight: row.syn_count > 10 ? 600 : 400,
            fontSize: 12
          }}>
            {row.syn_count}
          </span>
        </div>
      )
    },
    { 
      key: 'ack_count', 
      name: 'ACK', 
      minWidth: 55, 
      width: '5%', 
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => (
        <div style={{ 
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '2px 8px',
          borderRadius: 10,
          background: 'var(--bg-tertiary)',
          border: '1px solid var(--border-subtle)',
        }}>
          <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
            {row.ack_count}
          </span>
        </div>
      )
    },
    { 
      key: 'hit_count', 
      name: 'Hits', 
      minWidth: 65, 
      width: '6%', 
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => (
        <div style={{ 
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 4,
          padding: '2px 8px',
          borderRadius: 10,
          background: row.hit_count > 50 ? 'rgba(99, 102, 241, 0.15)' : 'var(--bg-tertiary)',
          border: `1px solid ${row.hit_count > 50 ? 'rgba(99, 102, 241, 0.3)' : 'var(--border-subtle)'}`,
        }}>
          <Activity size={11} style={{ color: row.hit_count > 50 ? '#6366f1' : 'var(--text-muted)' }} />
          <span style={{ 
            color: row.hit_count > 50 ? '#6366f1' : 'var(--text-secondary)',
            fontWeight: row.hit_count > 50 ? 600 : 400,
            fontSize: 12
          }}>
            {row.hit_count}
          </span>
        </div>
      )
    },
    { 
      key: 'threat_score', 
      name: 'Risk', 
      minWidth: 75,
      width: '7%',
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => {
        const colors = getThreatColor(row.threat_score);
        return (
          <div style={{ 
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 4,
            padding: '3px 10px',
            borderRadius: 12,
            background: colors.bg,
            border: `1px solid ${colors.border}`,
          }}>
            {getThreatIcon(row.threat_score)}
            <span style={{ 
              color: colors.text,
              fontWeight: 700,
              fontSize: 12
            }}>
              {row.threat_score}
            </span>
          </div>
        );
      }
    },
    { 
      key: 'last_seen', 
      name: 'Last Seen', 
      minWidth: 140,
      width: '12%',
      sortable: true,
      formatter: ({ row }: { row: PortSourceIP }) => {
        const isRecent = new Date(row.last_seen).getTime() > Date.now() - 5 * 60 * 1000; // 5 minutes
        return (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={13} style={{ 
              color: isRecent ? '#10b981' : 'var(--text-muted)',
              opacity: isRecent ? 1 : 0.5
            }} />
            <span style={{ 
              color: isRecent ? '#10b981' : 'var(--text-tertiary)', 
              fontSize: 12,
              fontWeight: isRecent ? 500 : 400
            }}>
              {formatDate(row.last_seen)}
            </span>
            {isRecent && (
              <span style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: '#10b981',
                boxShadow: '0 0 6px #10b981',
                animation: 'pulse 2s infinite'
              }} />
            )}
          </div>
        );
      }
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
            <Input
              placeholder="Search IP, country..."
              value={trafficParams.search}
              onChange={(e) => setTrafficParams(p => ({ ...p, search: e.target.value, page: 1 }))}
              style={{ width: 180 }}
              size="small"
              prefix={<Search size={14} />}
            />
            <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
              {isConnected ? '● Live' : '○ Paused'}
            </Text>
            <Badge 
              count={trafficPagination?.total_count || portTraffic.length} 
              style={{ background: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
            />
          </Space>
        }
      >
        <Table
          columns={portColumns}
          dataSource={portTraffic}
          rowKey="key"
          pagination={trafficPagination ? {
            current: trafficPagination.page,
            pageSize: trafficPagination.page_size,
            total: trafficPagination.total_count,
            showSizeChanger: true,
            pageSizeOptions: ['25', '50', '100'],
            showTotal: (total) => `${total} events`,
            onChange: (page, pageSize) => setTrafficParams(p => ({ ...p, page, page_size: pageSize || 50 })),
          } : { pageSize: 15, size: 'small' }}
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
              count={filteredAndSortedRows.length} 
              style={{ background: '#3b82f6' }}
            />
            {ipFilter && (
              <Tag style={{ fontSize: 11 }}>
                Filtered from {selectedPortTraffic?.sources.length || 0}
              </Tag>
            )}
          </Space>
        }
        open={ipModalOpen}
        onCancel={() => {
          setIpModalOpen(false)
          setIpFilter('')
          setSortColumns([])
        }}
        footer={null}
        width="95vw"
        style={{ top: 50, maxWidth: 1400 }}
        bodyStyle={{ padding: 0 }}
      >
        {selectedPortTraffic && (
          <div style={{ display: 'flex', flexDirection: 'column', height: 600 }}>
            {/* Filter Bar */}
            <div style={{ 
              padding: '12px 16px', 
              borderBottom: '1px solid var(--border-subtle)',
              background: 'var(--bg-tertiary)',
              display: 'flex',
              gap: 12,
              alignItems: 'center'
            }}>
              <Search size={16} color="var(--text-tertiary)" />
              <Input
                placeholder="Filter by IP, country, or city..."
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                style={{ 
                  width: 300,
                  background: 'var(--bg-secondary)',
                  borderColor: 'var(--border-subtle)'
                }}
                allowClear
              />
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                Click column headers to sort
              </Text>
              {sortColumns.length > 0 && (
                <Button 
                  size="small" 
                  icon={<ArrowUpDown size={14} />}
                  onClick={() => setSortColumns([])}
                >
                  Clear Sort
                </Button>
              )}
            </div>
            
            {/* DataGrid */}
            <div style={{ flex: 1, overflow: 'hidden' }}>
              <DataGrid
                columns={ipGridColumns}
                rows={filteredAndSortedRows}
                rowKeyGetter={(row) => `${row.source_ip}-${row.destination_port || 0}`}
                style={{ height: '100%', width: '100%' }}
                className="rdg-dark"
                headerRowHeight={40}
                rowHeight={36}
                sortColumns={sortColumns}
                onSortColumnsChange={setSortColumns}
              />
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
