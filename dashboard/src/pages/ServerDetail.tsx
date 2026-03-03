import { useParams, Link } from '@tanstack/react-router'
import { Typography, Card, Row, Col, Table, Tag, Spin, Alert, Button, Badge, Popconfirm, App, Tooltip, Progress, Space, Avatar, Modal, Input } from 'antd'
import { ArrowLeft, Server, Activity, Shield, Globe, Trash2, RefreshCw, Clock, MapPin, Wifi, Users, Search, ArrowUpDown, ArrowDownLeft, ArrowUpRight, AlertTriangle, AlertCircle, CheckCircle2, ChevronUp, ChevronDown } from 'lucide-react'
import { CountryFlag } from '../components/CountryFlag'
import type { ColumnsType } from 'antd/es/table'
import { useServer, useServerStats, useServerPortTraffic, useDeleteServer, useServerPortSources } from '../hooks/useQueries'
import type { PortTraffic, PortSourceIP } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useEffect, useState, useMemo } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
  type ColumnDef,
} from '@tanstack/react-table'

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
  const [sorting, setSorting] = useState<SortingState>([])
  const [sourcesParams, setSourcesParams] = useState({ page: 1, page_size: 25, search: '', sort_by: 'last_seen', sort_order: 'desc' })
  
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

  // Server-side paginated sources
  const { data: sourcesResponse, isLoading: sourcesLoading } = useServerPortSources(
    id, 
    selectedPortTraffic?.port, 
    selectedPortTraffic?.protocol,
    sourcesParams
  )
  const paginatedSources = sourcesResponse?.data || []
  const sourcesPagination = sourcesResponse?.pagination
  
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
      title: 'Service',
      dataIndex: 'service_name',
      key: 'service_name',
      width: 120,
      render: (service: string, record: PortTraffic) => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Tag style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)', marginBottom: 0 }}>
            {service || record.protocol}
          </Tag>
          {service && service !== record.protocol && (
            <Text style={{ fontSize: 10, color: 'var(--text-tertiary)', lineHeight: 1 }}>
              {record.protocol}
            </Text>
          )}
        </div>
      ),
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
      title: 'ICMP',
      key: 'icmp',
      width: 90,
      render: (_: unknown, record: PortTraffic) => {
        const icmpIn = record.total_icmp_in ?? 0
        const icmpOut = record.total_icmp_out ?? 0
        if (icmpIn === 0 && icmpOut === 0) return <Text style={{ color: 'var(--text-muted)' }}>—</Text>
        const isHigh = icmpIn > 100
        return (
          <Tooltip title={`${icmpIn.toLocaleString()} packets in / ${icmpOut.toLocaleString()} packets out`}>
            <Text style={{ color: isHigh ? '#f59e0b' : 'var(--text-secondary)', fontFamily: 'monospace', fontSize: 12 }}>
              ↓{icmpIn} ↑{icmpOut}
            </Text>
          </Tooltip>
        )
      },
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
          trailColor="var(--border-subtle)"
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

  // Update sources params when filter changes (with debounce)
  useEffect(() => {
    const timeout = setTimeout(() => {
      setSourcesParams(prev => ({ ...prev, search: ipFilter, page: 1 }))
    }, 300)
    return () => clearTimeout(timeout)
  }, [ipFilter])

  // Handle sort changes
  const handleSortingChange = (updater: SortingState | ((old: SortingState) => SortingState)) => {
    const newSorting = typeof updater === 'function' ? updater(sorting) : updater
    setSorting(newSorting)
    
    if (newSorting.length > 0) {
      const { id, desc } = newSorting[0]
      setSourcesParams(prev => ({
        ...prev,
        sort_by: id,
        sort_order: desc ? 'desc' : 'asc'
      }))
    } else {
      setSourcesParams(prev => ({
        ...prev,
        sort_by: 'last_seen',
        sort_order: 'desc'
      }))
    }
  }

  // Get threat icon based on severity level
  const getThreatIcon = (score: number) => {
    if (score >= 70) return <AlertTriangle size={14} style={{ color: '#dc2626' }} />;  // Critical - red
    if (score >= 50) return <AlertCircle size={14} style={{ color: '#f97316' }} />;   // Suspicious - orange
    if (score >= 20) return <AlertCircle size={14} style={{ color: '#eab308' }} />;   // Warning - yellow
    return <CheckCircle2 size={14} style={{ color: '#22c55e' }} />;                   // Normal - green
  };

  // Severity color system: Critical → red, Suspicious → orange, Warning → yellow, Normal → green
  const getThreatColor = (score: number) => {
    if (score >= 70) return { 
      bg: 'rgba(220, 38, 38, 0.15)', 
      text: '#dc2626', 
      border: 'rgba(220, 38, 38, 0.3)',
      label: 'CRITICAL'
    };  // Critical - red
    if (score >= 50) return { 
      bg: 'rgba(249, 115, 22, 0.15)', 
      text: '#f97316', 
      border: 'rgba(249, 115, 22, 0.3)',
      label: 'SUSPICIOUS'
    };  // Suspicious - orange
    if (score >= 20) return { 
      bg: 'rgba(234, 179, 8, 0.15)', 
      text: '#eab308', 
      border: 'rgba(234, 179, 8, 0.3)',
      label: 'WARNING'
    };  // Warning - yellow
    return { 
      bg: 'rgba(34, 197, 94, 0.15)', 
      text: '#22c55e', 
      border: 'rgba(34, 197, 94, 0.3)',
      label: 'NORMAL'
    };  // Normal - green
  };

  // TanStack Table column definitions
  const columnHelper = createColumnHelper<PortSourceIP>()
  
  const ipTableColumns = useMemo<ColumnDef<PortSourceIP, any>[]>(
    () => [
      columnHelper.accessor('source_ip', {
        header: 'Remote IP',
        cell: ({ row }) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 140 }}>
            <CountryFlag countryCode={row.original.country || ''} size={14} />
            <Text code style={{ fontSize: 12, background: 'var(--bg-tertiary)', padding: '2px 6px', borderRadius: 4, fontFamily: 'monospace' }}>
              {row.original.source_ip}
            </Text>
          </div>
        ),
      }),
      columnHelper.accessor('direction', {
        header: 'Dir',
        cell: ({ row }) => {
          const isOutbound = row.original.direction === 'outbound';
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
        },
      }),
      columnHelper.accessor('country', {
        header: 'Country',
        cell: ({ row }) => (
          <span style={{ color: row.original.country ? 'var(--text-primary)' : 'var(--text-muted)', fontSize: 12 }}>
            {row.original.country || 'Unknown'}
          </span>
        ),
      }),
      columnHelper.accessor('city', {
        header: 'City',
        cell: ({ row }) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <MapPin size={13} style={{ color: 'var(--text-muted)', opacity: 0.7 }} />
            <span style={{ color: row.original.city ? 'var(--text-secondary)' : 'var(--text-muted)', fontSize: 12 }}>
              {row.original.city || '-'}
            </span>
          </div>
        ),
      }),
      columnHelper.accessor('bytes_in', {
        header: '↓ In',
        cell: ({ row }) => {
          const portMap = row.original.port_bytes_in
          const hasPortData = portMap && Object.keys(portMap).length > 0
          const content = (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <ArrowDownLeft size={12} style={{ color: '#10b981', opacity: 0.7 }} />
              <span style={{
                color: (row.original.bytes_in || 0) > 1000000 ? '#10b981' : 'var(--text-secondary)',
                fontWeight: (row.original.bytes_in || 0) > 1000000 ? 600 : 400,
                fontSize: 12
              }}>
                {formatBytes(row.original.bytes_in || 0)}
              </span>
            </div>
          )
          if (!hasPortData) return content
          const tooltipContent = (
            <div style={{ minWidth: 140 }}>
              <div style={{ marginBottom: 4, fontWeight: 600, fontSize: 11 }}>By port:</div>
              {Object.entries(portMap)
                .sort(([, a], [, b]) => Number(b) - Number(a))
                .slice(0, 10)
                .map(([port, bytes]) => (
                  <div key={port} style={{ display: 'flex', justifyContent: 'space-between', gap: 16, fontSize: 11 }}>
                    <span style={{ color: '#818cf8' }}>:{port}</span>
                    <span>{formatBytes(Number(bytes))}</span>
                  </div>
                ))}
            </div>
          )
          return <Tooltip title={tooltipContent}>{content}</Tooltip>
        },
      }),
      columnHelper.accessor('bytes_out', {
        header: '↑ Out',
        cell: ({ row }) => {
          const portMap = row.original.port_bytes_out
          const hasPortData = portMap && Object.keys(portMap).length > 0
          const content = (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <ArrowUpRight size={12} style={{ color: '#3b82f6', opacity: 0.7 }} />
              <span style={{
                color: (row.original.bytes_out || 0) > 1000000 ? '#3b82f6' : 'var(--text-secondary)',
                fontWeight: (row.original.bytes_out || 0) > 1000000 ? 600 : 400,
                fontSize: 12
              }}>
                {formatBytes(row.original.bytes_out || 0)}
              </span>
            </div>
          )
          if (!hasPortData) return content
          const tooltipContent = (
            <div style={{ minWidth: 140 }}>
              <div style={{ marginBottom: 4, fontWeight: 600, fontSize: 11 }}>By port:</div>
              {Object.entries(portMap)
                .sort(([, a], [, b]) => Number(b) - Number(a))
                .slice(0, 10)
                .map(([port, bytes]) => (
                  <div key={port} style={{ display: 'flex', justifyContent: 'space-between', gap: 16, fontSize: 11 }}>
                    <span style={{ color: '#818cf8' }}>:{port}</span>
                    <span>{formatBytes(Number(bytes))}</span>
                  </div>
                ))}
            </div>
          )
          return <Tooltip title={tooltipContent}>{content}</Tooltip>
        },
      }),
      columnHelper.accessor('syn_count', {
        header: 'SYN',
        cell: ({ row }) => (
          <div style={{ 
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2px 8px',
            borderRadius: 10,
            background: row.original.syn_count > 10 ? 'rgba(220, 38, 38, 0.15)' : 'var(--bg-tertiary)',
            border: `1px solid ${row.original.syn_count > 10 ? 'rgba(220, 38, 38, 0.3)' : 'var(--border-subtle)'}`,
          }}>
            <span style={{ 
              color: row.original.syn_count > 10 ? '#dc2626' : 'var(--text-secondary)',
              fontWeight: row.original.syn_count > 10 ? 600 : 400,
              fontSize: 12
            }}>
              {row.original.syn_count}
            </span>
          </div>
        ),
      }),
      columnHelper.accessor('ack_count', {
        header: 'ACK',
        cell: ({ row }) => (
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
              {row.original.ack_count}
            </span>
          </div>
        ),
      }),
      columnHelper.accessor('hit_count', {
        header: 'Hits',
        cell: ({ row }) => (
          <div style={{ 
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 4,
            padding: '2px 8px',
            borderRadius: 10,
            background: row.original.hit_count > 50 ? 'rgba(99, 102, 241, 0.15)' : 'var(--bg-tertiary)',
            border: `1px solid ${row.original.hit_count > 50 ? 'rgba(99, 102, 241, 0.3)' : 'var(--border-subtle)'}`,
          }}>
            <Activity size={11} style={{ color: row.original.hit_count > 50 ? '#6366f1' : 'var(--text-muted)' }} />
            <span style={{ 
              color: row.original.hit_count > 50 ? '#6366f1' : 'var(--text-secondary)',
              fontWeight: row.original.hit_count > 50 ? 600 : 400,
              fontSize: 12
            }}>
              {row.original.hit_count}
            </span>
          </div>
        ),
      }),
      columnHelper.accessor('icmp_packets_in', {
        header: 'ICMP',
        cell: ({ row }) => {
          const icmpIn = row.original.icmp_packets_in ?? 0
          const icmpOut = row.original.icmp_packets_out ?? 0
          if (icmpIn === 0 && icmpOut === 0) {
            return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
          }
          const isHigh = icmpIn > 50
          return (
            <Tooltip title={`${icmpIn.toLocaleString()} in / ${icmpOut.toLocaleString()} out`}>
              <span style={{
                color: isHigh ? '#f59e0b' : 'var(--text-secondary)',
                fontSize: 11,
                fontFamily: 'monospace',
              }}>
                ↓{icmpIn} ↑{icmpOut}
              </span>
            </Tooltip>
          )
        },
      }),
      columnHelper.accessor('connection_duration_ms', {
        header: 'Duration',
        cell: ({ row }) => {
          const ms = row.original.connection_duration_ms ?? 0
          if (ms === 0) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
          let label: string
          if (ms < 1000) label = `${ms}ms`
          else if (ms < 60000) label = `${(ms / 1000).toFixed(1)}s`
          else label = `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
          return <span style={{ color: 'var(--text-tertiary)', fontSize: 12, fontFamily: 'monospace' }}>{label}</span>
        },
      }),
      columnHelper.accessor('threat_score', {
        header: 'Severity',
        cell: ({ row }) => {
          const colors = getThreatColor(row.original.threat_score);
          return (
            <div style={{ 
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6,
              padding: '4px 10px',
              borderRadius: 12,
              background: colors.bg,
              border: `1px solid ${colors.border}`,
            }}>
              {getThreatIcon(row.original.threat_score)}
              <span style={{ 
                color: colors.text,
                fontWeight: 700,
                fontSize: 11,
                textTransform: 'uppercase',
                letterSpacing: '0.02em'
              }}>
                {colors.label}
              </span>
            </div>
          );
        },
      }),
      columnHelper.accessor('last_seen', {
        header: 'Last Seen',
        cell: ({ row }) => {
          const isRecent = new Date(row.original.last_seen).getTime() > Date.now() - 5 * 60 * 1000;
          return (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Clock size={13} style={{ 
                color: isRecent ? '#22c55e' : 'var(--text-muted)',
                opacity: isRecent ? 1 : 0.5
              }} />
              <span style={{ 
                color: isRecent ? '#22c55e' : 'var(--text-tertiary)', 
                fontSize: 12,
                fontWeight: isRecent ? 500 : 400
              }}>
                {formatDate(row.original.last_seen)}
              </span>
              {isRecent && (
                <span style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: '#22c55e',
                  boxShadow: '0 0 6px #22c55e',
                  animation: 'pulse 2s infinite'
                }} />
              )}
            </div>
          );
        },
      }),
    ],
    []
  )

  // TanStack Table instance (server-side data)
  const ipTable = useReactTable({
    data: paginatedSources,
    columns: ipTableColumns,
    state: {
      sorting,
    },
    onSortingChange: handleSortingChange,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    manualSorting: true, // Server-side sorting
    manualPagination: true, // Server-side pagination
    pageCount: sourcesPagination?.total_pages || 1,
  })

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
          style={{ background: 'transparent' }}
          rowClassName={() => 'traffic-row'}
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

      {/* IP List Modal with TanStack Table */}
      <Modal
        title={
          <Space>
            <Users size={20} color="#3b82f6" />
            <span>
              Source IPs for Port {selectedPortTraffic?.port} / {selectedPortTraffic?.service_name || selectedPortTraffic?.protocol}
            </span>
            <Badge 
              count={sourcesPagination?.total_count || selectedPortTraffic?.sources.length || 0} 
              style={{ background: '#3b82f6' }}
            />
            {ipFilter && (
              <Tag style={{ fontSize: 11 }}>
                Searching "{ipFilter}"
              </Tag>
            )}
          </Space>
        }
        open={ipModalOpen}
        onCancel={() => {
          setIpModalOpen(false)
          setIpFilter('')
          setSorting([])
          setSourcesParams({ page: 1, page_size: 25, search: '', sort_by: 'last_seen', sort_order: 'desc' })
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
              alignItems: 'center',
              flexWrap: 'wrap'
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
              {sorting.length > 0 && (
                <Button 
                  size="small" 
                  icon={<ArrowUpDown size={14} />}
                  onClick={() => handleSortingChange([])}
                >
                  Clear Sort
                </Button>
              )}
              {sourcesLoading && <Spin size="small" />}
            </div>
            
            {/* TanStack Table */}
            <div style={{ flex: 1, overflow: 'auto' }}>
              <table style={{ 
                width: '100%', 
                borderCollapse: 'collapse',
                fontSize: 13
              }}>
                <thead style={{ 
                  position: 'sticky', 
                  top: 0, 
                  zIndex: 1,
                  background: 'var(--bg-secondary)'
                }}>
                  {ipTable.getHeaderGroups().map(headerGroup => (
                    <tr key={headerGroup.id}>
                      {headerGroup.headers.map(header => (
                        <th
                          key={header.id}
                          onClick={header.column.getToggleSortingHandler()}
                          style={{
                            padding: '12px 8px',
                            textAlign: 'left',
                            fontWeight: 600,
                            fontSize: 11,
                            textTransform: 'uppercase',
                            letterSpacing: '0.05em',
                            color: 'var(--text-secondary)',
                            borderBottom: '1px solid var(--border-subtle)',
                            cursor: header.column.getCanSort() ? 'pointer' : 'default',
                            whiteSpace: 'nowrap',
                            userSelect: 'none'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {header.column.getCanSort() && (
                              <span style={{ display: 'flex', flexDirection: 'column' }}>
                                <ChevronUp 
                                  size={12} 
                                  style={{ 
                                    opacity: header.column.getIsSorted() === 'asc' ? 1 : 0.3,
                                    marginBottom: -4
                                  }} 
                                />
                                <ChevronDown 
                                  size={12} 
                                  style={{ 
                                    opacity: header.column.getIsSorted() === 'desc' ? 1 : 0.3
                                  }} 
                                />
                              </span>
                            )}
                          </div>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {ipTable.getRowModel().rows.length === 0 ? (
                    <tr>
                      <td 
                        colSpan={ipTableColumns.length}
                        style={{ 
                          padding: '60px 24px', 
                          textAlign: 'center',
                          color: 'var(--text-tertiary)'
                        }}
                      >
                        <Globe size={48} style={{ marginBottom: 16, opacity: 0.3 }} />
                        <div>No matching IPs found</div>
                      </td>
                    </tr>
                  ) : (
                    ipTable.getRowModel().rows.map(row => (
                      <tr 
                        key={row.id}
                        style={{
                          borderBottom: '1px solid var(--border-subtle)',
                          transition: 'background 0.15s'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = 'var(--bg-tertiary)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = 'transparent';
                        }}
                      >
                        {row.getVisibleCells().map(cell => (
                          <td
                            key={cell.id}
                            style={{
                              padding: '10px 8px',
                              color: 'var(--text-primary)',
                              whiteSpace: 'nowrap'
                            }}
                          >
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </td>
                        ))}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            
            {/* Server-side Pagination */}
            {sourcesPagination && sourcesPagination.total_count > 0 && (
              <div style={{ 
                padding: '12px 16px', 
                borderTop: '1px solid var(--border-subtle)',
                background: 'var(--bg-tertiary)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 12
              }}>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 13 }}>
                  Showing {(sourcesPagination.page - 1) * sourcesPagination.page_size + 1} to {Math.min(
                    sourcesPagination.page * sourcesPagination.page_size,
                    sourcesPagination.total_count
                  )} of {sourcesPagination.total_count} IPs
                </Text>
                
                <Space>
                  <Button
                    size="small"
                    disabled={sourcesPagination.page <= 1}
                    onClick={() => setSourcesParams(prev => ({ ...prev, page: prev.page - 1 }))}
                    style={{
                      background: 'var(--bg-secondary)',
                      borderColor: 'var(--border-subtle)'
                    }}
                  >
                    Previous
                  </Button>
                  
                  <div style={{ display: 'flex', gap: 4 }}>
                    {Array.from({ length: Math.min(5, sourcesPagination.total_pages) }, (_, i) => {
                      const currentPage = sourcesPagination.page;
                      const totalPages = sourcesPagination.total_pages;
                      
                      // Show pages around current page
                      let startPage = Math.max(1, currentPage - 2);
                      let endPage = Math.min(totalPages, startPage + 4);
                      if (endPage - startPage < 4) {
                        startPage = Math.max(1, endPage - 4);
                      }
                      const pageNum = startPage + i;
                      if (pageNum > endPage) return null;
                      
                      const isActive = pageNum === currentPage;
                      return (
                        <Button
                          key={pageNum}
                          size="small"
                          onClick={() => setSourcesParams(prev => ({ ...prev, page: pageNum }))}
                          style={{
                            minWidth: 32,
                            background: isActive ? '#3b82f6' : 'var(--bg-secondary)',
                            borderColor: isActive ? '#3b82f6' : 'var(--border-subtle)',
                            color: isActive ? '#fff' : 'var(--text-primary)'
                          }}
                        >
                          {pageNum}
                        </Button>
                      );
                    })}
                  </div>
                  
                  <Button
                    size="small"
                    disabled={sourcesPagination.page >= sourcesPagination.total_pages}
                    onClick={() => setSourcesParams(prev => ({ ...prev, page: prev.page + 1 }))}
                    style={{
                      background: 'var(--bg-secondary)',
                      borderColor: 'var(--border-subtle)'
                    }}
                  >
                    Next
                  </Button>
                  
                  <select
                    value={sourcesParams.page_size}
                    onChange={e => setSourcesParams(prev => ({ ...prev, page_size: Number(e.target.value), page: 1 }))}
                    style={{
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 6,
                      padding: '4px 8px',
                      color: 'var(--text-primary)',
                      fontSize: 13,
                      cursor: 'pointer'
                    }}
                  >
                    {[10, 25, 50, 100].map(pageSize => (
                      <option key={pageSize} value={pageSize} style={{ background: 'var(--bg-card)' }}>
                        {pageSize} / page
                      </option>
                    ))}
                  </select>
                </Space>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}
