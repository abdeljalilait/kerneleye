import { useState } from 'react'
import {
  Table,
  Card,
  Tag,
  Button,
  Space,
  Tooltip,
  Typography,
  Row,
  Col,
  Select,
  Input,
  Badge,
  Popconfirm,
  Drawer,
  Descriptions,
  Alert,
  Progress,
} from 'antd'
import {
  Shield,
  Server,
  AlertTriangle,
  Unlock,
  Globe,
  Clock,
  Eye,
  Filter,
  Download,
  Search,
  Flag,
  Building2,
  Wifi,
  Database,
  FolderOpen,
  Mail,
  CheckCircle,
  Ban,
} from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import { useBlocks, useBlockStats, useUnblockIP, useServers } from '../hooks/useQueries'
import { useWebSocketEvent } from '../hooks/useWebSocketEvent'
import { whitelistAPI } from '../api/client'
import StatCard from '../components/StatCard'
import LiveBlockFeed from '../components/LiveBlockFeed'

dayjs.extend(relativeTime)

const { Title, Text } = Typography
const { Option } = Select

// Types matching backend response
interface BlockView {
  id: string
  ip_address: string
  ip_version: number
  server_id: string
  server_name: string
  threat_score: number
  threat_level: 'normal' | 'suspicious' | 'malicious' | 'critical'
  reasons: string[]
  target_port: number
  service_name: string
  protocol: string
  country_code: string
  country_name: string
  city: string
  region: string
  asn: number
  asn_org: string
  is_vpn: boolean
  is_tor: boolean
  is_datacenter: boolean
  latitude: number
  longitude: number
  blocked_at: string
  expires_at: string
  duration_seconds: number
  is_active: boolean
  is_auto_blocked: boolean
  unblocked_at?: string
}

interface BlockListResponse {
  items: BlockView[]
  total: number
  page: number
  page_size: number
}

interface BlockStats {
  total_active: number
  total_today: number
  by_service: Record<string, number>
  by_country: Record<string, number>
  by_server: Record<string, number>
  by_threat_level: Record<string, number>
}

const reasonLabels: Record<string, string> = {
  service_abuse: 'Service Abuse',
  port_scan: 'Port Scan',
  syn_flood: 'SYN Flood',
  ddos: 'DDoS',
  brute_force: 'Brute Force',
  connection_burst: 'Conn. Burst',
  failed_handshake: 'Failed Handshake',
  ssh_bruteforce: 'SSH Brute Force',
  http_flood: 'HTTP Flood',
  dns_amplification: 'DNS Amplification',
  ipset_block: 'IPSet Block',
  ipset_ratelimit: 'IPSet Rate Limit',
  xdp_block: 'XDP Block',
}

const reasonLabel = (reason: string) => reasonLabels[reason] || reason.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())

const reasonTagColor = (reason: string): string => {
  switch (reason) {
    case 'syn_flood':
    case 'ddos':
    case 'http_flood':
      return 'red'
    case 'port_scan':
      return 'orange'
    case 'service_abuse':
    case 'brute_force':
    case 'ssh_bruteforce':
      return 'volcano'
    case 'connection_burst':
      return 'gold'
    case 'failed_handshake':
      return 'purple'
    case 'ipset_block':
      return 'red'
    case 'xdp_block':
      return 'red'
    case 'ipset_ratelimit':
      return 'gold'
    default:
      return 'default'
  }
}

const serviceIcons: Record<string, React.ReactNode> = {
  ssh: <Shield size={16} />,
  http: <Wifi size={16} />,
  https: <Shield size={16} />,
  mysql: <Database size={16} />,
  postgres: <Database size={16} />,
  redis: <Database size={16} />,
  mongodb: <Database size={16} />,
  ftp: <FolderOpen size={16} />,
  smtp: <Mail size={16} />,
  dns: <Globe size={16} />,
}

export default function BlockedIPs() {
  const queryClient = useQueryClient()
  const [selectedBlock, setSelectedBlock] = useState<BlockView | null>(null)
  const [drawerVisible, setDrawerVisible] = useState(false)
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [filters, setFilters] = useState({
    server: 'all',
    service: 'all',
    country: 'all',
    status: 'active',
    search: '',
  })

  // Fetch servers for filter dropdown
  const { data: servers } = useServers()

  // Fetch blocks with filters and pagination
  const { data: blocksData, isLoading, error } = useBlocks({
    page: currentPage,
    page_size: pageSize,
    server: filters.server,
    status: filters.status,
  })

  // Fetch stats
  const { data: statsData } = useBlockStats()

  // Unblock mutation
  const unblockMutation = useUnblockIP()

  // Whitelist mutation
  const [whitelistLoading, setWhitelistLoading] = useState<string | null>(null)

  const handleWhitelist = async (ip: string, reasons: string[]) => {
    setWhitelistLoading(ip)
    try {
      await whitelistAPI.add(ip, `False positive - ${reasons.join(', ')}`)
      queryClient.invalidateQueries({ queryKey: ['blocks'] })
    } finally {
      setWhitelistLoading(null)
      setDrawerVisible(false)
    }
  }

  // Auto-refresh table & stats whenever a new block arrives via WebSocket
  useWebSocketEvent('new_block', () => {
    queryClient.invalidateQueries({ queryKey: ['blocks'] })
    queryClient.invalidateQueries({ queryKey: ['block-stats'] })
  })

  // Type the blocks data
  const blocks = (blocksData as BlockListResponse)?.items || []
  const totalBlocks = (blocksData as BlockListResponse)?.total || 0
  const stats: BlockStats = (statsData as BlockStats) || {
    total_active: 0,
    total_today: 0,
    by_service: {},
    by_country: {},
    by_server: {},
    by_threat_level: {},
  }

  const columns: ColumnsType<BlockView> = [
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip',
      render: (ip: string, record: BlockView) => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Text strong style={{ fontFamily: 'monospace', fontSize: 14 }}>
              {ip}
            </Text>
            {record.ip_version === 6 && <Tag style={{ fontSize: 10, padding: '0 4px' }}>IPv6</Tag>}
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {record.is_datacenter && (
              <Tooltip title="Datacenter IP (AWS, GCP, etc.)">
                <Tag color="orange" style={{ fontSize: 10, padding: '0 4px', margin: 0 }}>
                  DC
                </Tag>
              </Tooltip>
            )}
            {record.is_vpn && (
              <Tooltip title="VPN Exit Node">
                <Tag color="purple" style={{ fontSize: 10, padding: '0 4px', margin: 0 }}>
                  VPN
                </Tag>
              </Tooltip>
            )}
            {record.is_tor && (
              <Tooltip title="Tor Exit Node">
                <Tag color="red" style={{ fontSize: 10, padding: '0 4px', margin: 0 }}>
                  TOR
                </Tag>
              </Tooltip>
            )}
          </div>
        </div>
      ),
    },
    {
      title: 'Threat',
      dataIndex: 'threat_score',
      key: 'threat',
      width: 100,
      sorter: (a, b) => a.threat_score - b.threat_score,
      render: (score: number, record: BlockView) => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Badge
              status={score >= 80 ? 'error' : score >= 60 ? 'warning' : 'default'}
            />
            <Text strong style={{ 
              color: score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : score >= 30 ? '#eab308' : '#10b981',
              fontSize: 14 
            }}>
              {score}
            </Text>
          </div>
          <Text type="secondary" style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {record.threat_level}
          </Text>
        </div>
      ),
    },
    {
      title: 'Attack Reason',
      key: 'reason',
      width: 200,
      render: (_, record: BlockView) => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {record.reasons && record.reasons.length > 0 ? (
              record.reasons.map((reason) => (
                <Tag
                  key={reason}
                  color={reasonTagColor(reason)}
                  style={{ fontSize: 11, margin: 0 }}
                >
                  {reasonLabel(reason)}
                </Tag>
              ))
            ) : (
              <Tag style={{ fontSize: 11, margin: 0 }}>Unknown</Tag>
            )}
          </div>
          {(record.service_name || (record.target_port && record.target_port > 0) || (record.protocol && record.protocol.toLowerCase() !== 'unknown')) && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ color: 'var(--text-secondary)' }}>
                {serviceIcons[record.service_name] || <Server size={12} />}
              </span>
              <Text type="secondary" style={{ fontSize: 11 }}>
                {record.service_name ? record.service_name.toUpperCase() : ''}
                {record.service_name && record.target_port > 0 && ' · '}
                {record.target_port > 0 && `Port ${record.target_port}`}
                {record.protocol && record.protocol.toLowerCase() !== 'unknown' && ` (${record.protocol.toUpperCase()})`}
              </Text>
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Location',
      key: 'location',
      render: (_, record: BlockView) => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Flag size={14} style={{ color: 'var(--text-secondary)', flexShrink: 0 }} />
            <Text style={{ fontSize: 13 }}>
              {record.country_name || 'Unknown'}
              {record.country_code && (
                <span style={{ marginLeft: 4, fontSize: 11, color: 'var(--text-tertiary)' }}>
                  ({record.country_code})
                </span>
              )}
            </Text>
          </div>
          {record.city && (
            <Text type="secondary" style={{ fontSize: 11, paddingLeft: 20 }}>
              {record.city}
            </Text>
          )}
          {record.asn_org && (
            <Tooltip title={`AS${record.asn}`}>
              <Text type="secondary" style={{ fontSize: 10, paddingLeft: 20 }} ellipsis>
                {record.asn_org}
              </Text>
            </Tooltip>
          )}
        </div>
      ),
    },
    {
      title: 'Server',
      dataIndex: 'server_name',
      key: 'server',
      width: 140,
      render: (name: string) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Building2 size={14} style={{ color: 'var(--text-secondary)', flexShrink: 0 }} />
          <Text style={{ fontSize: 13 }} ellipsis>{name}</Text>
        </div>
      ),
    },
    {
      title: 'Blocked',
      dataIndex: 'blocked_at',
      key: 'blocked',
      width: 160,
      sorter: (a, b) => new Date(a.blocked_at).getTime() - new Date(b.blocked_at).getTime(),
      render: (date: string, record: BlockView) => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={14} style={{ color: 'var(--text-secondary)', flexShrink: 0 }} />
            <Text style={{ fontSize: 13 }}>{dayjs(date).format('MMM D, HH:mm')}</Text>
          </div>
          {record.expires_at && dayjs(record.expires_at).isValid() && record.expires_at !== '0001-01-01T00:00:00Z' ? (
            <Text type="secondary" style={{ fontSize: 11, paddingLeft: 20 }}>
              Expires {dayjs(record.expires_at).fromNow()}
            </Text>
          ) : (
            <Text type="secondary" style={{ fontSize: 11, paddingLeft: 20, color: 'var(--text-muted)' }}>
              Permanent block
            </Text>
          )}
          {record.is_active && record.expires_at && dayjs(record.expires_at).isValid() && record.expires_at !== '0001-01-01T00:00:00Z' && (
            <div style={{ paddingLeft: 20, width: 80 }}>
              <Progress
                percent={calculateProgress(record.blocked_at, record.expires_at)}
                size="small"
                showInfo={false}
                strokeColor="#3b82f6"
                trailColor="var(--border-subtle)"
                style={{ margin: 0 }}
              />
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'status',
      width: 120,
      render: (active: boolean, record: BlockView) => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <Tag 
            color={active ? 'red' : 'green'} 
            style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: 4, 
              width: 'fit-content',
              fontSize: 11,
              padding: '0 6px',
              margin: 0
            }}
          >
            {active ? <Ban size={10} /> : <Unlock size={10} />}
            {active ? 'Blocked' : 'Unblocked'}
          </Tag>
          <Tag 
            color={record.is_auto_blocked ? 'blue' : 'purple'} 
            style={{ 
              width: 'fit-content',
              fontSize: 10,
              padding: '0 6px',
              margin: 0
            }}
          >
            {record.is_auto_blocked ? 'Auto' : 'Manual'}
          </Tag>
        </div>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 180,
      render: (_, record: BlockView) => (
        <Space size="small">
          <Button
            size="small"
            icon={<Eye size={14} />}
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
            }}
            onClick={() => {
              setSelectedBlock(record)
              setDrawerVisible(true)
            }}
          >
            Details
          </Button>
          {record.is_active && (
            <Popconfirm
              title="Unblock this IP?"
              description="The IP will be immediately removed from the blocklist."
              onConfirm={() => unblockMutation.mutate({ ip: record.ip_address })}
              okText="Yes, unblock"
              cancelText="Cancel"
            >
              <Button
                size="small"
                type="primary"
                danger
                icon={<Unlock size={14} />}
                loading={unblockMutation.isPending}
              >
                Unblock
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ]

  // Filter blocks locally based on search (only for current page items)
  // Note: For full dataset search, implement search on backend
  const filteredBlocks = filters.search
    ? blocks.filter(
        (block) =>
          block.ip_address.toLowerCase().includes(filters.search.toLowerCase()) ||
          block.server_name.toLowerCase().includes(filters.search.toLowerCase()) ||
          block.country_name?.toLowerCase().includes(filters.search.toLowerCase())
      )
    : blocks

  if (error) {
    return (
      <div style={{ padding: '24px 48px' }}>
        <Alert
          message="Failed to load blocked IPs"
          description="Please try again later"
          type="error"
          showIcon
        />
      </div>
    )
  }

  return (
    <div style={{ padding: '24px 48px', maxWidth: 1600, margin: '0 auto' }}>
      {/* Header */}
      <Row justify="space-between" align="middle" style={{ marginBottom: 32 }}>
        <Col>
          <Space direction="vertical" size={4}>
            <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
              Blocked IPs
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>
              View and manage automatically blocked IPs across all your servers
            </Text>
          </Space>
        </Col>
        <Col>
          <Space>
            <Button
              icon={<Download size={16} />}
              style={{
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              Export CSV
            </Button>
            <Button
              icon={<Filter size={16} />}
              style={{
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              Filters
            </Button>
          </Space>
        </Col>
      </Row>

      {/* Statistics Cards - Using StatCard Component */}
      <Row gutter={[20, 20]} style={{ marginBottom: 32 }}>
        <Col xs={24} sm={12} md={6}>
          <StatCard
            title="Active Blocks"
            value={stats.total_active.toString()}
            subtext="Currently blocked IPs"
            icon={Ban}
            color="error"
          />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <StatCard
            title="Blocked Today"
            value={stats.total_today.toString()}
            subtext="New blocks in last 24h"
            icon={AlertTriangle}
            color="warning"
          />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <StatCard
            title="Unique Countries"
            value={Object.keys(stats.by_country).length.toString()}
            subtext="Different attack origins"
            icon={Globe}
            color="cyan"
          />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <StatCard
            title="Services Protected"
            value={Object.keys(stats.by_service).length.toString()}
            subtext="Services under protection"
            icon={Shield}
            color="success"
          />
        </Col>
      </Row>

      {/* Live Block Feed */}
      <LiveBlockFeed />

      {/* Filters */}
      <Card
        variant="borderless"
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          marginBottom: 24,
        }}
        bodyStyle={{ padding: 16 }}
      >
        <Space wrap>
          <Select
            value={filters.server}
            onChange={(val) => {
              setFilters({ ...filters, server: val })
              setCurrentPage(1) // Reset to page 1 when filter changes
            }}
            style={{ width: 180 }}
            placeholder="Server"
          >
            <Option value="all">All Servers</Option>
            {servers?.map((s) => (
              <Option key={s.id} value={s.id}>
                {s.hostname}
              </Option>
            ))}
          </Select>

          <Select
            value={filters.service}
            onChange={(val) => setFilters({ ...filters, service: val })}
            style={{ width: 150 }}
            placeholder="Service"
          >
            <Option value="all">All Services</Option>
            <Option value="ssh">SSH</Option>
            <Option value="http">HTTP</Option>
            <Option value="https">HTTPS</Option>
            <Option value="mysql">MySQL</Option>
            <Option value="postgres">PostgreSQL</Option>
            <Option value="redis">Redis</Option>
          </Select>

          <Select
            value={filters.status}
            onChange={(val) => {
              setFilters({ ...filters, status: val })
              setCurrentPage(1) // Reset to page 1 when filter changes
            }}
            style={{ width: 150 }}
          >
            <Option value="active">Active Only</Option>
            <Option value="expired">Expired</Option>
            <Option value="all">All</Option>
          </Select>

          <Input.Search
            placeholder="Search IP, server, country..."
            value={filters.search}
            onChange={(e) => {
              setFilters({ ...filters, search: e.target.value })
              setCurrentPage(1) // Reset to page 1 when search changes
            }}
            style={{ width: 250 }}
            prefix={<Search size={16} />}
            allowClear
          />
        </Space>
      </Card>

      {/* Main Table */}
      <Card
        variant="borderless"
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          backdropFilter: 'blur(10px)',
        }}
        bodyStyle={{ padding: 0 }}
      >
        <Table
          columns={columns}
          dataSource={filteredBlocks}
          loading={isLoading}
          rowKey="id"
          pagination={{
            current: currentPage,
            pageSize: pageSize,
            total: totalBlocks,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} blocked IPs`,
            onChange: (page, newPageSize) => {
              setCurrentPage(page)
              if (newPageSize !== pageSize) {
                setPageSize(newPageSize)
                setCurrentPage(1) // Reset to page 1 when page size changes
              }
            },
            style: { margin: '16px 24px' }
          }}
          scroll={{ x: 1200 }}
          rowClassName="blocked-ip-row"
          expandable={{
            expandedRowRender: (record) => (
              <div style={{ padding: 16, background: 'var(--bg-tertiary)' }}>
                <Text strong style={{ fontSize: 13 }}>Threat Reasons</Text>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                  {record.reasons && record.reasons.length > 0 ? (
                    record.reasons.map((reason) => (
                      <Tag key={reason} color={reasonTagColor(reason)} style={{ fontSize: 12, padding: '2px 10px' }}>
                        {reasonLabel(reason)}
                      </Tag>
                    ))
                  ) : (
                    <Text type="secondary" style={{ fontSize: 13 }}>No specific reason recorded</Text>
                  )}
                </div>
              </div>
            ),
          }}
          locale={{
            emptyText: (
              <div style={{ padding: '60px 0', textAlign: 'center' }}>
                <div style={{
                  width: 64,
                  height: 64,
                  borderRadius: '50%',
                  background: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 16px',
                }}>
                  <Shield size={28} color="#10b981" />
                </div>
                <Text style={{ color: 'var(--text-secondary)', fontSize: 16, display: 'block', marginBottom: 8 }}>
                  No blocked IPs found
                </Text>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 13 }}>
                  Your systems are currently secure
                </Text>
              </div>
            )
          }}
        />
      </Card>

      {/* Detail Drawer */}
      <Drawer
        title="Block Details"
        placement="right"
        width={600}
        onClose={() => setDrawerVisible(false)}
        open={drawerVisible}
      >
        {selectedBlock && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <Alert
              message={selectedBlock.is_active ? 'Currently Blocked' : 'Unblocked'}
              type={selectedBlock.is_active ? 'error' : 'success'}
              showIcon
              icon={selectedBlock.is_active ? <Ban size={16} /> : <CheckCircle size={16} />}
            />

            <Descriptions title="IP Information" bordered column={1}>
              <Descriptions.Item label="IP Address">
                <Text copyable style={{ fontFamily: 'monospace', fontSize: 16 }}>
                  {selectedBlock.ip_address}
                </Text>
              </Descriptions.Item>
              <Descriptions.Item label="Version">IPv{selectedBlock.ip_version}</Descriptions.Item>
              <Descriptions.Item label="ASN">
                {selectedBlock.asn > 0 ? `AS${selectedBlock.asn}` : ''}
                {selectedBlock.asn > 0 && selectedBlock.asn_org ? ' - ' : ''}
                {selectedBlock.asn_org || (selectedBlock.asn === 0 ? 'Unknown' : '')}
              </Descriptions.Item>
              <Descriptions.Item label="Attributes">
                <Space>
                  {selectedBlock.is_datacenter && <Tag color="orange">Datacenter</Tag>}
                  {selectedBlock.is_vpn && <Tag color="purple">VPN</Tag>}
                  {selectedBlock.is_tor && <Tag color="red">Tor</Tag>}
                </Space>
              </Descriptions.Item>
            </Descriptions>

            <Descriptions title="Location" bordered column={1}>
              <Descriptions.Item label="Country">
                {selectedBlock.country_name} ({selectedBlock.country_code})
              </Descriptions.Item>
              <Descriptions.Item label="City/Region">
                {[selectedBlock.city, selectedBlock.region].filter(Boolean).join(', ') || 'Unknown'}
              </Descriptions.Item>
            </Descriptions>

            <Descriptions title="Attack Details" bordered column={1}>
              {(selectedBlock.service_name || selectedBlock.target_port > 0 || (selectedBlock.protocol && selectedBlock.protocol.toLowerCase() !== 'unknown')) && (
                <Descriptions.Item label="Target Service">
                  <Space>
                    {serviceIcons[selectedBlock.service_name] || <Server size={16} />}
                    {selectedBlock.service_name && (
                      <Text strong style={{ textTransform: 'uppercase' }}>
                        {selectedBlock.service_name}
                      </Text>
                    )}
                    {selectedBlock.target_port > 0 && (
                      <Text type="secondary">Port {selectedBlock.target_port}</Text>
                    )}
                    {selectedBlock.protocol && selectedBlock.protocol.toLowerCase() !== 'unknown' && (
                      <Text type="secondary">({selectedBlock.protocol.toUpperCase()})</Text>
                    )}
                  </Space>
                </Descriptions.Item>
              )}
              <Descriptions.Item label="Threat Score">
                <Tag color={selectedBlock.threat_score >= 80 ? 'red' : selectedBlock.threat_score >= 60 ? 'orange' : 'gold'}>
                  {selectedBlock.threat_score}
                </Tag>
                <Tag color={selectedBlock.threat_level === 'malicious' ? 'red' : selectedBlock.threat_level === 'suspicious' ? 'orange' : 'default'} style={{ marginLeft: 4 }}>
                  {selectedBlock.threat_level && selectedBlock.threat_level.charAt(0).toUpperCase() + selectedBlock.threat_level.slice(1)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Reasons">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {selectedBlock.reasons && selectedBlock.reasons.length > 0 ? (
                    selectedBlock.reasons.map((reason) => (
                      <Tag key={reason} color={reasonTagColor(reason)} style={{ fontSize: 12, padding: '2px 10px' }}>
                        {reasonLabel(reason)}
                      </Tag>
                    ))
                  ) : (
                    <Text type="secondary">No specific reason recorded</Text>
                  )}
                </div>
              </Descriptions.Item>
            </Descriptions>

            <Descriptions title="Timeline" bordered column={1}>
              <Descriptions.Item label="Blocked At">
                {dayjs(selectedBlock.blocked_at).format('MMMM D, YYYY HH:mm:ss')}
              </Descriptions.Item>
              <Descriptions.Item label="Expires At">
                {selectedBlock.expires_at && dayjs(selectedBlock.expires_at).isValid() && selectedBlock.expires_at !== '0001-01-01T00:00:00Z' ? (
                  <>
                    {dayjs(selectedBlock.expires_at).format('MMMM D, YYYY HH:mm:ss')} (
                    {dayjs(selectedBlock.expires_at).fromNow()})
                  </>
                ) : (
                  <Text type="secondary">Permanent block</Text>
                )}
              </Descriptions.Item>
              {selectedBlock.unblocked_at && (
                <Descriptions.Item label="Unblocked At">
                  {dayjs(selectedBlock.unblocked_at).format('MMMM D, YYYY HH:mm:ss')}
                </Descriptions.Item>
              )}
            </Descriptions>

            {selectedBlock.is_active && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 16 }}>
                <Popconfirm
                  title="Unblock this IP?"
                  onConfirm={() => {
                    unblockMutation.mutate({ ip: selectedBlock.ip_address })
                    setDrawerVisible(false)
                  }}
                >
                  <Button type="primary" danger block size="large" icon={<Unlock size={18} />}>
                    Unblock IP Address
                  </Button>
                </Popconfirm>
                <Popconfirm
                  title="Whitelist this IP?"
                  description="This IP will be added to your whitelist and will never be blocked again. It will also be immediately unblocked."
                  onConfirm={() =>
                    handleWhitelist(selectedBlock.ip_address, selectedBlock.reasons)
                  }
                >
                  <Button
                    type="default"
                    block
                    size="large"
                    icon={<CheckCircle size={18} />}
                    loading={whitelistLoading === selectedBlock.ip_address}
                  >
                    Whitelist & Unblock (False Positive)
                  </Button>
                </Popconfirm>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  )
}

function calculateProgress(start: string, end: string): number {
  const startTime = new Date(start).getTime()
  const endTime = new Date(end).getTime()
  const now = Date.now()
  const total = endTime - startTime
  const elapsed = now - startTime
  return Math.min(100, Math.max(0, (elapsed / total) * 100))
}
