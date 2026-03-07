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
  Statistic,
  Empty,
  theme,
} from 'antd'
const { useToken } = theme
import {
  SafetyOutlined,
  CloudServerOutlined,
  AlertOutlined,
  UnlockOutlined,
  GlobalOutlined,
  EyeOutlined,
  FilterOutlined,
  DownloadOutlined,
  WifiOutlined,
  DatabaseOutlined,
  FolderOpenOutlined,
  MailOutlined,
  CheckCircleOutlined,
  StopOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import { useBlocks, useBlockStats, useUnblockIP, useServers } from '../hooks/useQueries'
import { useWebSocketEvent } from '../hooks/useWebSocketEvent'
import { whitelistAPI } from '../api/client'
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
  ssh: <SafetyOutlined />,
  http: <WifiOutlined />,
  https: <SafetyCertificateOutlined />,
  mysql: <DatabaseOutlined />,
  postgres: <DatabaseOutlined />,
  redis: <DatabaseOutlined />,
  mongodb: <DatabaseOutlined />,
  ftp: <FolderOpenOutlined />,
  smtp: <MailOutlined />,
  dns: <GlobalOutlined />,
}

// Threat level icons - colors are applied using theme tokens inside component

export default function BlockedIPs() {
  const { token } = useToken()
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
      fixed: 'left',
      width: 160,
      ellipsis: true,
      render: (ip: string, record: BlockView) => (
        <Space direction="vertical" size={2}>
          <Space size={4}>
            <Text strong copyable style={{ fontFamily: 'monospace', fontSize: 13 }}>
              {ip}
            </Text>
            {record.ip_version === 6 && <Tag style={{ fontSize: 10, padding: '0 4px' }}>v6</Tag>}
          </Space>
          <Space size={2}>
            {record.is_datacenter && (
              <Tooltip title="Datacenter">
                <Tag color="orange" style={{ fontSize: 9, margin: 0, padding: '0 3px' }}>DC</Tag>
              </Tooltip>
            )}
            {record.is_vpn && (
              <Tooltip title="VPN">
                <Tag color="purple" style={{ fontSize: 9, margin: 0, padding: '0 3px' }}>VPN</Tag>
              </Tooltip>
            )}
            {record.is_tor && (
              <Tooltip title="Tor">
                <Tag color="red" style={{ fontSize: 9, margin: 0, padding: '0 3px' }}>TOR</Tag>
              </Tooltip>
            )}
          </Space>
        </Space>
      ),
    },
    {
      title: 'Threat',
      dataIndex: 'threat_score',
      key: 'threat',
      width: 90,
      sorter: (a, b) => a.threat_score - b.threat_score,
      render: (score: number, record: BlockView) => {
        const getThreatColor = () => {
          if (score >= 80) return token.colorError
          if (score >= 60) return token.colorWarning
          if (score >= 30) return token.colorWarning
          return token.colorSuccess
        }
        return (
          <Space direction="vertical" size={2}>
            <Space>
              <Badge
                status={score >= 80 ? 'error' : score >= 60 ? 'warning' : 'default'}
              />
              <Text strong style={{ color: getThreatColor(), fontSize: 14 }}>
                {score}
              </Text>
            </Space>
            <Text type="secondary" style={{ fontSize: 11, textTransform: 'capitalize' }}>
              {record.threat_level}
            </Text>
          </Space>
        )
      },
    },
    {
      title: 'Attack Reason',
      key: 'reason',
      width: 160,
      render: (_, record: BlockView) => (
        <Space direction="vertical" size={4}>
          <Space size={2} wrap>
            {record.reasons && record.reasons.length > 0 ? (
              record.reasons.slice(0, 2).map((reason) => (
                <Tag
                  key={reason}
                  color={reasonTagColor(reason)}
                  style={{ fontSize: 10, margin: 0, padding: '0 4px' }}
                >
                  {reasonLabel(reason)}
                </Tag>
              ))
            ) : (
              <Tag style={{ fontSize: 10, margin: 0, padding: '0 4px' }}>Unknown</Tag>
            )}
            {record.reasons && record.reasons.length > 2 && (
              <Tooltip title={record.reasons.slice(2).map(r => reasonLabel(r)).join(', ')}>
                <Tag style={{ fontSize: 10, margin: 0, padding: '0 4px' }}>+{record.reasons.length - 2}</Tag>
              </Tooltip>
            )}
          </Space>
          {(record.service_name || record.target_port > 0) && (
            <Text type="secondary" style={{ fontSize: 10 }}>
              {record.service_name?.toUpperCase()}
              {record.service_name && record.target_port > 0 && ' · '}
              {record.target_port > 0 && `Port ${record.target_port}`}
            </Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Location',
      key: 'location',
      width: 140,
      ellipsis: true,
      render: (_, record: BlockView) => (
        <Space direction="vertical" size={2}>
          <Text style={{ fontSize: 12 }} ellipsis>
            {record.country_name || 'Unknown'}
          </Text>
          {record.city && (
            <Text type="secondary" style={{ fontSize: 10 }} ellipsis>
              {record.city}
            </Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Server',
      dataIndex: 'server_name',
      key: 'server',
      width: 120,
      ellipsis: true,
      render: (name: string) => (
        <Text style={{ fontSize: 12 }} ellipsis>{name}</Text>
      ),
    },
    {
      title: 'Blocked',
      dataIndex: 'blocked_at',
      key: 'blocked',
      width: 130,
      sorter: (a, b) => new Date(a.blocked_at).getTime() - new Date(b.blocked_at).getTime(),
      render: (date: string, record: BlockView) => (
        <Space direction="vertical" size={2}>
          <Text style={{ fontSize: 12 }}>{dayjs(date).format('MMM D, HH:mm')}</Text>
          {record.expires_at && dayjs(record.expires_at).isValid() && record.expires_at !== '0001-01-01T00:00:00Z' ? (
            <Text type="secondary" style={{ fontSize: 10 }}>
              Exp {dayjs(record.expires_at).fromNow(true)}
            </Text>
          ) : (
            <Text type="secondary" style={{ fontSize: 10 }}>
              Permanent
            </Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'status',
      width: 90,
      render: (active: boolean, record: BlockView) => (
        <Space direction="vertical" size={2}>
          <Tag 
            color={active ? 'error' : 'success'} 
            style={{ margin: 0, fontSize: 10, padding: '0 4px' }}
          >
            {active ? 'Blocked' : 'Unblocked'}
          </Tag>
          <Tag 
            color={record.is_auto_blocked ? 'blue' : 'purple'} 
            style={{ margin: 0, fontSize: 9, padding: '0 4px' }}
          >
            {record.is_auto_blocked ? 'Auto' : 'Manual'}
          </Tag>
        </Space>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      fixed: 'right',
      render: (_, record: BlockView) => (
        <Space size="small">
          <Tooltip title="View Details">
            <Button
              size="small"
              icon={<EyeOutlined />}
              onClick={() => {
                setSelectedBlock(record)
                setDrawerVisible(true)
              }}
            />
          </Tooltip>
          {record.is_active && (
            <Popconfirm
              title="Unblock this IP?"
              description="The IP will be immediately removed from the blocklist."
              onConfirm={() => unblockMutation.mutate({ ip: record.ip_address })}
              okText="Yes"
              cancelText="No"
            >
              <Tooltip title="Unblock IP">
                <Button
                  size="small"
                  type="primary"
                  danger
                  icon={<UnlockOutlined />}
                  loading={unblockMutation.isPending}
                />
              </Tooltip>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ]

  // Filter blocks locally based on search
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
      <div style={{ padding: 24 }}>
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
    <div style={{ padding: 24 }}>
      {/* Header */}
      <Row justify="space-between" align="middle" style={{ marginBottom: 24 }}>
        <Col>
          <Space direction="vertical" size={4}>
            <Title level={2} style={{ margin: 0 }}>
              Blocked IPs
            </Title>
            <Text type="secondary">
              View and manage automatically blocked IPs across all your servers
            </Text>
          </Space>
        </Col>
        <Col>
          <Space>
            <Button icon={<DownloadOutlined />}>
              Export CSV
            </Button>
            <Button icon={<FilterOutlined />}>
              Filters
            </Button>
          </Space>
        </Col>
      </Row>

      {/* Statistics Cards - Using Ant Design Statistics with Theme Tokens */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card styles={{ body: { padding: 16 } }}>
            <Statistic
              title="Active Blocks"
              value={stats.total_active}
              valueStyle={{ color: token.colorError }}
              prefix={<StopOutlined />}
            />
            <Text type="secondary" style={{ fontSize: 12 }}>Currently blocked</Text>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card styles={{ body: { padding: 16 } }}>
            <Statistic
              title="Blocked Today"
              value={stats.total_today}
              valueStyle={{ color: token.colorWarning }}
              prefix={<AlertOutlined />}
            />
            <Text type="secondary" style={{ fontSize: 12 }}>Last 24 hours</Text>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card styles={{ body: { padding: 16 } }}>
            <Statistic
              title="Unique Countries"
              value={Object.keys(stats.by_country).length}
              valueStyle={{ color: token.colorInfo }}
              prefix={<GlobalOutlined />}
            />
            <Text type="secondary" style={{ fontSize: 12 }}>Attack origins</Text>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card styles={{ body: { padding: 16 } }}>
            <Statistic
              title="Services Protected"
              value={Object.keys(stats.by_service).length}
              valueStyle={{ color: token.colorSuccess }}
              prefix={<SafetyOutlined />}
            />
            <Text type="secondary" style={{ fontSize: 12 }}>Under protection</Text>
          </Card>
        </Col>
      </Row>

      {/* Live Block Feed */}
      <LiveBlockFeed />

      {/* Filters */}
      <Card style={{ marginBottom: 24 }}>
        <Space wrap>
          <Select
            value={filters.server}
            onChange={(val) => {
              setFilters({ ...filters, server: val })
              setCurrentPage(1)
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
              setCurrentPage(1)
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
              setCurrentPage(1)
            }}
            style={{ width: 250 }}
            allowClear
          />
        </Space>
      </Card>

      {/* Main Table */}
      <Card styles={{ body: { padding: 0 } }}>
        <Table
          columns={columns}
          dataSource={filteredBlocks}
          loading={isLoading}
          rowKey="id"
          scroll={{ x: 1100 }}
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
                setCurrentPage(1)
              }
            },
          }}
          expandable={{
            expandedRowRender: (record) => (
              <div style={{ padding: 16, background: '#fafafa' }}>
                <Text strong style={{ fontSize: 13 }}>Threat Reasons</Text>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
                  {record.reasons && record.reasons.length > 0 ? (
                    record.reasons.map((reason) => (
                      <Tag key={reason} color={reasonTagColor(reason)}>
                        {reasonLabel(reason)}
                      </Tag>
                    ))
                  ) : (
                    <Text type="secondary">No specific reason recorded</Text>
                  )}
                </div>
              </div>
            ),
          }}
          locale={{
            emptyText: (
              <Empty
                image={<SafetyOutlined style={{ fontSize: 64, color: '#52c41a' }} />}
                description={
                  <Space direction="vertical" size={4}>
                    <Text style={{ fontSize: 16 }}>No blocked IPs found</Text>
                    <Text type="secondary">Your systems are currently secure</Text>
                  </Space>
                }
              />
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
          <Space direction="vertical" size={24} style={{ width: '100%' }}>
            <Alert
              message={selectedBlock.is_active ? 'Currently Blocked' : 'Unblocked'}
              type={selectedBlock.is_active ? 'error' : 'success'}
              showIcon
              icon={selectedBlock.is_active ? <StopOutlined /> : <CheckCircleOutlined />}
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
              {(selectedBlock.service_name || selectedBlock.target_port > 0) && (
                <Descriptions.Item label="Target Service">
                  <Space>
                    {serviceIcons[selectedBlock.service_name] || <CloudServerOutlined />}
                    {selectedBlock.service_name && (
                      <Text strong style={{ textTransform: 'uppercase' }}>
                        {selectedBlock.service_name}
                      </Text>
                    )}
                    {selectedBlock.target_port > 0 && (
                      <Text type="secondary">Port {selectedBlock.target_port}</Text>
                    )}
                    {selectedBlock.protocol?.toLowerCase() !== 'unknown' && (
                      <Text type="secondary">({selectedBlock.protocol?.toUpperCase()})</Text>
                    )}
                  </Space>
                </Descriptions.Item>
              )}
              <Descriptions.Item label="Threat Score">
                <Tag color={selectedBlock.threat_score >= 80 ? 'red' : selectedBlock.threat_score >= 60 ? 'orange' : 'gold'}>
                  {selectedBlock.threat_score}
                </Tag>
                <Tag color={selectedBlock.threat_level === 'malicious' ? 'red' : selectedBlock.threat_level === 'suspicious' ? 'orange' : 'default'} style={{ marginLeft: 4 }}>
                  {selectedBlock.threat_level?.charAt(0).toUpperCase() + selectedBlock.threat_level?.slice(1)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Reasons">
                <Space size={4} wrap>
                  {selectedBlock.reasons && selectedBlock.reasons.length > 0 ? (
                    selectedBlock.reasons.map((reason) => (
                      <Tag key={reason} color={reasonTagColor(reason)}>
                        {reasonLabel(reason)}
                      </Tag>
                    ))
                  ) : (
                    <Text type="secondary">No specific reason recorded</Text>
                  )}
                </Space>
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
              <Space direction="vertical" style={{ width: '100%' }}>
                <Popconfirm
                  title="Unblock this IP?"
                  onConfirm={() => {
                    unblockMutation.mutate({ ip: selectedBlock.ip_address })
                    setDrawerVisible(false)
                  }}
                >
                  <Button type="primary" danger block size="large" icon={<UnlockOutlined />}>
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
                    block
                    size="large"
                    icon={<CheckCircleOutlined />}
                    loading={whitelistLoading === selectedBlock.ip_address}
                  >
                    Whitelist & Unblock (False Positive)
                  </Button>
                </Popconfirm>
              </Space>
            )}
          </Space>
        )}
      </Drawer>
    </div>
  )
}

