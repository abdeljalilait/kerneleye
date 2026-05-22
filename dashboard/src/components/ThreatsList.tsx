import { useState } from 'react'
import { Table, Input, Button, Typography, Card, Space, Progress, Avatar, Drawer, Descriptions, Tag, Popconfirm, message, theme, Empty } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Search, Shield, AlertTriangle, Ban, ExternalLink, MapPin, Clock, Lock } from 'lucide-react'
import { useQueryClient, useMutation } from '@tanstack/react-query'
import { Threat } from '../types'
import api from '../api/client'
import { CountryFlag } from './CountryFlag'

const { Text, Title } = Typography

interface ThreatsListProps {
  threats: Threat[]
}

interface ThreatDetailsProps {
  threat: Threat | null
  visible: boolean
  onClose: () => void
}

const blockIP = async (ip: string) => {
  const { data } = await api.post('/blocks', { ip_address: ip })
  return data
}

const getRiskConfig = (score: number) => {
  if (score >= 70) return { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.12)', label: 'Critical', icon: AlertTriangle }
  if (score >= 40) return { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.12)', label: 'High Risk', icon: Shield }
  if (score >= 20) return { color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.12)', label: 'Suspicious', icon: Shield }
  return { color: '#10b981', bg: 'rgba(16, 185, 129, 0.12)', label: 'Low Risk', icon: Shield }
}

const typeLabels: Record<string, string> = {
  port_scan: 'Port Scanning',
  service_abuse: 'Service Abuse',
  syn_flood: 'SYN Flood',
  failed_handshake: 'Failed Handshake',
  connection_burst: 'Connection Burst',
  none: 'Normal Traffic',
}

function ThreatDetailsDrawer({ threat, visible, onClose }: ThreatDetailsProps) {
  const { token } = theme.useToken()
  if (!threat) return null

  const config = getRiskConfig(threat.threat_score)
  const Icon = config.icon

  return (
    <Drawer title="Threat Details" placement="right" width={500} onClose={onClose} open={visible}>
      {/* Risk header */}
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: 16,
          padding: 16, background: config.bg,
          borderRadius: token.borderRadius,
          border: `1px solid ${config.color}30`,
          marginBottom: 24,
        }}
      >
        <Avatar size={56} style={{ background: 'rgba(255,255,255,0.2)' }} icon={<Icon size={28} color={config.color} />} />
        <div>
          <Text style={{ fontSize: 12, color: config.color, fontWeight: 600 }}>{config.label}</Text>
          <Title level={4} style={{ margin: '4px 0' }}>{threat.source_ip}</Title>
        </div>
      </div>

      <Descriptions title="Risk Assessment" bordered column={1} style={{ marginBottom: 24 }}>
        <Descriptions.Item label="Threat Score">
          <Space size={12}>
            <Progress percent={threat.threat_score} size="small" strokeColor={config.color} style={{ width: 100 }} />
            <Text strong style={{ color: config.color }}>{threat.threat_score}</Text>
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="Threat Level">
          <Tag color={threat.threat_level === 'malicious' ? 'red' : threat.threat_level === 'suspicious' ? 'orange' : 'green'}>
            {threat.threat_level?.toUpperCase()}
          </Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Detection Type">{typeLabels[threat.threat_type] || 'Detected by heuristics'}</Descriptions.Item>
      </Descriptions>

      <Descriptions title="Network Information" bordered column={1} style={{ marginBottom: 24 }}>
        <Descriptions.Item label="Source IP">
          <Text copyable style={{ fontFamily: 'monospace' }}>{threat.source_ip}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Target Port">{threat.destination_port}</Descriptions.Item>
        <Descriptions.Item label="Protocol">{threat.protocol?.toUpperCase()}</Descriptions.Item>
        <Descriptions.Item label="Location">
          <Space size={8}>
            <MapPin size={14} />
            {threat.city && threat.country ? `${threat.city}, ${threat.country}` : threat.country || threat.city || 'Unknown Location'}
          </Space>
        </Descriptions.Item>
        {threat.isp && <Descriptions.Item label="ISP">{threat.isp}</Descriptions.Item>}
      </Descriptions>

      <Descriptions title="Activity Statistics" bordered column={1} style={{ marginBottom: 24 }}>
        <Descriptions.Item label="SYN Count">{threat.syn_count?.toLocaleString()}</Descriptions.Item>
        <Descriptions.Item label="ACK Count">{threat.ack_count?.toLocaleString()}</Descriptions.Item>
        <Descriptions.Item label="Failed Handshakes">{threat.failed_handshakes?.toLocaleString()}</Descriptions.Item>
        <Descriptions.Item label="Unique Ports Scanned">{threat.unique_ports?.toLocaleString()}</Descriptions.Item>
      </Descriptions>

      <Descriptions title="Timeline" bordered column={1}>
        <Descriptions.Item label="First Seen">
          <Space size={8}><Clock size={14} />{new Date(threat.first_seen).toLocaleString()}</Space>
        </Descriptions.Item>
        <Descriptions.Item label="Last Seen">
          <Space size={8}><Clock size={14} />{new Date(threat.last_seen).toLocaleString()}</Space>
        </Descriptions.Item>
      </Descriptions>
    </Drawer>
  )
}

export default function ThreatsList({ threats }: ThreatsListProps) {
  const queryClient = useQueryClient()
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null)
  const [drawerVisible, setDrawerVisible] = useState(false)
  const [searchText, setSearchText] = useState('')
  const { token } = theme.useToken()

  const blockMutation = useMutation({
    mutationFn: blockIP,
    onSuccess: () => {
      message.success('IP blocked successfully')
      queryClient.invalidateQueries({ queryKey: ['threats'] })
      queryClient.invalidateQueries({ queryKey: ['blocks'] })
    },
    onError: (error: any) => {
      message.error(error?.response?.data?.message || 'Failed to block IP')
    },
  })

  const filteredThreats = threats.filter(t =>
    t.source_ip.toLowerCase().includes(searchText.toLowerCase()) ||
    t.country?.toLowerCase().includes(searchText.toLowerCase()) ||
    t.city?.toLowerCase().includes(searchText.toLowerCase()),
  )
  const blockedCount = threats.filter(t => t.is_blocked).length

  const columns: ColumnsType<Threat> = [
    {
      title: 'Threat',
      dataIndex: 'source_ip',
      key: 'source_ip',
      width: 300,
      render: (ip, record) => {
        const config = getRiskConfig(record.threat_score)
        const Icon = config.icon
        return (
          <Space size={12}>
            <Avatar
              size={44}
              style={{ background: config.bg, border: `2px solid ${config.color}40` }}
              icon={<Icon size={22} color={config.color} />}
            />
            <div style={{ minWidth: 0, flex: 1 }}>
              <Space size={8}>
                <Text strong style={{ fontFamily: 'monospace', fontSize: 14 }}>
                  {ip}
                </Text>
                {record.is_blocked && (
                  <Tag style={{ color: '#10b981', border: `1px solid rgba(16,185,129,0.4)`, fontSize: 10, fontWeight: 700 }}>
                    <Lock size={10} style={{ marginRight: 4 }} />BLOCKED
                  </Tag>
                )}
              </Space>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                <CountryFlag countryCode={record.country_code || record.country || ''} size={14} />
                <Text style={{ fontSize: 12, color: token.colorTextTertiary }}>
                  {record.city && record.country ? `${record.city}, ${record.country}` : record.country || record.city || record.isp || 'Unknown Location'}
                </Text>
              </div>
            </div>
          </Space>
        )
      },
    },
    {
      title: 'Detection Reason',
      dataIndex: 'threat_type',
      key: 'reason',
      render: (threatType, record) => (
        <div>
          <Text style={{ fontSize: 13 }}>{typeLabels[threatType] || 'Detected by heuristics'}</Text>
          {record.reason && (
            <Text type="secondary" style={{ fontSize: 11, display: 'block', marginTop: 2 }}>{record.reason}</Text>
          )}
        </div>
      ),
    },
    {
      title: 'Risk Score',
      dataIndex: 'threat_score',
      key: 'score',
      width: 160,
      render: (score) => {
        const config = getRiskConfig(score)
        return (
          <div style={{ width: 130 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <Text style={{ color: config.color, fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>{config.label}</Text>
              <Text style={{ color: config.color, fontSize: 14, fontWeight: 700, fontFamily: 'monospace' }}>{score}</Text>
            </div>
            <Progress percent={score} size="small" strokeColor={config.color} trailColor={token.colorFillContent} showInfo={false} />
          </div>
        )
      },
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 150,
      render: (date) => (
        <Text type="secondary" style={{ fontSize: 13 }}>
          {date ? new Date(date).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Unknown'}
        </Text>
      ),
    },
    {
      title: 'Actions',
      key: 'action',
      width: 180,
      render: (_, record) => (
        <Space size={8}>
          <Button size="small" icon={<ExternalLink size={14} />} onClick={() => { setSelectedThreat(record); setDrawerVisible(true) }}>
            Details
          </Button>
          {record.is_blocked ? (
            <Button size="small" disabled icon={<Lock size={14} />} style={{ color: '#10b981' }}>
              Blocked
            </Button>
          ) : (
            <Popconfirm
              title="Block this IP?"
              description={`${record.source_ip} will be blocked and added to the blocklist.`}
              onConfirm={() => blockMutation.mutate(record.source_ip)}
              okText="Yes, block"
              cancelText="Cancel"
              okButtonProps={{ danger: true, loading: blockMutation.isPending }}
            >
              <Button size="small" danger icon={<Ban size={14} />} loading={blockMutation.isPending}>
                Block
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Card
      styles={{ body: { padding: 0 } }}
      title={
        <Space size={12}>
          <div style={{ width: 36, height: 36, background: 'rgba(239, 68, 68, 0.12)', borderRadius: token.borderRadius, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={18} color="#ef4444" />
          </div>
          <div>
            <Title level={5} style={{ margin: 0, fontSize: 16 }}>Detected Threats</Title>
            <Text type="secondary" style={{ fontSize: 12 }}>{threats.length} detected, {blockedCount} blocked</Text>
          </div>
        </Space>
      }
      extra={
        <Input
          placeholder="Search IP..."
          prefix={<Search size={14} style={{ opacity: 0.5 }} />}
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          style={{ width: 200 }}
        />
      }
    >
      <Table
        columns={columns}
        dataSource={filteredThreats}
        rowKey={(record) => `${record.source_ip}-${record.last_seen || Math.random()}`}
        pagination={{ pageSize: 5, size: 'small', position: ['bottomRight'] }}
        locale={{
          emptyText: (
            <Empty
              image={<Shield size={48} color={token.colorTextQuaternary} style={{ opacity: 0.3 }} />}
              description={searchText ? 'No matching threats found' : 'No threats detected'}
            >
              {searchText ? 'Try a different search term' : 'Your systems are secure'}
            </Empty>
          ),
        }}
      />

      <ThreatDetailsDrawer threat={selectedThreat} visible={drawerVisible} onClose={() => setDrawerVisible(false)} />
    </Card>
  )
}
