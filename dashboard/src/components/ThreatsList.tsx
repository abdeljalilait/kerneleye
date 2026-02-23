import { Table, Input, Button, Typography, Card, Space, Progress, Avatar } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Globe, Search, Shield, AlertTriangle, Ban, ExternalLink } from 'lucide-react'
import { Threat } from '../types'

const { Text, Title } = Typography

interface ThreatsListProps {
  threats: Threat[]
}

const getRiskConfig = (score: number) => {
  if (score >= 70) {
    return {
      color: '#ef4444',
      bg: 'rgba(239, 68, 68, 0.15)',
      label: 'Critical',
      icon: AlertTriangle,
    }
  } else if (score >= 40) {
    return {
      color: '#f59e0b',
      bg: 'rgba(245, 158, 11, 0.15)',
      label: 'High Risk',
      icon: Shield,
    }
  } else if (score >= 20) {
    return {
      color: '#fbbf24',
      bg: 'rgba(251, 191, 36, 0.15)',
      label: 'Suspicious',
      icon: Shield,
    }
  }
  return {
    color: '#10b981',
    bg: 'rgba(16, 185, 129, 0.15)',
    label: 'Low Risk',
    icon: Shield,
  }
}

export default function ThreatsList({ threats }: ThreatsListProps) {
  const columns: ColumnsType<Threat> = [
    {
      title: 'Threat',
      dataIndex: 'source_ip',
      key: 'source_ip',
      width: 280,
      render: (ip, record) => {
        const config = getRiskConfig(record.threat_score)
        const Icon = config.icon
        return (
          <Space size={12}>
            <Avatar
              size={40}
              style={{
                background: config.bg,
                border: `1px solid ${config.color}30`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Icon size={20} color={config.color} />
            </Avatar>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Text strong style={{ color: 'var(--text-primary)', fontSize: 14, fontFamily: 'monospace' }}>
                  {ip}
                </Text>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
                <Globe size={12} style={{ opacity: 0.5 }} />
                <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                  {record.location || 'Unknown Location'}
                </Text>
              </div>
            </div>
          </Space>
        )
      }
    },
    {
      title: 'Detection Reason',
      dataIndex: 'threat_type',
      key: 'reason',
      render: (threatType, record) => {
        const typeLabels: Record<string, string> = {
          port_scan: 'Port Scanning',
          service_abuse: 'Service Abuse',
          syn_flood: 'SYN Flood',
          failed_handshake: 'Failed Handshake',
          connection_burst: 'Connection Burst',
          none: 'Normal Traffic',
        }
        return (
          <div>
            <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
              {typeLabels[threatType] || 'Detected by heuristics'}
            </Text>
            {record.reason && (
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 11, display: 'block', marginTop: 2 }}>
                {record.reason}
              </Text>
            )}
          </div>
        )
      }
    },
    {
      title: 'Risk Score',
      dataIndex: 'threat_score',
      key: 'score',
      width: 180,
      render: (score) => {
        const config = getRiskConfig(score)
        return (
          <div style={{ width: 140 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <Text strong style={{ color: config.color, fontSize: 13 }}>
                {config.label}
              </Text>
              <Text style={{ color: config.color, fontSize: 13, fontWeight: 600 }}>
                {score}
              </Text>
            </div>
            <Progress
              percent={score}
              size="small"
              strokeColor={config.color}
              trailColor="rgba(255, 255, 255, 0.05)"
              showInfo={false}
            />
          </div>
        )
      }
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 150,
      render: (date) => (
        <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
          {date ? new Date(date).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Unknown'}
        </Text>
      )
    },
    {
      title: 'Actions',
      key: 'action',
      width: 150,
      render: () => (
        <Space size={4}>
          <Button 
            size="small" 
            type="text" 
            icon={<ExternalLink size={14} />}
            style={{ color: 'var(--text-secondary)' }}
          >
            Details
          </Button>
          <Button 
            size="small" 
            type="text" 
            danger
            icon={<Ban size={14} />}
          >
            Block
          </Button>
        </Space>
      )
    }
  ]

  return (
    <Card
      variant="borderless"
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        backdropFilter: 'blur(10px)',
        height: '100%',
      }}
      bodyStyle={{ padding: 0, height: '100%' }}
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div 
            style={{
              width: 36,
              height: 36,
              background: 'rgba(239, 68, 68, 0.15)',
              borderRadius: 10,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={18} color="#ef4444" />
          </div>
          <div>
            <Title level={5} style={{ margin: 0, color: 'var(--text-primary)', fontSize: 16 }}>
              Detected Threats
            </Title>
            <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
              {threats.length} active threats
            </Text>
          </div>
        </div>
      }
      extra={
        <Input 
          placeholder="Search IP..." 
          prefix={<Search size={14} style={{ opacity: 0.5 }} />} 
          style={{ 
            width: 200, 
            background: 'var(--bg-tertiary)',
            border: '1px solid var(--border-subtle)',
          }}
        />
      }
    >
      <Table 
        columns={columns} 
        dataSource={threats} 
        rowKey={(record) => `${record.source_ip}-${record.last_seen || Math.random()}`}
        pagination={{ 
          pageSize: 5,
          size: 'small',
          style: { margin: '16px 24px' }
        }}
        locale={{ 
          emptyText: (
            <div style={{ padding: '40px 0', textAlign: 'center' }}>
              <div style={{ marginBottom: 16 }}>
                <Shield size={48} color="var(--text-muted)" opacity={0.3} />
              </div>
              <Text style={{ color: 'var(--text-tertiary)' }}>No threats detected</Text>
              <br />
              <Text style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                Your systems are secure
              </Text>
            </div>
          ) 
        }}
        style={{
          background: 'transparent',
        }}
      />
    </Card>
  )
}
