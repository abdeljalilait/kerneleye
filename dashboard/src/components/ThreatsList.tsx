import { useState } from 'react'
import { Table, Input, Button, Typography, Card, Space, Progress, Avatar, Drawer, Descriptions, Tag, Statistic, Row, Col, Popconfirm, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Globe, Search, Shield, AlertTriangle, Ban, ExternalLink, MapPin, Clock, Activity, Server, Flag, Lock } from 'lucide-react'
import { useQueryClient, useMutation } from '@tanstack/react-query'
import { Threat } from '../types'
import api from '../api/client'
import { CountryFlag } from './CountryFlag'

const { Text, Title } = Typography

interface ThreatsListProps {
  threats: Threat[]
}

interface ThreatDetailsProps {
  threat: Threat | null;
  visible: boolean;
  onClose: () => void;
}

// API function to block an IP
const blockIP = async (ip: string) => {
  const { data } = await api.post('/blocks', { ip_address: ip });
  return data;
};

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

// Threat Details Drawer Component
function ThreatDetailsDrawer({ threat, visible, onClose }: ThreatDetailsProps) {
  if (!threat) return null;
  
  const config = getRiskConfig(threat.threat_score);
  const Icon = config.icon;
  
  const typeLabels: Record<string, string> = {
    port_scan: 'Port Scanning',
    service_abuse: 'Service Abuse',
    syn_flood: 'SYN Flood',
    failed_handshake: 'Failed Handshake',
    connection_burst: 'Connection Burst',
    none: 'Normal Traffic',
  };
  
  return (
    <Drawer
      title="Threat Details"
      placement="right"
      width={500}
      onClose={onClose}
      open={visible}
    >
      <div style={{ marginBottom: 24 }}>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 16, 
          padding: 16, 
          background: config.bg,
          borderRadius: 12,
          border: `1px solid ${config.color}30`,
        }}>
          <Avatar
            size={56}
            style={{
              background: 'rgba(255,255,255,0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Icon size={28} color={config.color} />
          </Avatar>
          <div>
            <Text style={{ fontSize: 12, color: config.color, fontWeight: 600 }}>
              {config.label}
            </Text>
            <Title level={4} style={{ margin: '4px 0', color: 'var(--text-primary)' }}>
              {threat.source_ip}
            </Title>
          </div>
        </div>
      </div>

      <Descriptions title="Risk Assessment" bordered column={1} style={{ marginBottom: 24 }}>
        <Descriptions.Item label="Threat Score">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Progress percent={threat.threat_score} size="small" strokeColor={config.color} style={{ width: 100 }} />
            <Text strong style={{ color: config.color }}>{threat.threat_score}</Text>
          </div>
        </Descriptions.Item>
        <Descriptions.Item label="Threat Level">
          <Tag color={threat.threat_level === 'malicious' ? 'red' : threat.threat_level === 'suspicious' ? 'orange' : 'green'}>
            {threat.threat_level?.toUpperCase()}
          </Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Detection Type">
          {typeLabels[threat.threat_type] || 'Detected by heuristics'}
        </Descriptions.Item>
      </Descriptions>

      <Descriptions title="Network Information" bordered column={1} style={{ marginBottom: 24 }}>
        <Descriptions.Item label="Source IP">
          <Text copyable className="font-mono">{threat.source_ip}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Target Port">
          {threat.destination_port}
        </Descriptions.Item>
        <Descriptions.Item label="Protocol">
          {threat.protocol?.toUpperCase()}
        </Descriptions.Item>
        <Descriptions.Item label="Location">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <MapPin size={14} />
            {threat.city && threat.country 
              ? `${threat.city}, ${threat.country}`
              : threat.country || threat.city || 'Unknown Location'}
          </div>
        </Descriptions.Item>
        {threat.isp && (
          <Descriptions.Item label="ISP">
            {threat.isp}
          </Descriptions.Item>
        )}
      </Descriptions>

      <Descriptions title="Activity Statistics" bordered column={1} style={{ marginBottom: 24 }}>
        <Descriptions.Item label="SYN Count">
          {threat.syn_count?.toLocaleString()}
        </Descriptions.Item>
        <Descriptions.Item label="ACK Count">
          {threat.ack_count?.toLocaleString()}
        </Descriptions.Item>
        <Descriptions.Item label="Failed Handshakes">
          {threat.failed_handshakes?.toLocaleString()}
        </Descriptions.Item>
        <Descriptions.Item label="Unique Ports Scanned">
          {threat.unique_ports?.toLocaleString()}
        </Descriptions.Item>
      </Descriptions>

      <Descriptions title="Timeline" bordered column={1}>
        <Descriptions.Item label="First Seen">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={14} />
            {new Date(threat.first_seen).toLocaleString()}
          </div>
        </Descriptions.Item>
        <Descriptions.Item label="Last Seen">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={14} />
            {new Date(threat.last_seen).toLocaleString()}
          </div>
        </Descriptions.Item>
      </Descriptions>
    </Drawer>
  );
}

export default function ThreatsList({ threats }: ThreatsListProps) {
  const queryClient = useQueryClient();
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [searchText, setSearchText] = useState('');
  
  // Block IP mutation
  const blockMutation = useMutation({
    mutationFn: blockIP,
    onSuccess: () => {
      message.success('IP blocked successfully');
      queryClient.invalidateQueries({ queryKey: ['threats'] });
      queryClient.invalidateQueries({ queryKey: ['blocks'] });
    },
    onError: (error: any) => {
      message.error(error?.response?.data?.message || 'Failed to block IP');
    },
  });
  
  const handleDetails = (threat: Threat) => {
    setSelectedThreat(threat);
    setDrawerVisible(true);
  };
  
  const handleBlock = (threat: Threat) => {
    blockMutation.mutate(threat.source_ip);
  };
  
  const filteredThreats = threats.filter(t => 
    t.source_ip.toLowerCase().includes(searchText.toLowerCase()) ||
    t.country?.toLowerCase().includes(searchText.toLowerCase()) ||
    t.city?.toLowerCase().includes(searchText.toLowerCase())
  );

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
              style={{
                background: config.bg,
                border: `2px solid ${config.color}40`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Icon size={22} color={config.color} />
            </Avatar>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'nowrap' }}>
                <Text strong style={{ 
                  color: 'var(--text-primary)', 
                  fontSize: 14, 
                  fontFamily: 'monospace',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  maxWidth: record.is_blocked ? 130 : 180,
                }}>
                  {ip}
                </Text>
                {record.is_blocked && (
                  <Tag
                    style={{
                      background: 'rgba(16, 185, 129, 0.15)',
                      color: '#10b981',
                      border: '1px solid rgba(16, 185, 129, 0.4)',
                      fontSize: 10,
                      fontWeight: 700,
                      padding: '2px 10px',
                      borderRadius: 12,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      textTransform: 'uppercase',
                      letterSpacing: '0.5px',
                      flexShrink: 0,
                    }}
                  >
                    <Lock size={10} />
                    BLOCKED
                  </Tag>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                <CountryFlag countryCode={record.country_code || record.country || ''} size={14} />
                <Text style={{ fontSize: 12, color: 'var(--text-tertiary)', whiteSpace: 'nowrap' }}>
                  {record.city && record.country 
                    ? `${record.city}, ${record.country}`
                    : record.country || record.city || record.isp || 'Unknown Location'}
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
      width: 160,
      render: (score) => {
        const config = getRiskConfig(score)
        return (
          <div style={{ width: 130 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, alignItems: 'center' }}>
              <Text style={{ 
                color: config.color, 
                fontSize: 11, 
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.5px'
              }}>
                {config.label}
              </Text>
              <Text style={{ 
                color: config.color, 
                fontSize: 14, 
                fontWeight: 700,
                fontFamily: 'monospace'
              }}>
                {score}
              </Text>
            </div>
            <Progress
              percent={score}
              size="small"
              strokeColor={config.color}
              trailColor="rgba(255, 255, 255, 0.08)"
              showInfo={false}
              strokeWidth={6}
              style={{ margin: 0 }}
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
      width: 180,
      render: (_, record) => (
        <Space size={8}>
          <Button 
            size="small" 
            icon={<ExternalLink size={14} />}
            onClick={() => handleDetails(record)}
            style={{ 
              color: 'var(--text-secondary)',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            Details
          </Button>
          {record.is_blocked ? (
            <Button 
              size="small" 
              disabled
              icon={<Lock size={14} />}
              style={{
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: '#10b981',
                opacity: 0.8,
              }}
            >
              Blocked
            </Button>
          ) : (
            <Popconfirm
              title="Block this IP?"
              description={`${record.source_ip} will be blocked and added to the blocklist.`}
              onConfirm={() => handleBlock(record)}
              okText="Yes, block"
              cancelText="Cancel"
              okButtonProps={{ danger: true, loading: blockMutation.isPending }}
            >
              <Button 
                size="small" 
                danger
                icon={<Ban size={14} />}
                loading={blockMutation.isPending}
                style={{
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                }}
              >
                Block
              </Button>
            </Popconfirm>
          )}
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
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
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
        dataSource={filteredThreats} 
        rowKey={(record) => `${record.source_ip}-${record.last_seen || Math.random()}`}
        rowClassName="threats-table-row"
        pagination={{ 
          pageSize: 5,
          size: 'small',
          position: ['bottomRight'],
          style: { margin: '16px 24px' }
        }}
        locale={{ 
          emptyText: (
            <div style={{ padding: '40px 0', textAlign: 'center' }}>
              <div style={{ marginBottom: 16 }}>
                <Shield size={48} color="var(--text-muted)" opacity={0.3} />
              </div>
              <Text style={{ color: 'var(--text-tertiary)' }}>
                {searchText ? 'No matching threats found' : 'No threats detected'}
              </Text>
              <br />
              <Text style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                {searchText ? 'Try a different search term' : 'Your systems are secure'}
              </Text>
            </div>
          ) 
        }}
        style={{
          background: 'transparent',
        }}
      />
      
      <ThreatDetailsDrawer 
        threat={selectedThreat}
        visible={drawerVisible}
        onClose={() => setDrawerVisible(false)}
      />
    </Card>
  )
}
