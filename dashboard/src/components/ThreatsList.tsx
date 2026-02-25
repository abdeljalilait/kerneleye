import { useState } from 'react'
import { Table, Input, Button, Typography, Card, Space, Progress, Avatar, Drawer, Descriptions, Tag, Statistic, Row, Col, Popconfirm, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Globe, Search, Shield, AlertTriangle, Ban, ExternalLink, MapPin, Clock, Activity, Server, Flag, Lock } from 'lucide-react'
import { useQueryClient, useMutation } from '@tanstack/react-query'
import { Threat } from '../types'
import api from '../api/client'
// Import commonly used flags
import US from 'country-flag-icons/react/3x2/US'
import GB from 'country-flag-icons/react/3x2/GB'
import CA from 'country-flag-icons/react/3x2/CA'
import AU from 'country-flag-icons/react/3x2/AU'
import DE from 'country-flag-icons/react/3x2/DE'
import FR from 'country-flag-icons/react/3x2/FR'
import IT from 'country-flag-icons/react/3x2/IT'
import ES from 'country-flag-icons/react/3x2/ES'
import NL from 'country-flag-icons/react/3x2/NL'
import RU from 'country-flag-icons/react/3x2/RU'
import CN from 'country-flag-icons/react/3x2/CN'
import JP from 'country-flag-icons/react/3x2/JP'
import KR from 'country-flag-icons/react/3x2/KR'
import IN from 'country-flag-icons/react/3x2/IN'
import BR from 'country-flag-icons/react/3x2/BR'
import MX from 'country-flag-icons/react/3x2/MX'
import SG from 'country-flag-icons/react/3x2/SG'
import HK from 'country-flag-icons/react/3x2/HK'
import TW from 'country-flag-icons/react/3x2/TW'
import CH from 'country-flag-icons/react/3x2/CH'
import SE from 'country-flag-icons/react/3x2/SE'
import NO from 'country-flag-icons/react/3x2/NO'
import DK from 'country-flag-icons/react/3x2/DK'
import FI from 'country-flag-icons/react/3x2/FI'
import PL from 'country-flag-icons/react/3x2/PL'
import CZ from 'country-flag-icons/react/3x2/CZ'
import AT from 'country-flag-icons/react/3x2/AT'
import BE from 'country-flag-icons/react/3x2/BE'
import IE from 'country-flag-icons/react/3x2/IE'
import PT from 'country-flag-icons/react/3x2/PT'
import GR from 'country-flag-icons/react/3x2/GR'
import TR from 'country-flag-icons/react/3x2/TR'
import UA from 'country-flag-icons/react/3x2/UA'
import RO from 'country-flag-icons/react/3x2/RO'
import HU from 'country-flag-icons/react/3x2/HU'
import IL from 'country-flag-icons/react/3x2/IL'
import AE from 'country-flag-icons/react/3x2/AE'
import SA from 'country-flag-icons/react/3x2/SA'
import ZA from 'country-flag-icons/react/3x2/ZA'
import NG from 'country-flag-icons/react/3x2/NG'
import EG from 'country-flag-icons/react/3x2/EG'
import PK from 'country-flag-icons/react/3x2/PK'
import BD from 'country-flag-icons/react/3x2/BD'
import ID from 'country-flag-icons/react/3x2/ID'
import TH from 'country-flag-icons/react/3x2/TH'
import VN from 'country-flag-icons/react/3x2/VN'
import MY from 'country-flag-icons/react/3x2/MY'
import PH from 'country-flag-icons/react/3x2/PH'
import NZ from 'country-flag-icons/react/3x2/NZ'
import CL from 'country-flag-icons/react/3x2/CL'
import CO from 'country-flag-icons/react/3x2/CO'
import AR from 'country-flag-icons/react/3x2/AR'
import PE from 'country-flag-icons/react/3x2/PE'
import VE from 'country-flag-icons/react/3x2/VE'
import EC from 'country-flag-icons/react/3x2/EC'
import UY from 'country-flag-icons/react/3x2/UY'
import PY from 'country-flag-icons/react/3x2/PY'
import BO from 'country-flag-icons/react/3x2/BO'

const flagComponents: Record<string, React.FC<{ style?: React.CSSProperties }>> = {
  US, GB, CA, AU, DE, FR, IT, ES, NL, RU, CN, JP, KR, IN, BR, MX, SG, HK, TW,
  CH, SE, NO, DK, FI, PL, CZ, AT, BE, IE, PT, GR, TR, UA, RO, HU, IL, AE, SA,
  ZA, NG, EG, PK, BD, ID, TH, VN, MY, PH, NZ, CL, CO, AR, PE, VE, EC, UY, PY, BO,
}

// Normalize country code from various formats
const normalizeCountryCode = (country: string): string => {
  if (!country) return ''
  if (/^[A-Za-z]{2}$/.test(country)) return country.toUpperCase()
  
  // Map of common country names to codes
  const countryMap: Record<string, string> = {
    'united states': 'US',
    'usa': 'US',
    'united kingdom': 'GB',
    'uk': 'GB',
    'germany': 'DE',
    'france': 'FR',
    'italy': 'IT',
    'spain': 'ES',
    'netherlands': 'NL',
    'russia': 'RU',
    'china': 'CN',
    'japan': 'JP',
    'south korea': 'KR',
    'korea': 'KR',
    'india': 'IN',
    'brazil': 'BR',
    'mexico': 'MX',
    'singapore': 'SG',
    'hong kong': 'HK',
    'taiwan': 'TW',
    'switzerland': 'CH',
    'sweden': 'SE',
    'norway': 'NO',
    'denmark': 'DK',
    'finland': 'FI',
    'poland': 'PL',
    'czech republic': 'CZ',
    'austria': 'AT',
    'belgium': 'BE',
    'ireland': 'IE',
    'portugal': 'PT',
    'greece': 'GR',
    'turkey': 'TR',
    'ukraine': 'UA',
    'romania': 'RO',
    'hungary': 'HU',
    'israel': 'IL',
    'united arab emirates': 'AE',
    'saudi arabia': 'SA',
    'south africa': 'ZA',
    'nigeria': 'NG',
    'egypt': 'EG',
    'pakistan': 'PK',
    'bangladesh': 'BD',
    'indonesia': 'ID',
    'thailand': 'TH',
    'vietnam': 'VN',
    'malaysia': 'MY',
    'philippines': 'PH',
    'new zealand': 'NZ',
    'chile': 'CL',
    'colombia': 'CO',
    'argentina': 'AR',
    'peru': 'PE',
    'venezuela': 'VE',
    'ecuador': 'EC',
    'uruguay': 'UY',
    'paraguay': 'PY',
    'bolivia': 'BO',
    'canada': 'CA',
    'australia': 'AU',
  }
  
  return countryMap[country.toLowerCase()] || ''
}

// Country flag component
const CountryFlag = ({ countryCode, size = 12 }: { countryCode: string; size?: number }) => {
  const code = normalizeCountryCode(countryCode)
  if (!code) return <Globe size={size} style={{ opacity: 0.5 }} />
  
  const FlagComponent = flagComponents[code]
  if (!FlagComponent) return <Globe size={size} style={{ opacity: 0.5 }} />
  
  return <FlagComponent style={{ width: size * 1.5, height: size, borderRadius: 2 }} />
}

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
                {record.is_blocked && (
                  <Tag
                    style={{
                      background: 'rgba(239, 68, 68, 0.15)',
                      color: '#ef4444',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      fontSize: 10,
                      fontWeight: 600,
                      padding: '0px 8px',
                      borderRadius: 4,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                    }}
                  >
                    <Lock size={10} />
                    BLOCKED
                  </Tag>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
                <CountryFlag countryCode={record.country_code || record.country || ''} size={12} />
                <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
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
