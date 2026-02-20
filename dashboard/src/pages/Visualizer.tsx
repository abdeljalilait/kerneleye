import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import {
  Card,
  Button,
  Typography,
  Row,
  Col,
  Badge,
  Space,
  Tabs,
  Tag,
  Tooltip,
  Select,
  DatePicker,
  Radio,
  Empty,
  Spin,
} from 'antd';
import {
  ArrowLeft,
  Globe,
  Server,
  Shield,
  Building2,
  Filter,
  BarChart3,
  Target,
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  Legend,
} from 'recharts';
import { 
  useThreats, 
  useServers,
  useTopSourceIPs,
  useTopASNs,
} from '../hooks/useQueries';

const { Title, Text } = Typography;
const { TabPane } = Tabs;
const { RangePicker } = DatePicker;

// Mock data - in production this comes from API
interface SourceIP {
  ip: string;
  count: number;
  percentage: number;
  country: string;
  countryCode: string;
  asn: string;
  isp: string;
  firstSeen: string;
  lastSeen: string;
  timeline: { time: string; count: number }[];
  threatTypes: string[];
}

interface SourceAS {
  asn: string;
  name: string;
  country: string;
  countryCode: string;
  count: number;
  percentage: number;
  timeline: { time: string; count: number }[];
  topIPs: string[];
}

// Generate mock timeline data
const generateTimeline = (baseCount: number) => {
  const data = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      count: Math.floor(Math.random() * baseCount * 0.5) + (Math.random() > 0.7 ? baseCount : 0),
    });
  }
  return data;
};

const mockSourceIPs: SourceIP[] = [
  {
    ip: '123.249.96.46',
    count: 45,
    percentage: 4.4,
    country: 'China',
    countryCode: 'CN',
    asn: 'AS4134',
    isp: 'Huawei Cloud Service data center',
    firstSeen: '2024-02-18T08:30:00Z',
    lastSeen: '2024-02-20T14:22:00Z',
    timeline: generateTimeline(3),
    threatTypes: ['SSH Bruteforce', 'Port Scan'],
  },
  {
    ip: '143.110.183.221',
    count: 42,
    percentage: 4.1,
    country: 'United States',
    countryCode: 'US',
    asn: 'AS14061',
    isp: 'DigitalOcean, LLC',
    firstSeen: '2024-02-18T12:15:00Z',
    lastSeen: '2024-02-20T16:45:00Z',
    timeline: generateTimeline(3),
    threatTypes: ['HTTP Scan', 'HTTP Bruteforce'],
  },
  {
    ip: '165.245.130.81',
    count: 38,
    percentage: 3.7,
    country: 'Singapore',
    countryCode: 'SG',
    asn: 'AS14061',
    isp: 'DigitalOcean, LLC',
    firstSeen: '2024-02-19T03:20:00Z',
    lastSeen: '2024-02-20T11:30:00Z',
    timeline: generateTimeline(2),
    threatTypes: ['SSH Bruteforce'],
  },
  {
    ip: '110.72.242.164',
    count: 35,
    percentage: 3.4,
    country: 'China',
    countryCode: 'CN',
    asn: 'AS4837',
    isp: 'CHINA UNICOM China169 Backbone',
    firstSeen: '2024-02-18T22:10:00Z',
    lastSeen: '2024-02-20T09:15:00Z',
    timeline: generateTimeline(2),
    threatTypes: ['HTTP Exploit', 'Port Scan'],
  },
  {
    ip: '139.59.77.158',
    count: 32,
    percentage: 3.1,
    country: 'India',
    countryCode: 'IN',
    asn: 'AS14061',
    isp: 'DigitalOcean, LLC',
    firstSeen: '2024-02-19T15:45:00Z',
    lastSeen: '2024-02-20T18:20:00Z',
    timeline: generateTimeline(2),
    threatTypes: ['SSH Bruteforce'],
  },
  {
    ip: '139.59.180.235',
    count: 28,
    percentage: 2.7,
    country: 'India',
    countryCode: 'IN',
    asn: 'AS14061',
    isp: 'DigitalOcean, LLC',
    firstSeen: '2024-02-19T08:00:00Z',
    lastSeen: '2024-02-20T13:40:00Z',
    timeline: generateTimeline(2),
    threatTypes: ['HTTP Scan'],
  },
  {
    ip: '151.47.67.96',
    count: 25,
    percentage: 2.4,
    country: 'Italy',
    countryCode: 'IT',
    asn: 'AS1267',
    isp: 'Wind Tre S.p.A.',
    firstSeen: '2024-02-18T19:30:00Z',
    lastSeen: '2024-02-20T10:55:00Z',
    timeline: generateTimeline(1),
    threatTypes: ['SSH Bruteforce'],
  },
  {
    ip: '159.138.238.77',
    count: 23,
    percentage: 2.2,
    country: 'Hong Kong',
    countryCode: 'HK',
    asn: 'AS55990',
    isp: 'HUAWEI CLOUDS',
    firstSeen: '2024-02-19T11:20:00Z',
    lastSeen: '2024-02-20T15:30:00Z',
    timeline: generateTimeline(1),
    threatTypes: ['Port Scan'],
  },
];

const mockSourceAS: SourceAS[] = [
  {
    asn: 'AS14061',
    name: 'DigitalOcean, LLC',
    country: 'United States',
    countryCode: 'US',
    count: 320,
    percentage: 31.2,
    timeline: generateTimeline(15),
    topIPs: ['143.110.183.221', '165.245.130.81', '139.59.77.158'],
  },
  {
    asn: 'AS4134',
    name: 'Huawei Cloud Service data center',
    country: 'China',
    countryCode: 'CN',
    count: 180,
    percentage: 17.5,
    timeline: generateTimeline(8),
    topIPs: ['123.249.96.46', '121.37.8.92', '119.3.228.47'],
  },
  {
    asn: 'AS4837',
    name: 'CHINA UNICOM China169 Backbone',
    country: 'China',
    countryCode: 'CN',
    count: 145,
    percentage: 14.1,
    timeline: generateTimeline(6),
    topIPs: ['110.72.242.164', '123.125.13.79', '221.198.29.108'],
  },
  {
    asn: 'AS55990',
    name: 'HUAWEI CLOUDS',
    country: 'Hong Kong',
    countryCode: 'HK',
    count: 95,
    percentage: 9.3,
    timeline: generateTimeline(4),
    topIPs: ['159.138.238.77', '119.8.34.101', '159.138.124.55'],
  },
  {
    asn: 'AS1267',
    name: 'Wind Tre S.p.A.',
    country: 'Italy',
    countryCode: 'IT',
    count: 68,
    percentage: 6.6,
    timeline: generateTimeline(3),
    topIPs: ['151.47.67.96', '151.57.32.184', '151.61.208.92'],
  },
];

const COLORS = ['#6366f1', '#f59e0b', '#10b981', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16'];

// Mini Sparkline component
const Sparkline = ({ data, color }: { data: { time: string; count: number }[]; color: string }) => (
  <div style={{ width: 120, height: 40 }}>
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data}>
        <Line
          type="monotone"
          dataKey="count"
          stroke={color}
          strokeWidth={2}
          dot={false}
          fill="none"
        />
      </LineChart>
    </ResponsiveContainer>
  </div>
);

// Country flag emoji
const getFlagEmoji = (countryCode: string) => {
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
};

export default function Visualizer() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('source-ip');
  const [timeRange, setTimeRange] = useState('24h');
  const [visibility, setVisibility] = useState('expanded');
  const { isLoading: threatsLoading } = useThreats();
  const { data: servers } = useServers();

  // Calculate date range based on timeRange selection
  const getDateRange = () => {
    const end = new Date();
    const start = new Date();
    switch (timeRange) {
      case '1h': start.setHours(end.getHours() - 1); break;
      case '6h': start.setHours(end.getHours() - 6); break;
      case '24h': start.setDate(end.getDate() - 1); break;
      case '7d': start.setDate(end.getDate() - 7); break;
      case '30d': start.setDate(end.getDate() - 30); break;
      default: start.setDate(end.getDate() - 1);
    }
    return {
      startDate: start.toISOString().split('T')[0],
      endDate: end.toISOString().split('T')[0],
    };
  };

  const { startDate, endDate } = getDateRange();

  // Fetch real data from APIs
  const { data: topSourceIPs, isLoading: ipsLoading } = useTopSourceIPs(startDate, endDate, 20);
  const { data: topASNs, isLoading: asnsLoading } = useTopASNs(startDate, endDate, 10);

  const isLoading = threatsLoading || ipsLoading || asnsLoading;

  // Transform API data to match expected format
  const sourceIPsData = (topSourceIPs || []).map((ip: any, index: number) => ({
    ip: ip.ip,
    count: ip.count || 0,
    percentage: 0, // Will be calculated
    country: ip.country || 'Unknown',
    countryCode: ip.country || 'UN',
    asn: 'N/A',
    isp: ip.isp || 'Unknown',
    firstSeen: ip.first_seen,
    lastSeen: ip.last_seen,
    timeline: [], // Timeline would need separate API call
    threatTypes: [],
  }));

  // Calculate percentages
  const totalCount = sourceIPsData.reduce((sum: number, ip: any) => sum + ip.count, 0);
  sourceIPsData.forEach((ip: any) => {
    ip.percentage = totalCount > 0 ? parseFloat(((ip.count / totalCount) * 100).toFixed(1)) : 0;
  });

  const sourceASData = (topASNs || []).map((as: any, index: number) => ({
    asn: as.asn || 'Unknown',
    name: as.isp_name || as.asn || 'Unknown',
    country: as.country || 'Unknown',
    countryCode: as.country || 'UN',
    count: as.count || 0,
    percentage: 0,
    timeline: [],
    topIPs: [],
  }));

  // Calculate percentages for AS data
  const totalASCount = sourceASData.reduce((sum: number, as: any) => sum + as.count, 0);
  sourceASData.forEach((as: any) => {
    as.percentage = totalASCount > 0 ? parseFloat(((as.count / totalASCount) * 100).toFixed(1)) : 0;
  });

  const totalAlerts = sourceIPsData.reduce((sum: number, ip: any) => sum + ip.count, 0);
  const uniqueIPs = sourceIPsData.length;
  const uniqueAS = sourceASData.length;
  const uniqueCountries = new Set(sourceIPsData.map((ip: any) => ip.country)).size;

  // Use real data or fallback to empty arrays
  const mockSourceIPs = sourceIPsData.length > 0 ? sourceIPsData : [];
  const mockSourceAS = sourceASData.length > 0 ? sourceASData : [];

  return (
    <div style={{ padding: '24px 48px', maxWidth: 1600, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <Button
          icon={<ArrowLeft size={16} />}
          type="text"
          onClick={() => navigate({ to: '/dashboard' })}
          style={{ marginBottom: 16 }}
        >
          Back to Dashboard
        </Button>
        <Row justify="space-between" align="middle">
          <Col>
            <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
              Visualizer
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>
              Attack source analysis and threat visualization
            </Text>
          </Col>
          <Col>
            <Space>
              <Radio.Group value={visibility} onChange={(e) => setVisibility(e.target.value)}>
                <Radio.Button value="none">None</Radio.Button>
                <Radio.Button value="summary">Summary</Radio.Button>
                <Radio.Button value="expanded">Expanded</Radio.Button>
              </Radio.Group>
            </Space>
          </Col>
        </Row>
      </div>

      {/* Stats Bar */}
      <Card
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          marginBottom: 24,
        }}
        bodyStyle={{ padding: '12px 24px' }}
      >
        <Space size={32}>
          <Space>
            <Target size={16} color="#818cf8" />
            <Text style={{ color: 'var(--text-secondary)' }}>Source IP:</Text>
            <Text strong style={{ color: 'var(--text-primary)' }}>{uniqueIPs}</Text>
          </Space>
          <Space>
            <Building2 size={16} color="#f59e0b" />
            <Text style={{ color: 'var(--text-secondary)' }}>Source AS:</Text>
            <Text strong style={{ color: 'var(--text-primary)' }}>{uniqueAS}</Text>
          </Space>
          <Space>
            <Globe size={16} color="#10b981" />
            <Text style={{ color: 'var(--text-secondary)' }}>Countries:</Text>
            <Text strong style={{ color: 'var(--text-primary)' }}>{uniqueCountries}</Text>
          </Space>
          <Space>
            <Shield size={16} color="#ef4444" />
            <Text style={{ color: 'var(--text-secondary)' }}>Scenarios:</Text>
            <Text strong style={{ color: 'var(--text-primary)' }}>5</Text>
          </Space>
          <Space>
            <Server size={16} color="#8b5cf6" />
            <Text style={{ color: 'var(--text-secondary)' }}>Security Engines:</Text>
            <Text strong style={{ color: 'var(--text-primary)' }}>1</Text>
          </Space>
        </Space>
      </Card>

      {/* Filters */}
      <Card
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          marginBottom: 24,
        }}
        bodyStyle={{ padding: 16 }}
      >
        <Row gutter={16} align="middle">
          <Col>
            <Space>
              <Filter size={16} color="var(--text-tertiary)" />
              <Text style={{ color: 'var(--text-secondary)' }}>Time Range:</Text>
            </Space>
          </Col>
          <Col>
            <Select value={timeRange} onChange={setTimeRange} style={{ width: 120 }}>
              <Select.Option value="1h">Last 1 hour</Select.Option>
              <Select.Option value="6h">Last 6 hours</Select.Option>
              <Select.Option value="24h">Last 24 hours</Select.Option>
              <Select.Option value="7d">Last 7 days</Select.Option>
              <Select.Option value="30d">Last 30 days</Select.Option>
            </Select>
          </Col>
          <Col flex="auto" />
          <Col>
            <Select placeholder="Filter by engine or tag..." style={{ width: 250 }}>
              <Select.Option value="all">All Engines</Select.Option>
              <Select.Option value="ssh">SSH Bruteforce</Select.Option>
              <Select.Option value="http">HTTP Attacks</Select.Option>
              <Select.Option value="scan">Port Scans</Select.Option>
            </Select>
          </Col>
        </Row>
      </Card>

      {/* Main Content */}
      {isLoading ? (
        <div style={{ textAlign: 'center', padding: 64 }}>
          <Spin size="large" />
          <Text style={{ display: 'block', marginTop: 16, color: 'var(--text-secondary)' }}>
            Loading visualizer data...
          </Text>
        </div>
      ) : (
        <Tabs activeKey={activeTab} onChange={setActiveTab} type="card">
          {/* Source IP Tab */}
          <TabPane
            tab={
              <Space>
                <Target size={16} />
                Source IP
                <Badge count={uniqueIPs} style={{ backgroundColor: '#6366f1' }} />
              </Space>
            }
            key="source-ip"
          >
            <Row gutter={[24, 24]}>
              {/* Top IPs Tags */}
              <Col span={24}>
                <Card
                  variant="borderless"
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <Space wrap size={[8, 8]}>
                    {mockSourceIPs.slice(0, 10).map((ip, idx) => (
                      <Tooltip key={ip.ip} title={`${ip.isp} | ${ip.country}`}>
                        <Tag
                          color={COLORS[idx % COLORS.length]}
                          style={{ padding: '4px 12px', fontSize: 13 }}
                        >
                          <Space>
                            <Text style={{ color: 'white', fontWeight: 600 }}>
                              {idx + 1}{getOrdinalSuffix(idx + 1)}
                            </Text>
                            <Text style={{ color: 'white' }}>{ip.ip}</Text>
                            <Text style={{ color: 'rgba(255,255,255,0.7)', fontSize: 11 }}>
                              ×{ip.count}
                            </Text>
                          </Space>
                        </Tag>
                      </Tooltip>
                    ))}
                  </Space>
                </Card>
              </Col>

              {/* Source IP Chart */}
              <Col xs={24} lg={12}>
                <Card
                  variant="borderless"
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                  title={
                    <Space>
                      <BarChart3 size={18} color="#818cf8" />
                      <Text strong style={{ color: 'var(--text-primary)' }}>
                        Source IP Activity Timeline
                      </Text>
                    </Space>
                  }
                >
                  <div style={{ height: 250 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                        <XAxis
                          dataKey="time"
                          type="category"
                          allowDuplicatedCategory={false}
                          stroke="var(--text-tertiary)"
                          fontSize={11}
                          tickLine={false}
                        />
                        <YAxis stroke="var(--text-tertiary)" fontSize={11} tickLine={false} />
                        <RechartsTooltip
                          contentStyle={{
                            background: 'var(--bg-secondary)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 8,
                          }}
                        />
                        {mockSourceIPs.slice(0, 5).map((ip, idx) => (
                          <Line
                            key={ip.ip}
                            data={ip.timeline}
                            type="monotone"
                            dataKey="count"
                            name={ip.ip}
                            stroke={COLORS[idx % COLORS.length]}
                            strokeWidth={2}
                            dot={false}
                          />
                        ))}
                        <Legend />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              </Col>

              {/* Top IPs Bar Chart */}
              <Col xs={24} lg={12}>
                <Card
                  variant="borderless"
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                  title={
                    <Space>
                      <BarChart3 size={18} color="#818cf8" />
                      <Text strong style={{ color: 'var(--text-primary)' }}>
                        Top 10 Source IPs
                      </Text>
                    </Space>
                  }
                >
                  <Text style={{ color: 'var(--text-secondary)', marginBottom: 16, display: 'block' }}>
                    Top 10 out of {uniqueIPs} source IP (total of {totalAlerts} alerts)
                  </Text>
                  <div style={{ height: 300 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={mockSourceIPs.slice(0, 10)}
                        layout="vertical"
                        margin={{ left: 120 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} />
                        <XAxis type="number" stroke="var(--text-tertiary)" fontSize={11} />
                        <YAxis
                          type="category"
                          dataKey="ip"
                          stroke="var(--text-secondary)"
                          fontSize={11}
                          width={110}
                          tickFormatter={(value) => value.slice(0, 15) + '...'}
                        />
                        <RechartsTooltip
                          contentStyle={{
                            background: 'var(--bg-secondary)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 8,
                          }}
                        />
                        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                          {mockSourceIPs.slice(0, 10).map((_, idx) => (
                            <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              </Col>

              {/* Detailed IP List */}
              <Col span={24}>
                <Card
                  variant="borderless"
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                  title={
                    <Space>
                      <Target size={18} color="#818cf8" />
                      <Text strong style={{ color: 'var(--text-primary)' }}>
                        Source IP Details
                      </Text>
                    </Space>
                  }
                >
                  <Space direction="vertical" style={{ width: '100%' }} size={8}>
                    {mockSourceIPs.map((ip, idx) => (
                      <Row
                        key={ip.ip}
                        align="middle"
                        style={{
                          padding: '12px 16px',
                          background: 'var(--bg-tertiary)',
                          borderRadius: 8,
                          borderLeft: `4px solid ${COLORS[idx % COLORS.length]}`,
                        }}
                      >
                        <Col span={6}>
                          <Space>
                            <Text strong style={{ color: COLORS[idx % COLORS.length] }}>
                              {ip.ip}
                            </Text>
                            <Tag color="default" style={{ fontSize: 11 }}>
                              {getFlagEmoji(ip.countryCode)} {ip.country}
                            </Tag>
                          </Space>
                        </Col>
                        <Col span={4}>
                          <Text style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                            {ip.isp}
                          </Text>
                        </Col>
                        <Col span={4}>
                          <Space size={4} wrap>
                            {ip.threatTypes.map((type) => (
                              <Tag key={type} color="warning" style={{ fontSize: 10 }}>
                                {type}
                              </Tag>
                            ))}
                          </Space>
                        </Col>
                        <Col span={4}>
                          <Sparkline data={ip.timeline} color={COLORS[idx % COLORS.length]} />
                        </Col>
                        <Col span={3}>
                          <Text strong style={{ color: 'var(--text-primary)' }}>
                            {ip.count} alerts
                          </Text>
                        </Col>
                        <Col span={3}>
                          <Text style={{ color: 'var(--text-tertiary)' }}>
                            {ip.percentage}%
                          </Text>
                        </Col>
                      </Row>
                    ))}
                  </Space>
                </Card>
              </Col>
            </Row>
          </TabPane>

          {/* Source AS Tab */}
          <TabPane
            tab={
              <Space>
                <Building2 size={16} />
                Source AS
                <Badge count={uniqueAS} style={{ backgroundColor: '#f59e0b' }} />
              </Space>
            }
            key="source-as"
          >
            <Row gutter={[24, 24]}>
              {/* Top AS Tags */}
              <Col span={24}>
                <Card
                  variant="borderless"
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <Space wrap size={[8, 8]}>
                    {mockSourceAS.slice(0, 8).map((as, idx) => (
                      <Tooltip key={as.asn} title={`${as.name} | ${as.country}`}>
                        <Tag
                          color={COLORS[idx % COLORS.length]}
                          style={{ padding: '4px 12px', fontSize: 13 }}
                        >
                          <Space>
                            <Text style={{ color: 'white', fontWeight: 600 }}>
                              {idx + 1}{getOrdinalSuffix(idx + 1)}
                            </Text>
                            <Text style={{ color: 'white' }}>{as.name}</Text>
                            <Text style={{ color: 'rgba(255,255,255,0.7)', fontSize: 11 }}>
                              ×{as.count}
                            </Text>
                          </Space>
                        </Tag>
                      </Tooltip>
                    ))}
                  </Space>
                </Card>
              </Col>

              {/* AS Chart */}
              <Col xs={24} lg={12}>
                <Card
                  variant="borderless"
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                  title={
                    <Space>
                      <BarChart3 size={18} color="#818cf8" />
                      <Text strong style={{ color: 'var(--text-primary)' }}>
                        AS Activity Timeline
                      </Text>
                    </Space>
                  }
                >
                  <div style={{ height: 250 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                        <XAxis
                          dataKey="time"
                          type="category"
                          allowDuplicatedCategory={false}
                          stroke="var(--text-tertiary)"
                          fontSize={11}
                        />
                        <YAxis stroke="var(--text-tertiary)" fontSize={11} />
                        <RechartsTooltip
                          contentStyle={{
                            background: 'var(--bg-secondary)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 8,
                          }}
                        />
                        {mockSourceAS.slice(0, 5).map((as, idx) => (
                          <Line
                            key={as.asn}
                            data={as.timeline}
                            type="monotone"
                            dataKey="count"
                            name={as.name}
                            stroke={COLORS[idx % COLORS.length]}
                            strokeWidth={2}
                            dot={false}
                          />
                        ))}
                        <Legend />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              </Col>

              {/* Top AS Bar Chart */}
              <Col xs={24} lg={12}>
                <Card
                  variant="borderless"
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                  title={
                    <Space>
                      <BarChart3 size={18} color="#818cf8" />
                      <Text strong style={{ color: 'var(--text-primary)' }}>
                        Top Autonomous Systems
                      </Text>
                    </Space>
                  }
                >
                  <Text style={{ color: 'var(--text-secondary)', marginBottom: 16, display: 'block' }}>
                    Top {mockSourceAS.length} out of {uniqueAS} source AS (total of {totalAlerts} alerts)
                  </Text>
                  <div style={{ height: 300 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={mockSourceAS}
                        layout="vertical"
                        margin={{ left: 150 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} />
                        <XAxis type="number" stroke="var(--text-tertiary)" fontSize={11} />
                        <YAxis
                          type="category"
                          dataKey="name"
                          stroke="var(--text-secondary)"
                          fontSize={10}
                          width={140}
                          tickFormatter={(value) => value.length > 20 ? value.slice(0, 20) + '...' : value}
                        />
                        <RechartsTooltip
                          contentStyle={{
                            background: 'var(--bg-secondary)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 8,
                          }}
                        />
                        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                          {mockSourceAS.map((_, idx) => (
                            <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              </Col>

              {/* Detailed AS List */}
              <Col span={24}>
                <Card
                  variant="borderless"
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                  title={
                    <Space>
                      <Building2 size={18} color="#818cf8" />
                      <Text strong style={{ color: 'var(--text-primary)' }}>
                        Autonomous System Details
                      </Text>
                    </Space>
                  }
                >
                  <Space direction="vertical" style={{ width: '100%' }} size={8}>
                    {mockSourceAS.map((as, idx) => (
                      <Row
                        key={as.asn}
                        align="middle"
                        style={{
                          padding: '12px 16px',
                          background: 'var(--bg-tertiary)',
                          borderRadius: 8,
                          borderLeft: `4px solid ${COLORS[idx % COLORS.length]}`,
                        }}
                      >
                        <Col span={5}>
                          <Space direction="vertical" size={0}>
                            <Text strong style={{ color: COLORS[idx % COLORS.length] }}>
                              {as.name}
                            </Text>
                            <Text style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>
                              {as.asn}
                            </Text>
                          </Space>
                        </Col>
                        <Col span={3}>
                          <Tag color="default" style={{ fontSize: 11 }}>
                            {getFlagEmoji(as.countryCode)} {as.country}
                          </Tag>
                        </Col>
                        <Col span={6}>
                          <Space size={4} wrap>
                            <Text style={{ color: 'var(--text-secondary)', fontSize: 11 }}>
                              Top IPs:
                            </Text>
                            {as.topIPs.slice(0, 2).map((ip) => (
                              <Tag key={ip} style={{ fontSize: 10 }}>
                                {ip}
                              </Tag>
                            ))}
                          </Space>
                        </Col>
                        <Col span={4}>
                          <Sparkline data={as.timeline} color={COLORS[idx % COLORS.length]} />
                        </Col>
                        <Col span={3}>
                          <Text strong style={{ color: 'var(--text-primary)' }}>
                            {as.count} alerts
                          </Text>
                        </Col>
                        <Col span={3}>
                          <Text style={{ color: 'var(--text-tertiary)' }}>
                            {as.percentage}%
                          </Text>
                        </Col>
                      </Row>
                    ))}
                  </Space>
                </Card>
              </Col>
            </Row>
          </TabPane>

          {/* Countries Tab */}
          <TabPane
            tab={
              <Space>
                <Globe size={16} />
                Countries
                <Badge count={uniqueCountries} style={{ backgroundColor: '#10b981' }} />
              </Space>
            }
            key="countries"
          >
            <Empty
              description="Country analysis coming soon"
              image={Empty.PRESENTED_IMAGE_SIMPLE}
            />
          </TabPane>

          {/* Scenarios Tab */}
          <TabPane
            tab={
              <Space>
                <Shield size={16} />
                Scenarios
                <Badge count={5} style={{ backgroundColor: '#ef4444' }} />
              </Space>
            }
            key="scenarios"
          >
            <Empty
              description="Scenario analysis coming soon"
              image={Empty.PRESENTED_IMAGE_SIMPLE}
            />
          </TabPane>
        </Tabs>
      )}
    </div>
  );
}

// Helper function for ordinal suffixes
function getOrdinalSuffix(n: number): string {
  const s = ['th', 'st', 'nd', 'rd'];
  const v = n % 100;
  return s[(v - 20) % 10] || s[v] || s[0];
}
