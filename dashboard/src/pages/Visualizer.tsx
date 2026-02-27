import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import {
  Card,
  Typography,
  Row,
  Col,
  Badge,
  Space,
  Tabs,
  Tag,
  Tooltip,
  Select,
  Radio,
  Empty,
  Spin,
} from 'antd';
import {
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
  useTopSourceIPs,
  useTopASNs,
} from '../hooks/useQueries';
import { CountryFlag, normalizeCountryCode } from '../components/CountryFlag';

// Text sanitization helper
const sanitizeText = (value: string) =>
  value
    .normalize('NFC')
    .replace(/\uFFFD/g, '')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim();

const { Title, Text } = Typography;
const { TabPane } = Tabs;

// Data interfaces for visualizer
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

type RegionDisplayNames = {
  of: (code: string) => string | undefined;
};

type DisplayNamesCtor = new (
  locales?: string | string[],
  options?: { type: 'region' }
) => RegionDisplayNames;

const regionDisplayNamesCtor = (Intl as unknown as { DisplayNames?: DisplayNamesCtor }).DisplayNames;
const regionDisplayNames = regionDisplayNamesCtor
  ? new regionDisplayNamesCtor(['en'], { type: 'region' })
  : null;



export default function Visualizer() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('source-ip');
  const [timeRange, setTimeRange] = useState('24h');
  const [visibility, setVisibility] = useState('expanded');
  const { isLoading: threatsLoading } = useThreats();

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
  const sourceIPsData = (topSourceIPs || []).map((ip: any) => ({
    ip: ip.ip,
    count: ip.count || 0,
    percentage: 0, // Will be calculated
    country: sanitizeText(ip.country || 'Unknown'),
    countryCode: normalizeCountryCode(ip.country_code || '') || normalizeCountryCode(ip.country || ''),
    asn: 'N/A',
    isp: ip.isp || 'Unknown',
    firstSeen: ip.first_seen,
    lastSeen: ip.last_seen,
    timeline: [], // TODO: Add timeline API endpoint
    threatTypes: [], // TODO: Add threat type breakdown from API
  }));

  // Calculate percentages
  const totalCount = sourceIPsData.reduce((sum: number, ip: any) => sum + ip.count, 0);
  sourceIPsData.forEach((ip: any) => {
    ip.percentage = totalCount > 0 ? parseFloat(((ip.count / totalCount) * 100).toFixed(1)) : 0;
  });

  const sourceASData = (topASNs || []).map((as: any) => ({
    asn: as.asn || 'Unknown',
    name: as.isp_name || as.asn || 'Unknown',
    country: sanitizeText(as.country || 'Unknown'),
    countryCode: normalizeCountryCode(as.country_code || '') || normalizeCountryCode(as.country || ''),
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

  // Source data from API
  const sourceIPs = sourceIPsData.length > 0 ? sourceIPsData : [];
  const sourceAS = sourceASData.length > 0 ? sourceASData : [];

  return (
    <div style={{ padding: '24px 48px', maxWidth: 1600, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
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
                    {sourceIPs.slice(0, 10).map((ip: SourceIP, idx: number) => (
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
                        {sourceIPs.slice(0, 5).map((ip: SourceIP, idx: number) => (
                          <Line
                          key={ip.ip}
                          data={ip.timeline as { time: string; count: number }[]}
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
                    Top {Math.min(10, sourceIPs.length)} out of {uniqueIPs} source IPs (total of {totalAlerts} alerts)
                  </Text>
                  <div style={{ height: 300 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={sourceIPs.slice(0, 10)}
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
                            {sourceIPs.slice(0, 10).map((_: SourceIP, idx: number) => (
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
                    {sourceIPs.map((ip: SourceIP, idx: number) => (
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
                              <CountryFlag countryCode={ip.countryCode} size={14} /> {ip.country}
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
                            {ip.threatTypes.map((type: string) => (
                              <Tag key={type} color="warning" style={{ fontSize: 10 }}>
                                {type}
                              </Tag>
                            ))}
                          </Space>
                        </Col>
                        <Col span={4}>
                          <Sparkline data={ip.timeline as { time: string; count: number }[]} color={COLORS[idx % COLORS.length]} />
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
                    {sourceAS.slice(0, 8).map((as: SourceAS, idx: number) => (
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
                        {sourceAS.slice(0, 5).map((as: SourceAS, idx: number) => (
                          <Line
                          key={as.asn}
                          data={as.timeline as { time: string; count: number }[]}
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
                    Top {sourceAS.length} out of {uniqueAS} source AS (total of {totalAlerts} alerts)
                  </Text>
                  <div style={{ height: 300 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={sourceAS}
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
                            {sourceAS.map((_: SourceAS, idx: number) => (
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
                    {sourceAS.map((as: SourceAS, idx: number) => (
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
                        <CountryFlag countryCode={as.countryCode} size={14} /> {as.country}
                        </Tag>
                      </Col>
                      <Col span={6}>
                        <Space size={4} wrap>
                        <Text style={{ color: 'var(--text-secondary)', fontSize: 11 }}>
                          Top IPs:
                        </Text>
                        {as.topIPs.slice(0, 2).map((ip: string) => (
                          <Tag key={ip} style={{ fontSize: 10 }}>
                          {ip}
                          </Tag>
                        ))}
                        </Space>
                      </Col>
                      <Col span={4}>
                        <Sparkline data={as.timeline as { time: string; count: number }[]} color={COLORS[idx % COLORS.length]} />
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
