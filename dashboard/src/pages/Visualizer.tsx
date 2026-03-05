import { useMemo, useState, useEffect, useRef } from 'react';
import { useQueries } from '@tanstack/react-query';
import type { ColumnsType } from 'antd/es/table';
import {
  Alert,
  Badge,
  Card,
  Col,
  Empty,
  Progress,
  Row,
  Segmented,
  Space,
  Spin,
  Statistic,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  List,
  Avatar,
} from 'antd';
import {
  AimOutlined,
  ApartmentOutlined,
  BarChartOutlined,
  GlobalOutlined,
  RadarChartOutlined,
  SafetyOutlined,
  WarningOutlined,
  LineChartOutlined,
  EnvironmentOutlined,
} from '@ant-design/icons';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  PieChart,
  Pie,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { analyticsAPI } from '../api/client';
import { useTopASNs, useTopSourceIPs, useServers } from '../hooks/useQueries';
import { CountryFlag, normalizeCountryCode } from '../components/CountryFlag';

const { Title, Text } = Typography;

const sanitizeText = (value: string) =>
  value
    .normalize('NFC')
    .replace(/\uFFFD/g, '')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim();

const cleanIP = (ip: string): string => {
  if (!ip) return '';
  return ip.replace(/\/\d+$/, '');
};

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

interface CountryData {
  [key: string]: string | number | undefined;
  country: string;
  countryCode: string;
  count: number;
  percentage: number;
  fill?: string;
}

type TimelineDataPoint = { time: string; count: number };
type TimelineChartPoint = Record<string, string | number>;

const COLORS = ['#1677ff', '#52c41a', '#faad14', '#f5222d', '#722ed1', '#13c2c2', '#eb2f96', '#fa541c'];

function useAnimatedCounter(end: number, duration: number = 1000) {
  const [count, setCount] = useState(0);
  const countRef = useRef(0);
  const startTimeRef = useRef<number | null>(null);

  useEffect(() => {
    const animate = (timestamp: number) => {
      if (!startTimeRef.current) startTimeRef.current = timestamp;
      const progress = Math.min((timestamp - startTimeRef.current) / duration, 1);
      const easeOut = 1 - Math.pow(1 - progress, 3);
      countRef.current = Math.floor(easeOut * end);
      setCount(countRef.current);
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    startTimeRef.current = null;
    requestAnimationFrame(animate);
  }, [end, duration]);

  return count;
}

function getDateRange(timeRange: string) {
  const end = new Date();
  const start = new Date();
  switch (timeRange) {
    case '1h':
      start.setHours(end.getHours() - 1);
      break;
    case '6h':
      start.setHours(end.getHours() - 6);
      break;
    case '24h':
      start.setDate(end.getDate() - 1);
      break;
    case '7d':
      start.setDate(end.getDate() - 7);
      break;
    case '30d':
      start.setDate(end.getDate() - 30);
      break;
    default:
      start.setDate(end.getDate() - 1);
  }
  return {
    startDate: start.toISOString().split('T')[0],
    endDate: end.toISOString().split('T')[0],
  };
}

function extractTimelineBucket(raw: unknown): string | null {
  if (typeof raw === 'string') {
    return raw;
  }
  if (!raw || typeof raw !== 'object') {
    return null;
  }

  const obj = raw as Record<string, unknown>;
  const possibleString =
    obj.time ??
    obj.Time ??
    obj.time_bucket ??
    obj.TimeBucket;

  return typeof possibleString === 'string' ? possibleString : null;
}

function normalizeTimelineData(rows: unknown[] | undefined): TimelineDataPoint[] {
  if (!Array.isArray(rows)) {
    return [];
  }

  return rows
    .map((row) => {
      if (!row || typeof row !== 'object') {
        return null;
      }

      const rowObj = row as Record<string, unknown>;
      const rawBucket = rowObj.time_bucket ?? rowObj.timeBucket ?? rowObj.time;
      const bucket = extractTimelineBucket(rawBucket);
      if (!bucket) {
        return null;
      }

      const count = Number(rowObj.count ?? rowObj.Count ?? 0);
      return {
        time: bucket,
        count: Number.isFinite(count) ? count : 0,
      };
    })
    .filter((value): value is TimelineDataPoint => value !== null)
    .sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime());
}

function formatTimelineLabel(time: string, timeRange: string): string {
  const parsed = new Date(time);
  if (Number.isNaN(parsed.getTime())) {
    return time;
  }

  if (timeRange === '1h' || timeRange === '6h' || timeRange === '24h') {
    return parsed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  return parsed.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function Visualizer() {
  const [activeTab, setActiveTab] = useState('source-ip');
  const [timeRange, setTimeRange] = useState('24h');
  const [visibility, setVisibility] = useState<'none' | 'summary' | 'expanded'>('expanded');
  const [activePieIndex, setActivePieIndex] = useState(0);

  const { startDate, endDate } = useMemo(() => getDateRange(timeRange), [timeRange]);

  const { data: topSourceIPs, isLoading: ipsLoading } = useTopSourceIPs(startDate, endDate, 20);
  const { data: topASNs, isLoading: asnsLoading } = useTopASNs(startDate, endDate, 10);
  const { data: servers } = useServers();

  const isLoading = ipsLoading || asnsLoading;

  const serverLocation = useMemo(() => {
    const activeServer = servers?.find(s => s.status === 'active') ?? servers?.[0];
    if (!activeServer) return undefined;

    if (activeServer.latitude && activeServer.longitude) {
      return {
        lat: activeServer.latitude,
        lng: activeServer.longitude,
        city: activeServer.city || activeServer.hostname,
        country: activeServer.country_code || activeServer.country_name || '',
      };
    }

    if (activeServer.metadata) {
      try {
        const metadata = JSON.parse(activeServer.metadata);
        if (metadata.location?.lat && metadata.location?.lng) {
          return {
            lat: metadata.location.lat,
            lng: metadata.location.lng,
            city: metadata.location.city || activeServer.hostname,
            country: metadata.location.country || '',
          };
        }
      } catch {
        // Fall through
      }
    }

    return undefined;
  }, [servers]);

  const sourceIPsData: SourceIP[] = (topSourceIPs || []).map((ip: any) => ({
    ip: cleanIP(ip.ip),
    count: ip.count || 0,
    percentage: 0,
    country: sanitizeText(ip.country || 'Unknown'),
    countryCode: normalizeCountryCode(ip.country_code || '') || normalizeCountryCode(ip.country || ''),
    asn: 'N/A',
    isp: ip.isp || 'Unknown',
    firstSeen: ip.first_seen,
    lastSeen: ip.last_seen,
    timeline: [],
    threatTypes: [],
  }));

  const totalCount = sourceIPsData.reduce((sum: number, ip: any) => sum + ip.count, 0);
  sourceIPsData.forEach((ip) => {
    ip.percentage = totalCount > 0 ? parseFloat(((ip.count / totalCount) * 100).toFixed(1)) : 0;
  });

  const sourceASData: SourceAS[] = (topASNs || []).map((as: any) => ({
    asn: as.asn || 'Unknown',
    name: as.isp_name || as.asn || 'Unknown',
    country: sanitizeText(as.country || 'Unknown'),
    countryCode: normalizeCountryCode(as.country_code || '') || normalizeCountryCode(as.country || ''),
    count: as.count || 0,
    percentage: 0,
    timeline: [],
    topIPs: [],
  }));

  const totalASCount = sourceASData.reduce((sum: number, as: any) => sum + as.count, 0);
  sourceASData.forEach((as) => {
    as.percentage = totalASCount > 0 ? parseFloat(((as.count / totalASCount) * 100).toFixed(1)) : 0;
  });

  const countryData: CountryData[] = useMemo(() => {
    const countryMap = new Map<string, { count: number; code: string }>();
    sourceIPsData.forEach((ip) => {
      const existing = countryMap.get(ip.country);
      if (existing) {
        existing.count += ip.count;
      } else {
        countryMap.set(ip.country, { count: ip.count, code: ip.countryCode });
      }
    });
    
    const sorted = Array.from(countryMap.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 5);
    
    const total = sorted.reduce((sum, [, data]) => sum + data.count, 0);
    
    return sorted.map(([country, data], i) => ({
      country: country === 'Unknown' ? 'Unknown' : country,
      countryCode: data.code,
      count: data.count,
      percentage: total > 0 ? parseFloat(((data.count / total) * 100).toFixed(1)) : 0,
      fill: COLORS[i % COLORS.length],
    }));
  }, [sourceIPsData]);

  const visibleTimelineCount = visibility === 'none' ? 0 : visibility === 'summary' ? 3 : 5;

  const totalAlerts = sourceIPsData.reduce((sum: number, ip) => sum + ip.count, 0);
  const uniqueIPs = sourceIPsData.length;
  const uniqueAS = sourceASData.length;
  const uniqueCountries = new Set(sourceIPsData.map((ip) => ip.country)).size;

  const sourceIPs = sourceIPsData;
  const sourceAS = sourceASData;
  const topTimelineIPs = sourceIPs.slice(0, visibleTimelineCount).map((ip) => cleanIP(ip.ip));
  const sourceIPTableData = visibility === 'expanded' ? sourceIPs : sourceIPs.slice(0, 10);
  const sourceASTableData = visibility === 'expanded' ? sourceAS : sourceAS.slice(0, 10);

  const sourceTimelineQueries = useQueries({
    queries: topTimelineIPs.map((ip) => ({
      queryKey: ['analytics', 'ip-timeline', ip, startDate, endDate],
      queryFn: async () => {
        const { data } = await analyticsAPI.getSourceIPTimeline(ip, startDate, endDate);
        return Array.isArray(data?.data) ? data.data : [];
      },
      enabled: !!ip,
      staleTime: 60_000,
    })),
  });

  const timelineVersion = sourceTimelineQueries.map((query) => query.dataUpdatedAt).join('|');
  const sourceTimelineData = useMemo((): TimelineChartPoint[] => {
    const byBucket = new Map<string, TimelineChartPoint>();

    topTimelineIPs.forEach((ip, idx) => {
      const rows = normalizeTimelineData(sourceTimelineQueries[idx]?.data as unknown[] | undefined);
      rows.forEach((row) => {
        const existing = byBucket.get(row.time) ?? { time: row.time };
        existing[ip] = row.count;
        byBucket.set(row.time, existing);
      });
    });

    const filled = Array.from(byBucket.values())
      .sort((a, b) => new Date(String(a.time)).getTime() - new Date(String(b.time)).getTime())
      .map((row) => {
        const complete: TimelineChartPoint = { time: String(row.time) };
        topTimelineIPs.forEach((ip) => {
          complete[ip] = Number(row[ip] ?? 0);
        });
        return complete;
      });

    return filled;
  }, [topTimelineIPs, timelineVersion]);

  const timelineLoading = sourceTimelineQueries.some((query) => query.isLoading);

  const sourceIPColumns: ColumnsType<SourceIP> = [
    {
      title: 'Rank',
      key: 'rank',
      width: 70,
      align: 'center',
      render: (_, __, idx: number) => (
        <Avatar
          size="small"
          style={{
            backgroundColor: COLORS[idx % COLORS.length] + '20',
            color: COLORS[idx % COLORS.length],
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          {idx + 1}
        </Avatar>
      ),
    },
    {
      title: 'IP Address',
      dataIndex: 'ip',
      key: 'ip',
      render: (ip: string, record: SourceIP) => (
        <Space>
          <Text strong copyable={{ text: ip }} style={{ fontFamily: 'monospace' }}>
            {ip}
          </Text>
          <Tooltip title={record.country}>
            <CountryFlag countryCode={record.countryCode} size={16} />
          </Tooltip>
        </Space>
      ),
    },
    {
      title: 'Provider / ASN',
      dataIndex: 'isp',
      key: 'isp',
      render: (isp: string) => <Text type="secondary">{isp}</Text>,
    },
    {
      title: 'Alerts',
      dataIndex: 'count',
      key: 'count',
      width: 100,
      sorter: (a, b) => a.count - b.count,
      render: (count: number) => (
        <Badge
          count={count}
          style={{
            backgroundColor: count > 100 ? '#f5222d' : '#faad14',
          }}
          overflowCount={9999}
        />
      ),
    },
    {
      title: 'Share',
      dataIndex: 'percentage',
      key: 'percentage',
      width: 180,
      render: (percentage: number) => (
        <Space>
          <Progress
            percent={percentage}
            showInfo={false}
            size="small"
            style={{ width: 80 }}
            strokeColor={percentage > 20 ? '#f5222d' : percentage > 10 ? '#faad14' : '#1677ff'}
          />
          <Text type="secondary" style={{ fontSize: 12, minWidth: 40 }}>
            {percentage}%
          </Text>
        </Space>
      ),
    },
  ];

  const sourceASColumns: ColumnsType<SourceAS> = [
    {
      title: 'Rank',
      key: 'rank',
      width: 70,
      align: 'center',
      render: (_, __, idx: number) => (
        <Avatar
          size="small"
          style={{
            backgroundColor: COLORS[idx % COLORS.length] + '20',
            color: COLORS[idx % COLORS.length],
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          {idx + 1}
        </Avatar>
      ),
    },
    {
      title: 'ASN',
      dataIndex: 'asn',
      key: 'asn',
      render: (asn: string, record: SourceAS) => (
        <Space direction="vertical" size={0}>
          <Text strong>{asn}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {record.name}
          </Text>
        </Space>
      ),
    },
    {
      title: 'Country',
      dataIndex: 'country',
      key: 'country',
      render: (_: string, record: SourceAS) => (
        <Space>
          <CountryFlag countryCode={record.countryCode} size={16} />
          <Text type="secondary">{record.country}</Text>
        </Space>
      ),
    },
    {
      title: 'Alerts',
      dataIndex: 'count',
      key: 'count',
      width: 100,
      sorter: (a, b) => a.count - b.count,
      render: (count: number) => <Text strong>{count.toLocaleString()}</Text>,
    },
    {
      title: 'Share',
      dataIndex: 'percentage',
      key: 'percentage',
      width: 180,
      render: (percentage: number) => (
        <Space>
          <Progress
            percent={percentage}
            showInfo={false}
            size="small"
            style={{ width: 80 }}
            strokeColor="#faad14"
          />
          <Text type="secondary" style={{ fontSize: 12 }}>
            {percentage}%
          </Text>
        </Space>
      ),
    },
  ];

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <Card size="small" style={{ boxShadow: '0 4px 12px rgba(0,0,0,0.15)' }}>
          <Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>
            {formatTimelineLabel(label, timeRange)}
          </Text>
          <Space direction="vertical" size={4}>
            {payload.map((entry: any, index: number) => (
              <Space key={index}>
                <div
                  style={{
                    width: 8,
                    height: 8,
                    backgroundColor: entry.color,
                    borderRadius: 2,
                  }}
                />
                <Text style={{ fontSize: 12 }}>
                  {cleanIP(entry.name)}: <strong>{entry.value}</strong>
                </Text>
              </Space>
            ))}
          </Space>
        </Card>
      );
    }
    return null;
  };

  const totalThreatsValue = useAnimatedCounter(totalAlerts);
  const uniqueIPsValue = useAnimatedCounter(uniqueIPs);
  const uniqueASValue = useAnimatedCounter(uniqueAS);
  const uniqueCountriesValue = useAnimatedCounter(uniqueCountries);

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Row justify="space-between" align="middle" gutter={[16, 16]}>
        <Col>
          <Space align="center">
            <Avatar
              size="large"
              icon={<RadarChartOutlined />}
              style={{ background: 'linear-gradient(135deg, #1677ff 0%, #722ed1 100%)' }}
            />
            <Space direction="vertical" size={0}>
              <Title level={4} style={{ margin: 0 }}>
                Threat Visualizer
              </Title>
              <Text type="secondary" style={{ fontSize: 13 }}>
                Attack source analysis and threat intelligence
              </Text>
            </Space>
          </Space>
        </Col>
        <Col>
          <Space>
            <Segmented
              value={timeRange}
              onChange={(value) => setTimeRange(value as string)}
              options={[
                { label: '1H', value: '1h' },
                { label: '6H', value: '6h' },
                { label: '24H', value: '24h' },
                { label: '7D', value: '7d' },
                { label: '30D', value: '30d' },
              ]}
            />
            <Segmented
              value={visibility}
              onChange={(value) => setVisibility(value as 'none' | 'summary' | 'expanded')}
              options={[
                { label: 'Compact', value: 'none' },
                { label: 'Summary', value: 'summary' },
                { label: 'Expanded', value: 'expanded' },
              ]}
            />
          </Space>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Total Threats"
              value={totalThreatsValue}
              prefix={<SafetyOutlined style={{ color: '#1677ff' }} />}
              valueStyle={{ color: '#1677ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Unique Source IPs"
              value={uniqueIPsValue}
              prefix={<AimOutlined style={{ color: '#f5222d' }} />}
              valueStyle={{ color: '#f5222d' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Autonomous Systems"
              value={uniqueASValue}
              prefix={<ApartmentOutlined style={{ color: '#faad14' }} />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Countries"
              value={uniqueCountriesValue}
              prefix={<GlobalOutlined style={{ color: '#52c41a' }} />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
      </Row>

      {isLoading ? (
        <Card>
          <div style={{ textAlign: 'center', padding: 60 }}>
            <Spin size="large" />
            <Text type="secondary" style={{ display: 'block', marginTop: 16 }}>
              Analyzing threat data...
            </Text>
          </div>
        </Card>
      ) : (
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          type="card"
          items={[
            {
              key: 'source-ip',
              label: (
                <Space>
                  <AimOutlined />
                  Source IP
                  <Badge count={uniqueIPs} style={{ backgroundColor: '#1677ff' }} />
                </Space>
              ),
              children: (
                <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                  <Row gutter={[16, 16]}>
                    <Col xs={24} lg={12}>
                      <Card
                        title={
                          <Space>
                            <LineChartOutlined style={{ color: '#1677ff' }} />
                            <span>Attack Timeline</span>
                          </Space>
                        }
                      >
                        {topTimelineIPs.length === 0 ? (
                          <Empty
                            image={Empty.PRESENTED_IMAGE_SIMPLE}
                            description="Timeline hidden in compact mode"
                          />
                        ) : timelineLoading ? (
                          <div style={{ textAlign: 'center', padding: 48 }}>
                            <Spin />
                          </div>
                        ) : sourceTimelineData.length === 0 ? (
                          <Empty
                            image={Empty.PRESENTED_IMAGE_SIMPLE}
                            description="No timeline data for selected IPs"
                          />
                        ) : (
                          <div style={{ height: 280 }}>
                            <ResponsiveContainer width="100%" height="100%">
                              <AreaChart
                                data={sourceTimelineData}
                                margin={{ top: 12, right: 12, left: 0, bottom: 0 }}
                              >
                                <defs>
                                  {topTimelineIPs.map((ip, i) => (
                                    <linearGradient
                                      key={ip}
                                      id={`gradient${i}`}
                                      x1="0"
                                      y1="0"
                                      x2="0"
                                      y2="1"
                                    >
                                      <stop
                                        offset="5%"
                                        stopColor={COLORS[i % COLORS.length]}
                                        stopOpacity={0.3}
                                      />
                                      <stop
                                        offset="95%"
                                        stopColor={COLORS[i % COLORS.length]}
                                        stopOpacity={0}
                                      />
                                    </linearGradient>
                                  ))}
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                                <XAxis
                                  dataKey="time"
                                  tickFormatter={(value) =>
                                    formatTimelineLabel(String(value), timeRange)
                                  }
                                  minTickGap={30}
                                  stroke="#d9d9d9"
                                  fontSize={11}
                                />
                                <YAxis allowDecimals={false} stroke="#d9d9d9" fontSize={11} />
                                <RechartsTooltip content={<CustomTooltip />} />
                                {topTimelineIPs.map((ip, idx) => (
                                  <Area
                                    key={ip}
                                    type="stepAfter"
                                    dataKey={ip}
                                    name={ip}
                                    stroke={COLORS[idx % COLORS.length]}
                                    strokeWidth={2}
                                    fill={`url(#gradient${idx})`}
                                    dot={false}
                                    connectNulls
                                  />
                                ))}
                                <Legend formatter={(value: string) => cleanIP(value)} />
                              </AreaChart>
                            </ResponsiveContainer>
                          </div>
                        )}
                      </Card>
                    </Col>

                    <Col xs={24} lg={12}>
                      <Card
                        title={
                          <Space>
                            <GlobalOutlined style={{ color: '#faad14' }} />
                            <span>Attack Distribution by Country</span>
                          </Space>
                        }
                      >
                        {countryData.length === 0 ? (
                          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No geographic data" />
                        ) : (
                          <Row gutter={[16, 16]} align="middle">
                            <Col xs={24} sm={12}>
                              <div style={{ height: 200 }}>
                                <ResponsiveContainer width="100%" height="100%">
                                  <PieChart>
                                    <Pie
                                      data={countryData}
                                      cx="50%"
                                      cy="50%"
                                      innerRadius={50}
                                      outerRadius={80}
                                      paddingAngle={2}
                                      dataKey="count"
                                      onMouseEnter={(_, index) => setActivePieIndex(index)}
                                      onMouseLeave={() => setActivePieIndex(0)}
                                    >
                                      {countryData.map((_, index) => (
                                        <Cell
                                          key={`cell-${index}`}
                                          fill={COLORS[index % COLORS.length]}
                                          stroke="#fff"
                                          strokeWidth={index === activePieIndex ? 3 : 1}
                                        />
                                      ))}
                                    </Pie>
                                    <RechartsTooltip
                                      formatter={(value, _, props) => [
                                        `${value as number} alerts (${(props?.payload as any)?.percentage}%)`,
                                        (props?.payload as any)?.country as string,
                                      ]}
                                    />
                                  </PieChart>
                                </ResponsiveContainer>
                              </div>
                            </Col>
                            <Col xs={24} sm={12}>
                              <List
                                size="small"
                                dataSource={countryData}
                                renderItem={(entry, index) => (
                                  <List.Item
                                    style={{
                                      cursor: 'pointer',
                                      backgroundColor:
                                        index === activePieIndex
                                          ? COLORS[index % COLORS.length] + '10'
                                          : 'transparent',
                                      borderRadius: 4,
                                      padding: '4px 8px',
                                    }}
                                    onMouseEnter={() => setActivePieIndex(index)}
                                    onMouseLeave={() => setActivePieIndex(0)}
                                  >
                                    <Space>
                                      <div
                                        style={{
                                          width: 10,
                                          height: 10,
                                          borderRadius: 2,
                                          backgroundColor: COLORS[index % COLORS.length],
                                        }}
                                      />
                                      <CountryFlag countryCode={entry.countryCode as string} size={14} />
                                      <Text style={{ maxWidth: 120 }} ellipsis>
                                        {entry.country as string}
                                      </Text>
                                    </Space>
                                    <Text type="secondary">{entry.percentage}%</Text>
                                  </List.Item>
                                )}
                              />
                            </Col>
                          </Row>
                        )}
                      </Card>
                    </Col>
                  </Row>

                  <Row gutter={[16, 16]}>
                    <Col span={24}>
                      <Card
                        title={
                          <Space>
                            <WarningOutlined style={{ color: '#f5222d' }} />
                            <span>Threat Source Overview</span>
                          </Space>
                        }
                      >
                        {sourceIPs.length === 0 ? (
                          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No source IP data" />
                        ) : (
                          <Space wrap size={[8, 8]}>
                            {sourceIPs.slice(0, 20).map((ip, idx) => (
                              <Tooltip
                                key={ip.ip}
                                title={`${ip.isp} | ${ip.country} | ${ip.count} alerts`}
                              >
                                <Tag
                                  color={COLORS[idx % COLORS.length]}
                                  style={{ padding: '4px 12px', fontSize: 13 }}
                                >
                                  <Space size={4}>
                                    <CountryFlag countryCode={ip.countryCode} size={14} />
                                    <span style={{ fontFamily: 'monospace' }}>{ip.ip}</span>
                                    <Badge
                                      count={ip.count}
                                      style={{
                                        backgroundColor: 'rgba(0,0,0,0.2)',
                                        fontSize: 10,
                                        color: '#fff',
                                      }}
                                    />
                                  </Space>
                                </Tag>
                              </Tooltip>
                            ))}
                          </Space>
                        )}
                      </Card>
                    </Col>
                  </Row>

                  <Card
                    title={
                      <Space>
                        <AimOutlined style={{ color: '#1677ff' }} />
                        <span>Source IP Details</span>
                      </Space>
                    }
                    extra={
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        Showing {sourceIPTableData.length} of {uniqueIPs} sources
                      </Text>
                    }
                  >
                    <Table
                      rowKey="ip"
                      columns={sourceIPColumns}
                      dataSource={sourceIPTableData}
                      pagination={visibility === 'expanded' ? { pageSize: 10 } : false}
                      size="small"
                    />
                  </Card>
                </Space>
              ),
            },
            {
              key: 'source-as',
              label: (
                <Space>
                  <ApartmentOutlined />
                  Source AS
                  <Badge count={uniqueAS} style={{ backgroundColor: '#faad14' }} />
                </Space>
              ),
              children: (
                <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                  <Card
                    title={
                      <Space>
                        <EnvironmentOutlined style={{ color: '#722ed1' }} />
                        <span>Top Autonomous Systems</span>
                      </Space>
                    }
                  >
                    {sourceAS.length === 0 ? (
                      <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No ASN data" />
                    ) : (
                      <Space wrap size={[8, 8]}>
                        {sourceAS.slice(0, 15).map((as, idx) => (
                          <Tooltip key={as.asn} title={`${as.name} | ${as.country} | ${as.count} alerts`}>
                            <Tag
                              color={COLORS[idx % COLORS.length]}
                              style={{ padding: '4px 12px', fontSize: 13 }}
                            >
                              <Space size={4}>
                                <span>{as.name}</span>
                                <Badge
                                  count={as.count}
                                  style={{
                                    backgroundColor: 'rgba(0,0,0,0.2)',
                                    fontSize: 10,
                                    color: '#fff',
                                  }}
                                />
                              </Space>
                            </Tag>
                          </Tooltip>
                        ))}
                      </Space>
                    )}
                  </Card>

                  <Row gutter={[16, 16]}>
                    <Col xs={24} lg={12}>
                      <Card
                        title={
                          <Space>
                            <BarChartOutlined style={{ color: '#faad14' }} />
                            <span>AS Distribution</span>
                          </Space>
                        }
                      >
                        <Text type="secondary" style={{ marginBottom: 16, display: 'block', fontSize: 12 }}>
                          Top {sourceAS.length} out of {uniqueAS} ASNs ({totalAlerts.toLocaleString()} total alerts)
                        </Text>
                        {sourceAS.length === 0 ? (
                          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No ASN chart data" />
                        ) : (
                          <div style={{ height: 320 }}>
                            <ResponsiveContainer width="100%" height="100%">
                              <BarChart data={sourceAS} layout="vertical" margin={{ left: 140 }}>
                                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f0f0f0" />
                                <XAxis type="number" stroke="#d9d9d9" fontSize={11} />
                                <YAxis
                                  type="category"
                                  dataKey="name"
                                  width={128}
                                  tickFormatter={(value: string) =>
                                    value.length > 18 ? `${value.slice(0, 18)}...` : value
                                  }
                                  stroke="#d9d9d9"
                                  fontSize={11}
                                />
                                <RechartsTooltip />
                                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                                  {sourceAS.map((_, idx) => (
                                    <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                                  ))}
                                </Bar>
                              </BarChart>
                            </ResponsiveContainer>
                          </div>
                        )}
                      </Card>
                    </Col>

                    <Col xs={24} lg={12}>
                      <Alert
                        type="info"
                        showIcon
                        icon={<BarChartOutlined />}
                        message="ASN Timeline Analysis"
                        description="Source IP timeline is now live. ASN timeline tracking will be available in a future update with dedicated backend endpoints for AS-level traffic analysis."
                      />
                    </Col>
                  </Row>

                  <Card
                    title={
                      <Space>
                        <ApartmentOutlined style={{ color: '#faad14' }} />
                        <span>Autonomous System Details</span>
                      </Space>
                    }
                    extra={
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        Showing {sourceASTableData.length} of {uniqueAS} systems
                      </Text>
                    }
                  >
                    <Table
                      rowKey="asn"
                      columns={sourceASColumns}
                      dataSource={sourceASTableData}
                      pagination={visibility === 'expanded' ? { pageSize: 10 } : false}
                      size="small"
                    />
                  </Card>
                </Space>
              ),
            },
          ]}
        />
      )}
    </Space>
  );
}
