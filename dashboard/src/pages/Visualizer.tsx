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
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  AimOutlined,
  ApartmentOutlined,
  BarChartOutlined,
  RadarChartOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  LineChart,
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
import WorldAttackMap from '../components/WorldAttackMap';
import { 
  Globe, 
  Shield, 
  Target, 
  Activity, 
  Server,
  AlertTriangle,
} from 'lucide-react';

const { Title, Text } = Typography;

const sanitizeText = (value: string) =>
  value
    .normalize('NFC')
    .replace(/\uFFFD/g, '')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim();

// Remove CIDR suffix from IP addresses (e.g., "1.2.3.4/32" -> "1.2.3.4")
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

// Cyber color palette
const COLORS = {
  primary: '#6366f1',
  secondary: '#8b5cf6',
  accent: '#06b6d4',
  warning: '#f59e0b',
  danger: '#ef4444',
  success: '#10b981',
  chart: ['#6366f1', '#f59e0b', '#10b981', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16'],
};

// Animated counter hook
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

// Glass card component
function GlassCard({ 
  children, 
  title, 
  icon,
  extra,
  className = '',
  style = {},
}: { 
  children: React.ReactNode; 
  title?: React.ReactNode;
  icon?: React.ReactNode;
  extra?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <Card
      className={className}
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        backdropFilter: 'blur(10px)',
        ...style,
      }}
      bodyStyle={{ padding: 20 }}
      title={title && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Space size={10}>
            {icon && (
              <div
                style={{
                  width: 32,
                  height: 32,
                  background: 'rgba(99, 102, 241, 0.15)',
                  borderRadius: 8,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {icon}
              </div>
            )}
            <Text strong style={{ color: 'var(--text-primary)', fontSize: 14 }}>
              {title}
            </Text>
          </Space>
          {extra}
        </div>
      )}
    >
      {children}
    </Card>
  );
}

// Stat card with icon and trend
function StatCard({ 
  title, 
  value, 
  icon, 
  color,
  trend,
  suffix = '',
}: { 
  title: string; 
  value: number; 
  icon: React.ReactNode;
  color: string;
  trend?: string;
  suffix?: string;
}) {
  const animatedValue = useAnimatedCounter(value);

  return (
    <div
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        backdropFilter: 'blur(10px)',
        padding: 20,
        display: 'flex',
        alignItems: 'center',
        gap: 16,
      }}
    >
      <div
        style={{
          width: 48,
          height: 48,
          background: `${color}20`,
          borderRadius: 12,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}
      >
        {icon}
      </div>
      <div style={{ flex: 1 }}>
        <Text style={{ fontSize: 12, color: 'var(--text-tertiary)', display: 'block', marginBottom: 4 }}>
          {title}
        </Text>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
          <Text strong style={{ fontSize: 28, color: 'var(--text-primary)', lineHeight: 1 }}>
            {animatedValue.toLocaleString()}{suffix}
          </Text>
          {trend && (
            <Tag 
              style={{ 
                margin: 0, 
                fontSize: 10, 
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#10b981',
                border: 'none',
              }}
            >
              {trend}
            </Tag>
          )}
        </div>
      </div>
    </div>
  );
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

  // Get first active server location from GeoIP-enriched backend response
  const serverLocation = useMemo(() => {
    const activeServer = servers?.find(s => s.status === 'active') ?? servers?.[0];
    if (!activeServer) return undefined;

    // Use GeoIP-enriched fields from backend
    if (activeServer.latitude && activeServer.longitude) {
      return {
        lat: activeServer.latitude,
        lng: activeServer.longitude,
        city: activeServer.city || activeServer.hostname,
        country: activeServer.country_code || activeServer.country_name || '',
      };
    }

    // Fall back to metadata JSON (legacy)
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

  // Country data for pie chart
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
      fill: COLORS.chart[i % COLORS.chart.length],
    }));
  }, [sourceIPsData]);

  const visibleTimelineCount = visibility === 'none' ? 0 : visibility === 'summary' ? 3 : 5;

  const totalAlerts = sourceIPsData.reduce((sum: number, ip) => sum + ip.count, 0);
  const uniqueIPs = sourceIPsData.length;
  const uniqueAS = sourceASData.length;
  const uniqueCountries = new Set(sourceIPsData.map((ip) => ip.country)).size;

  const sourceIPs = sourceIPsData;
  const sourceAS = sourceASData;
  // Ensure timeline IPs are cleaned (no CIDR)
  const topTimelineIPs = sourceIPs.slice(0, visibleTimelineCount).map((ip) => cleanIP(ip.ip));
  const sourceIPTableData = visibility === 'expanded' ? sourceIPs : sourceIPs.slice(0, 10);
  const sourceASTableData = visibility === 'expanded' ? sourceAS : sourceAS.slice(0, 10);

  const sourceTimelineQueries = useQueries({
    queries: topTimelineIPs.map((ip) => ({
      queryKey: ['analytics', 'ip-timeline', ip, startDate, endDate],
      queryFn: async () => {
        const { data } = await analyticsAPI.getSourceIPTimeline(ip);
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
      width: 60,
      render: (_, __, idx: number) => (
        <div
          style={{
            width: 28,
            height: 28,
            background: COLORS.chart[idx % COLORS.chart.length] + '20',
            borderRadius: 6,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 12,
            fontWeight: 600,
            color: COLORS.chart[idx % COLORS.chart.length],
          }}
        >
          {idx + 1}
        </div>
      ),
    },
    {
      title: 'IP Address',
      dataIndex: 'ip',
      key: 'ip',
      render: (ip: string, record: SourceIP) => (
        <Space size={8}>
          <Text strong style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>
            {ip}
          </Text>
          <Tooltip title={record.country}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <CountryFlag countryCode={record.countryCode} size={16} />
            </div>
          </Tooltip>
        </Space>
      ),
    },
    {
      title: 'Provider / ASN',
      dataIndex: 'isp',
      key: 'isp',
      render: (isp: string) => (
        <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
          {isp}
        </Text>
      ),
    },
    {
      title: 'Alerts',
      dataIndex: 'count',
      key: 'count',
      width: 100,
      render: (count: number) => (
        <Space size={4}>
          <AlertTriangle size={14} color={count > 100 ? COLORS.danger : COLORS.warning} />
          <Text strong style={{ color: count > 100 ? COLORS.danger : 'var(--text-primary)' }}>
            {count.toLocaleString()}
          </Text>
        </Space>
      ),
    },
    {
      title: 'Share',
      dataIndex: 'percentage',
      key: 'percentage',
      width: 180,
      render: (percentage: number) => (
        <Space size={12} style={{ width: '100%' }}>
          <Progress 
            percent={percentage} 
            showInfo={false} 
            size="small" 
            style={{ width: 80 }}
            strokeColor={percentage > 20 ? COLORS.danger : percentage > 10 ? COLORS.warning : COLORS.primary}
          />
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, minWidth: 40 }}>
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
      width: 60,
      render: (_, __, idx: number) => (
        <div
          style={{
            width: 28,
            height: 28,
            background: COLORS.chart[idx % COLORS.chart.length] + '20',
            borderRadius: 6,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 12,
            fontWeight: 600,
            color: COLORS.chart[idx % COLORS.chart.length],
          }}
        >
          {idx + 1}
        </div>
      ),
    },
    {
      title: 'ASN',
      dataIndex: 'asn',
      key: 'asn',
      render: (asn: string, record: SourceAS) => (
        <Space size={8} direction="vertical" style={{ gap: 2 }}>
          <Text strong style={{ color: 'var(--text-primary)' }}>
            {asn}
          </Text>
          <Text style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
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
        <Space size={6}>
          <CountryFlag countryCode={record.countryCode} size={16} />
          <Text style={{ color: 'var(--text-secondary)' }}>{record.country}</Text>
        </Space>
      ),
    },
    {
      title: 'Alerts',
      dataIndex: 'count',
      key: 'count',
      width: 100,
      render: (count: number) => (
        <Text strong style={{ color: 'var(--text-primary)' }}>
          {count.toLocaleString()}
        </Text>
      ),
    },
    {
      title: 'Share',
      dataIndex: 'percentage',
      key: 'percentage',
      width: 180,
      render: (percentage: number) => (
        <Space size={12} style={{ width: '100%' }}>
          <Progress 
            percent={percentage} 
            showInfo={false} 
            size="small" 
            style={{ width: 80 }}
            strokeColor={COLORS.warning}
          />
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
            {percentage}%
          </Text>
        </Space>
      ),
    },
  ];

  // Custom tooltip for charts
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-md)',
            padding: '12px 16px',
            boxShadow: 'var(--shadow-lg)',
          }}
        >
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block', marginBottom: 4 }}>
            {formatTimelineLabel(label, timeRange)}
          </Text>
          {payload.map((entry: any, index: number) => (
            <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
              <div style={{ width: 8, height: 8, background: entry.color, borderRadius: 2 }} />
              <Text style={{ color: 'var(--text-primary)', fontSize: 13 }}>
                {cleanIP(entry.name)}: <strong>{entry.value}</strong>
              </Text>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1600, margin: '0 auto' }}>
      <Space direction="vertical" size={24} style={{ width: '100%' }}>
        {/* Header */}
        <Row justify="space-between" align="middle">
          <Col>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div
                style={{
                  width: 44,
                  height: 44,
                  background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <RadarChartOutlined style={{ fontSize: 22, color: 'white' }} />
              </div>
              <div>
                <Title level={3} style={{ margin: 0, color: 'var(--text-primary)' }}>
                  Threat Visualizer
                </Title>
                <Text type="secondary" style={{ fontSize: 13 }}>
                  Attack source analysis and threat intelligence visualization
                </Text>
              </div>
            </div>
          </Col>
          <Col>
            <Space size={12}>
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
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                }}
              />
              <Segmented
                value={visibility}
                onChange={(value) => setVisibility(value as 'none' | 'summary' | 'expanded')}
                options={[
                  { label: 'Compact', value: 'none' },
                  { label: 'Summary', value: 'summary' },
                  { label: 'Expanded', value: 'expanded' },
                ]}
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                }}
              />
            </Space>
          </Col>
        </Row>

        {/* Stats Row */}
        <Row gutter={[16, 16]}>
          <Col xs={24} sm={12} lg={6}>
            <StatCard
              title="Total Threats"
              value={totalAlerts}
              icon={<Shield size={24} color={COLORS.primary} />}
              color={COLORS.primary}
            />
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <StatCard
              title="Unique Source IPs"
              value={uniqueIPs}
              icon={<Target size={24} color={COLORS.danger} />}
              color={COLORS.danger}
            />
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <StatCard
              title="Autonomous Systems"
              value={uniqueAS}
              icon={<Server size={24} color={COLORS.warning} />}
              color={COLORS.warning}
            />
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <StatCard
              title="Countries"
              value={uniqueCountries}
              icon={<Globe size={24} color={COLORS.success} />}
              color={COLORS.success}
            />
          </Col>
        </Row>

        {isLoading ? (
          <div style={{ textAlign: 'center', padding: 80 }}>
            <Spin size="large" />
            <Text style={{ display: 'block', marginTop: 16 }} type="secondary">
              Analyzing threat data...
            </Text>
          </div>
        ) : (
          <Tabs
            activeKey={activeTab}
            onChange={setActiveTab}
            type="card"
            style={{ width: '100%' }}
            tabBarStyle={{
              marginBottom: 0,
              borderBottom: '1px solid var(--border-subtle)',
            }}
            items={[
              {
                key: 'source-ip',
                label: (
                  <Space size={8}>
                    <AimOutlined />
                    Source IP
                    <Badge 
                      count={uniqueIPs} 
                      style={{ 
                        backgroundColor: COLORS.primary,
                        fontSize: 10,
                        minWidth: 18,
                        height: 18,
                        lineHeight: '18px',
                      }} 
                    />
                  </Space>
                ),
                children: (
                  <Row gutter={[16, 16]}>
                    {/* World Attack Map */}
                    <Col span={24}>
                      <GlassCard
                        title="Global Attack Map"
                        icon={<Globe size={18} color={COLORS.primary} />}
                        extra={
                          <Space size={8}>
                            <Badge status="processing" color={COLORS.danger} />
                            <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                              Real-time attack origins
                            </Text>
                          </Space>
                        }
                        style={{ position: 'relative', overflow: 'hidden', minHeight: 580 }}
                      >
                        <div style={{ height: 560 }}>
                          <WorldAttackMap 
                            sourceIPs={sourceIPs} 
                            serverLocation={serverLocation}
                          />
                        </div>
                      </GlassCard>
                    </Col>
                    
                    {/* Timeline Chart */}
                    <Col xs={24} lg={12}>
                      <GlassCard
                        title="Attack Timeline"
                        icon={<Activity size={18} color={COLORS.primary} />}
                      >
                        {topTimelineIPs.length === 0 ? (
                          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Timeline hidden in compact mode" />
                        ) : timelineLoading ? (
                          <div style={{ textAlign: 'center', padding: 48 }}>
                            <Spin />
                          </div>
                        ) : sourceTimelineData.length === 0 ? (
                          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No timeline data for selected IPs" />
                        ) : (
                          <div style={{ height: 260 }}>
                            <ResponsiveContainer width="100%" height="100%">
                              <LineChart data={sourceTimelineData} margin={{ top: 12, right: 12, left: 0, bottom: 0 }}>
                                <defs>
                                  {topTimelineIPs.map((ip, i) => (
                                    <linearGradient key={ip} id={`gradient${i}`} x1="0" y1="0" x2="0" y2="1">
                                      <stop offset="5%" stopColor={COLORS.chart[i % COLORS.chart.length]} stopOpacity={0.3}/>
                                      <stop offset="95%" stopColor={COLORS.chart[i % COLORS.chart.length]} stopOpacity={0}/>
                                    </linearGradient>
                                  ))}
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                                <XAxis
                                  dataKey="time"
                                  tickFormatter={(value) => formatTimelineLabel(String(value), timeRange)}
                                  minTickGap={30}
                                  stroke="rgba(255,255,255,0.2)"
                                  fontSize={11}
                                  tick={{ fill: 'var(--text-tertiary)' }}
                                />
                                <YAxis 
                                  allowDecimals={false} 
                                  stroke="rgba(255,255,255,0.2)"
                                  fontSize={11}
                                  tick={{ fill: 'var(--text-tertiary)' }}
                                />
                                <RechartsTooltip content={<CustomTooltip />} />
                                {topTimelineIPs.map((ip, idx) => (
                                  <Area
                                    key={ip}
                                    type="monotone"
                                    dataKey={ip}
                                    name={ip}
                                    stroke={COLORS.chart[idx % COLORS.chart.length]}
                                    strokeWidth={2}
                                    fill={`url(#gradient${idx})`}
                                    dot={false}
                                    connectNulls
                                  />
                                ))}
                                <Legend 
                                  formatter={(value: string) => cleanIP(value)}
                                />
                              </LineChart>
                            </ResponsiveContainer>
                          </div>
                        )}
                      </GlassCard>
                    </Col>
                    
                    {/* Country Distribution */}
                    <Col xs={24} lg={12}>
                      <GlassCard
                        title="Attack Distribution by Country"
                        icon={<Globe size={18} color={COLORS.warning} />}
                      >
                        {countryData.length === 0 ? (
                          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No geographic data" />
                        ) : (
                          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                            {/* Donut chart */}
                            <div style={{ width: 180, height: 180, flexShrink: 0 }}>
                              <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                  <Pie
                                    data={countryData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={50}
                                    outerRadius={78}
                                    paddingAngle={2}
                                    dataKey="count"
                                    onMouseEnter={(_, index) => setActivePieIndex(index)}
                                    onMouseLeave={() => setActivePieIndex(0)}
                                  >
                                    {countryData.map((_, index) => (
                                      <Cell
                                        key={`cell-${index}`}
                                        fill={COLORS.chart[index % COLORS.chart.length]}
                                        stroke="var(--bg-base, #0b1020)"
                                        strokeWidth={index === activePieIndex ? 3 : 1}
                                        opacity={index === activePieIndex ? 1 : 0.8}
                                      />
                                    ))}
                                  </Pie>
                                  <RechartsTooltip
                                    formatter={(value, _, props) => [
                                      `${value as number} alerts (${(props?.payload as any)?.percentage}%)`,
                                      (props?.payload as any)?.country as string
                                    ]}
                                    contentStyle={{
                                      background: 'var(--bg-secondary)',
                                      border: '1px solid var(--border-default)',
                                      borderRadius: 8,
                                    }}
                                  />
                                </PieChart>
                              </ResponsiveContainer>
                            </div>
                            {/* Legend list */}
                            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
                              {countryData.map((entry, index) => (
                                <div
                                  key={entry.countryCode as string}
                                  style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: 8,
                                    padding: '4px 8px',
                                    borderRadius: 6,
                                    background: index === activePieIndex ? `${COLORS.chart[index % COLORS.chart.length]}15` : 'transparent',
                                    cursor: 'default',
                                    transition: 'background 0.2s',
                                  }}
                                  onMouseEnter={() => setActivePieIndex(index)}
                                  onMouseLeave={() => setActivePieIndex(0)}
                                >
                                  <div style={{ width: 10, height: 10, borderRadius: 3, background: COLORS.chart[index % COLORS.chart.length], flexShrink: 0 }} />
                                  <CountryFlag countryCode={entry.countryCode as string} size={14} />
                                  <Text style={{ flex: 1, fontSize: 12, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {entry.country as string}
                                  </Text>
                                  <Text style={{ fontSize: 12, color: 'var(--text-tertiary)', marginLeft: 'auto', flexShrink: 0 }}>
                                    {entry.percentage}%
                                  </Text>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </GlassCard>
                    </Col>
                    {/* IP Tags Cloud */}
                    <Col xs={24} lg={12}>
                      <GlassCard
                        title="Threat Source Overview"
                        icon={<WarningOutlined style={{ color: COLORS.danger }} />}
                      >
                        {sourceIPs.length === 0 ? (
                          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No source IP data" />
                        ) : (
                          <div style={{ minHeight: 'auto' }}>
                            <Space wrap size={[10, 10]} style={{ padding: '8px 0' }}>
                              {sourceIPs.slice(0, 15).map((ip, idx) => (
                                <Tooltip key={ip.ip} title={`${ip.isp} | ${ip.country} | ${ip.count} alerts`}>
                                  <Tag
                                    style={{
                                      padding: '8px 14px',
                                      fontSize: 13,
                                      background: `${COLORS.chart[idx % COLORS.chart.length]}15`,
                                      border: `1px solid ${COLORS.chart[idx % COLORS.chart.length]}40`,
                                      color: COLORS.chart[idx % COLORS.chart.length],
                                      borderRadius: 'var(--radius-md)',
                                      cursor: 'pointer',
                                      transition: 'all 0.2s',
                                    }}
                                    onMouseEnter={(e) => {
                                      e.currentTarget.style.background = `${COLORS.chart[idx % COLORS.chart.length]}30`;
                                      e.currentTarget.style.transform = 'translateY(-2px)';
                                    }}
                                    onMouseLeave={(e) => {
                                      e.currentTarget.style.background = `${COLORS.chart[idx % COLORS.chart.length]}15`;
                                      e.currentTarget.style.transform = 'translateY(0)';
                                    }}
                                  >
                                    <Space size={6}>
                                      <CountryFlag countryCode={ip.countryCode} size={14} />
                                      <span style={{ fontFamily: 'monospace' }}>{ip.ip}</span>
                                      <Badge 
                                        count={ip.count} 
                                        style={{ 
                                          backgroundColor: COLORS.chart[idx % COLORS.chart.length],
                                          fontSize: 10,
                                        }} 
                                      />
                                    </Space>
                                  </Tag>
                                </Tooltip>
                              ))}
                            </Space>
                          </div>
                        )}
                      </GlassCard>
                    </Col>

                    {/* IP Details Table */}
                    <Col span={24}>
                      <GlassCard
                        title="Source IP Details"
                        icon={<AimOutlined style={{ color: COLORS.primary }} />}
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
                          style={{ 
                            background: 'transparent',
                          }}
                        />
                      </GlassCard>
                    </Col>
                  </Row>
                ),
              },
              {
                key: 'source-as',
                label: (
                  <Space size={8}>
                    <ApartmentOutlined />
                    Source AS
                    <Badge 
                      count={uniqueAS} 
                      style={{ 
                        backgroundColor: COLORS.warning,
                        fontSize: 10,
                        minWidth: 18,
                        height: 18,
                        lineHeight: '18px',
                      }} 
                    />
                  </Space>
                ),
                children: (
                  <Row gutter={[16, 16]}>
                    <Col span={24}>
                      <GlassCard
                        title="Top Autonomous Systems"
                        icon={<Server size={18} color={COLORS.warning} />}
                      >
                        {sourceAS.length === 0 ? (
                          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No ASN data" />
                        ) : (
                          <Space wrap size={[10, 10]} style={{ padding: '8px 0' }}>
                            {sourceAS.slice(0, 10).map((as, idx) => (
                              <Tooltip key={as.asn} title={`${as.name} | ${as.country} | ${as.count} alerts`}>
                                <Tag
                                  style={{
                                    padding: '8px 14px',
                                    fontSize: 13,
                                    background: `${COLORS.chart[idx % COLORS.chart.length]}15`,
                                    border: `1px solid ${COLORS.chart[idx % COLORS.chart.length]}40`,
                                    color: COLORS.chart[idx % COLORS.chart.length],
                                    borderRadius: 'var(--radius-md)',
                                    cursor: 'pointer',
                                  }}
                                >
                                  <Space size={6}>
                                    <span>{as.name}</span>
                                    <Badge 
                                      count={as.count} 
                                      style={{ 
                                        backgroundColor: COLORS.chart[idx % COLORS.chart.length],
                                        fontSize: 10,
                                      }} 
                                    />
                                  </Space>
                                </Tag>
                              </Tooltip>
                            ))}
                          </Space>
                        )}
                      </GlassCard>
                    </Col>

                    <Col xs={24} lg={12}>
                      <GlassCard
                        title="AS Distribution"
                        icon={<BarChartOutlined style={{ color: COLORS.warning }} />}
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
                                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="rgba(255,255,255,0.05)" />
                                <XAxis type="number" stroke="rgba(255,255,255,0.2)" fontSize={11} tick={{ fill: 'var(--text-tertiary)' }} />
                                <YAxis
                                  type="category"
                                  dataKey="name"
                                  width={128}
                                  tickFormatter={(value: string) => (value.length > 18 ? `${value.slice(0, 18)}...` : value)}
                                  stroke="rgba(255,255,255,0.2)"
                                  fontSize={11}
                                  tick={{ fill: 'var(--text-secondary)' }}
                                />
                                <RechartsTooltip
                                  contentStyle={{
                                    background: 'var(--bg-secondary)',
                                    border: '1px solid var(--border-default)',
                                    borderRadius: 'var(--radius-md)',
                                  }}
                                />
                                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                                  {sourceAS.map((_, idx) => (
                                    <Cell key={idx} fill={COLORS.chart[idx % COLORS.chart.length]} />
                                  ))}
                                </Bar>
                              </BarChart>
                            </ResponsiveContainer>
                          </div>
                        )}
                      </GlassCard>
                    </Col>

                    <Col xs={24} lg={12}>
                      <Alert
                        type="info"
                        showIcon
                        icon={<Activity size={18} />}
                        message="ASN Timeline Analysis"
                        description="Source IP timeline is now live. ASN timeline tracking will be available in a future update with dedicated backend endpoints for AS-level traffic analysis."
                        style={{
                          background: 'rgba(6, 182, 212, 0.1)',
                          border: '1px solid rgba(6, 182, 212, 0.3)',
                          borderRadius: 'var(--radius-lg)',
                        }}
                      />
                    </Col>

                    <Col span={24}>
                      <GlassCard
                        title="Autonomous System Details"
                        icon={<ApartmentOutlined style={{ color: COLORS.warning }} />}
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
                          style={{ background: 'transparent' }}
                        />
                      </GlassCard>
                    </Col>
                  </Row>
                ),
              },
            ]}
          />
        )}
      </Space>
    </div>
  );
}
