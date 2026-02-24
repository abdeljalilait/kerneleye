import { useState, useMemo } from 'react';
import dayjs, { Dayjs } from 'dayjs';
import {
  Card,
  Button,
  Typography,
  DatePicker,
  Row,
  Col,
  Statistic,
  Select,
  Space,
  Table,
  Spin,
} from 'antd';
import {
  Calendar,
  Shield,
  AlertTriangle,
  Ban,
  Globe,
  Clock,
  TrendingUp,
  Activity,
  Download,
  FileText,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from 'recharts';
import { 
  useServers,
  useDailyAttackStats,
  useDailyBlockStats,
  useAttackTypeBreakdown,
  useTopSourceCountries,
  useHourlyAttackDistribution,
} from '../hooks/useQueries';

const { Title, Text } = Typography;
const { RangePicker } = DatePicker;

// Color palette for charts
const COLORS = ['#6366f1', '#f59e0b', '#8b5cf6', '#06b6d4', '#10b981', '#64748b'];

export default function Reports() {
  const [dateRange, setDateRange] = useState<[Dayjs, Dayjs]>(() => {
    const end = dayjs();
    const start = dayjs().subtract(7, 'day');
    return [start, end];
  });
  const [selectedServer, setSelectedServer] = useState<string>('all');
  
  const { data: servers, isLoading: serversLoading } = useServers();

  // Format dates for API
  const startDate = dateRange[0].format('YYYY-MM-DD');
  const endDate = dateRange[1].format('YYYY-MM-DD');

  // Fetch analytics data
  const { data: dailyStats, isLoading: dailyStatsLoading } = useDailyAttackStats(startDate, endDate);
  const { data: blockStats, isLoading: blockStatsLoading } = useDailyBlockStats(startDate, endDate);
  const { data: attackTypes, isLoading: attackTypesLoading } = useAttackTypeBreakdown(startDate, endDate);
  const { data: topCountries, isLoading: countriesLoading } = useTopSourceCountries(startDate, endDate, 5);
  const { data: hourlyData, isLoading: hourlyLoading } = useHourlyAttackDistribution(startDate, endDate);

  // Transform daily stats for chart display
  // Combine traffic_events (monitored attacks) with blocks (prevented attacks)
  const dailyData = useMemo(() => {
    // Create a map from blockStats for quick lookup
    const blockMap = new Map();
    if (blockStats) {
      blockStats.forEach((b: any) => {
        blockMap.set(b.date, b.total_blocks || 0);
      });
    }

    if (!dailyStats) return [];
    return dailyStats.map((day: any) => ({
      date: dayjs(day.date).format('MMM D'),
      fullDate: day.date,
      monitored: day.total_attacks || 0,  // Threats detected (from traffic_events)
      prevented: blockMap.get(day.date) || 0,  // Actually blocked (from blocks table)
      uniqueIPs: day.unique_sources || 0,
      sshBruteforce: day.ssh_attacks || 0,
      httpScan: day.http_attacks || 0,
      httpBruteforce: Math.floor((day.http_attacks || 0) * 0.3),
      httpExploit: Math.floor((day.http_attacks || 0) * 0.2),
      portScan: day.other_attacks || 0,
    })).reverse();
  }, [dailyStats, blockStats]);

  // Transform attack types for pie chart
  const threatTypeData = useMemo(() => {
    if (!attackTypes) return [];
    return attackTypes.map((type: any, index: number) => ({
      name: type.attack_type,
      value: type.count || 0,
      color: COLORS[index % COLORS.length],
    }));
  }, [attackTypes]);

  // Transform hourly data
  type HourlyData = { hour: number; attack_count: number; blocked_count: number };
  const hourlyChartData = useMemo(() => {
    if (!hourlyData) {
      // Return empty 24-hour structure if no data
      return Array.from({ length: 24 }, (_, i) => ({
        hour: `${i}:00`,
        attacks: 0,
        blocked: 0,
      }));
    }
    const dataMap = new Map(
      (hourlyData as HourlyData[]).map((h) => [h.hour, h])
    );
    return Array.from({ length: 24 }, (_, i) => {
      const hourData = dataMap.get(i) as HourlyData | undefined;
      return {
        hour: `${i}:00`,
        attacks: hourData?.attack_count || 0,
        blocked: hourData?.blocked_count || 0,
      };
    });
  }, [hourlyData]);

  // Calculate totals
  const totalMonitored = dailyData.reduce((sum: number, d: any) => sum + d.monitored, 0);
  const totalPrevented = dailyData.reduce((sum: number, d: any) => sum + d.prevented, 0);
  const avgAttacksPerDay = dailyData.length > 0 ? Math.round(totalMonitored / dailyData.length) : 0;
  const totalUniqueIPs = dailyData.reduce((sum: number, d: any) => sum + d.uniqueIPs, 0);

  const handleDateChange = (dates: [Dayjs | null, Dayjs | null] | null, _dateStrings: [string, string]) => {
    if (dates && dates[0] && dates[1]) {
      setDateRange([dates[0], dates[1]]);
    }
  };

  const columns = [
    {
      title: 'Date',
      dataIndex: 'fullDate',
      key: 'date',
      render: (text: string) => new Date(text).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
    },
    {
      title: 'Monitored',
      dataIndex: 'monitored',
      key: 'monitored',
      render: (value: number) => value.toLocaleString(),
    },
    {
      title: 'Prevented',
      dataIndex: 'prevented',
      key: 'prevented',
      render: (value: number, record: any) => (
        <Text style={{ color: '#10b981' }}>
          {value.toLocaleString()} ({record.monitored > 0 ? ((value / record.monitored) * 100).toFixed(1) : 0}%)
        </Text>
      ),
    },
  ];

  const isLoading = serversLoading || dailyStatsLoading || blockStatsLoading ||
                    attackTypesLoading || countriesLoading || hourlyLoading;

  return (
    <div style={{ padding: '24px 48px', maxWidth: 1600, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <Row justify="space-between" align="middle">
          <Col>
            <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
              Security Reports
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>
              Daily security metrics and threat analysis
            </Text>
          </Col>
          <Col>
            <Space>
              <Button icon={<Download size={16} />}>Export PDF</Button>
              <Button icon={<FileText size={16} />}>Export CSV</Button>
            </Space>
          </Col>
        </Row>
      </div>

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
            <Text style={{ color: 'var(--text-secondary)' }}>Date Range:</Text>
          </Col>
          <Col>
            <RangePicker
              value={[dateRange[0], dateRange[1]]}
              onChange={handleDateChange}
              style={{
                background: 'var(--bg-tertiary)',
                borderColor: 'var(--border-subtle)',
              }}
            />
          </Col>
          <Col>
            <Text style={{ color: 'var(--text-secondary)' }}>Server:</Text>
          </Col>
          <Col>
            <Select
              value={selectedServer}
              onChange={setSelectedServer}
              style={{ width: 200 }}
              options={[
                { value: 'all', label: 'All Servers' },
                ...(servers?.map((s: any) => ({ value: s.id, label: s.hostname })) || []),
              ]}
            />
          </Col>
        </Row>
      </Card>

      {isLoading ? (
        <div style={{ textAlign: 'center', padding: 64 }}>
          <Spin size="large" />
          <Text style={{ display: 'block', marginTop: 16, color: 'var(--text-secondary)' }}>
            Loading reports...
          </Text>
        </div>
      ) : (
        <>
          {/* Summary Stats */}
          <Row gutter={[20, 20]} style={{ marginBottom: 24 }}>
            <Col xs={24} sm={12} lg={6}>
              <Card
                variant="borderless"
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-lg)',
                }}
                bodyStyle={{ padding: 20 }}
              >
                <Statistic
                  title={
                    <Space>
                      <Shield size={16} color="#818cf8" />
                      <Text style={{ color: 'var(--text-secondary)' }}>Prevented Attacks</Text>
                    </Space>
                  }
                  value={totalPrevented.toLocaleString()}
                  valueStyle={{ color: '#10b981', fontSize: 28, fontWeight: 700 }}
                  prefix={<TrendingUp size={20} style={{ marginRight: 8 }} />}
                />
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                  {totalMonitored > 0 ? ((totalPrevented / totalMonitored) * 100).toFixed(1) : 0}% of threats prevented
                </Text>
              </Card>
            </Col>

            <Col xs={24} sm={12} lg={6}>
              <Card
                variant="borderless"
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-lg)',
                }}
                bodyStyle={{ padding: 20 }}
              >
                <Statistic
                  title={
                    <Space>
                      <AlertTriangle size={16} color="#f59e0b" />
                      <Text style={{ color: 'var(--text-secondary)' }}>Monitored Threats</Text>
                    </Space>
                  }
                  value={totalMonitored.toLocaleString()}
                  valueStyle={{ color: 'var(--text-primary)', fontSize: 28, fontWeight: 700 }}
                />
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                  ~{avgAttacksPerDay.toLocaleString()} per day
                </Text>
              </Card>
            </Col>

            <Col xs={24} sm={12} lg={6}>
              <Card
                variant="borderless"
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-lg)',
                }}
                bodyStyle={{ padding: 20 }}
              >
                <Statistic
                  title={
                    <Space>
                      <Ban size={16} color="#ef4444" />
                      <Text style={{ color: 'var(--text-secondary)' }}>Unique Sources</Text>
                    </Space>
                  }
                  value={totalUniqueIPs.toLocaleString()}
                  valueStyle={{ color: '#ef4444', fontSize: 28, fontWeight: 700 }}
                />
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                  From {topCountries?.length || 0} countries
                </Text>
              </Card>
            </Col>

            <Col xs={24} sm={12} lg={6}>
              <Card
                variant="borderless"
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-lg)',
                }}
                bodyStyle={{ padding: 20 }}
              >
                <Statistic
                  title={
                    <Space>
                      <Globe size={16} color="#06b6d4" />
                      <Text style={{ color: 'var(--text-secondary)' }}>Top Country</Text>
                    </Space>
                  }
                  value={topCountries?.[0]?.country || 'N/A'}
                  valueStyle={{ color: '#06b6d4', fontSize: 24, fontWeight: 700 }}
                />
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                  {topCountries?.[0]?.percentage || 0}% of attacks
                </Text>
              </Card>
            </Col>
          </Row>

          {/* Main Chart - Distribution of Malicious Intents */}
          <Row gutter={[24, 24]} style={{ marginBottom: 24 }}>
            <Col xs={24} lg={16}>
              <Card
                variant="borderless"
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-lg)',
                }}
                title={
                  <Space>
                    <Activity size={18} color="#818cf8" />
                    <Text strong style={{ color: 'var(--text-primary)', fontSize: 16 }}>
                      Distribution of Malicious Intents
                    </Text>
                  </Space>
                }
              >
                <Text style={{ color: 'var(--text-secondary)', marginBottom: 24, display: 'block' }}>
                  Breakdown of attack typology associated with IPs blocked by security engines
                </Text>
                
                <div style={{ height: 350 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={dailyData} barCategoryGap="20%">
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                      <XAxis 
                        dataKey="date" 
                        stroke="var(--text-tertiary)"
                        fontSize={12}
                        tickLine={false}
                      />
                      <YAxis 
                        stroke="var(--text-tertiary)"
                        fontSize={12}
                        tickLine={false}
                        tickFormatter={(value) => value >= 1000 ? `${(value / 1000).toFixed(0)}k` : value}
                      />
                      <RechartsTooltip
                        contentStyle={{
                          background: 'var(--bg-secondary)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 8,
                        }}
                        labelStyle={{ color: 'var(--text-primary)' }}
                      />
                      <Legend />
                      <Bar dataKey="sshBruteforce" name="SSH Attacks" stackId="a" fill="#6366f1" radius={[0, 0, 4, 4]} />
                      <Bar dataKey="httpScan" name="HTTP Attacks" stackId="a" fill="#f59e0b" />
                      <Bar dataKey="portScan" name="Other" stackId="a" fill="#10b981" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* Threat Type Breakdown Table */}
                <div style={{ marginTop: 24 }}>
                  {threatTypeData.map((threat: any, index: number) => (
                    <Row
                      key={threat.name}
                      justify="space-between"
                      align="middle"
                      style={{
                        padding: '12px 0',
                        borderBottom: index < threatTypeData.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                      }}
                    >
                      <Space>
                        <div
                          style={{
                            width: 12,
                            height: 12,
                            borderRadius: '50%',
                            background: threat.color,
                          }}
                        />
                        <Text style={{ color: 'var(--text-primary)' }}>{threat.name}</Text>
                      </Space>
                      <Space size={32}>
                        <Text style={{ color: 'var(--text-secondary)', width: 80, textAlign: 'right' }}>
                          {threat.value >= 1000 ? `${(threat.value / 1000).toFixed(1)}k` : threat.value}
                        </Text>
                        <Text style={{ color: 'var(--text-tertiary)', width: 60, textAlign: 'right' }}>
                          {totalMonitored > 0 ? ((threat.value / totalMonitored) * 100).toFixed(1) : 0}%
                        </Text>
                      </Space>
                    </Row>
                  ))}
                </div>
              </Card>
            </Col>

            <Col xs={24} lg={8}>
              {/* Threat Types Pie Chart */}
              <Card
                variant="borderless"
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-lg)',
                  marginBottom: 24,
                }}
                title={
                  <Space>
                    <Shield size={18} color="#818cf8" />
                    <Text strong style={{ color: 'var(--text-primary)' }}>
                      Attack Distribution
                    </Text>
                  </Space>
                }
              >
                <div style={{ height: 250 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={threatTypeData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        paddingAngle={2}
                        dataKey="value"
                      >
                        {threatTypeData.map((entry: any, index: number) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{
                          background: 'var(--bg-secondary)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 8,
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </Card>

              {/* Top Countries */}
              <Card
                variant="borderless"
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-lg)',
                }}
                title={
                  <Space>
                    <Globe size={18} color="#818cf8" />
                    <Text strong style={{ color: 'var(--text-primary)' }}>
                      Top Attack Sources
                    </Text>
                  </Space>
                }
              >
                <Space direction="vertical" style={{ width: '100%' }} size={12}>
                  {topCountries?.map((country: any, index: number) => (
                    <Row key={country.country} justify="space-between" align="middle">
                      <Space>
                        <Text style={{ color: 'var(--text-tertiary)', width: 20 }}>
                          {index + 1}.
                        </Text>
                        <Text style={{ color: 'var(--text-primary)' }}>{country.country}</Text>
                      </Space>
                      <Space size={16}>
                        <Text style={{ color: 'var(--text-secondary)' }}>
                          {country.attack_count >= 1000 ? `${(country.attack_count / 1000).toFixed(1)}k` : country.attack_count}
                        </Text>
                        <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                          {country.percentage}%
                        </Text>
                      </Space>
                    </Row>
                  ))}
                </Space>
              </Card>
            </Col>
          </Row>

          {/* Hourly Activity Chart */}
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
              marginBottom: 24,
            }}
            title={
              <Space>
                <Clock size={18} color="#818cf8" />
                <Text strong style={{ color: 'var(--text-primary)' }}>
                  Hourly Activity Pattern
                </Text>
              </Space>
            }
          >
            <div style={{ height: 250 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={hourlyChartData}>
                  <defs>
                    <linearGradient id="colorAttacks" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                  <XAxis 
                    dataKey="hour" 
                    stroke="var(--text-tertiary)"
                    fontSize={12}
                    tickLine={false}
                    interval={2}
                  />
                  <YAxis 
                    stroke="var(--text-tertiary)"
                    fontSize={12}
                    tickLine={false}
                  />
                  <RechartsTooltip
                    contentStyle={{
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 8,
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="attacks"
                    name="Total Attacks"
                    stroke="#6366f1"
                    fillOpacity={1}
                    fill="url(#colorAttacks)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name="Blocked"
                    stroke="#10b981"
                    fill="none"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>

          {/* Daily Breakdown Table */}
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            title={
              <Space>
                <Calendar size={18} color="#818cf8" />
                <Text strong style={{ color: 'var(--text-primary)' }}>
                  Daily Breakdown
                </Text>
              </Space>
            }
          >
            <Table
              dataSource={dailyData}
              columns={columns}
              pagination={{ pageSize: 7 }}
              rowKey="fullDate"
              style={{ background: 'transparent' }}
            />
          </Card>
        </>
      )}
    </div>
  );
}
