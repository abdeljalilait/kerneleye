import { useState, useMemo } from 'react';
import dayjs, { Dayjs } from 'dayjs';
import { useNavigate } from '@tanstack/react-router';
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
  Badge,
  Table,
  Spin,
} from 'antd';
import {
  ArrowLeft,
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
import { useStats, useThreats, useServers } from '../hooks/useQueries';

const { Title, Text } = Typography;
const { RangePicker } = DatePicker;

// Mock data for reports - in production this would come from API
const generateDailyData = (startDate: Date, days: number) => {
  const data = [];
  
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(startDate);
    date.setDate(date.getDate() - i);
    const baseAttacks = Math.floor(Math.random() * 5000) + 1000;
    
    data.push({
      date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      fullDate: date.toISOString().split('T')[0],
      sshBruteforce: Math.floor(baseAttacks * 0.6),
      httpScan: Math.floor(baseAttacks * 0.15),
      httpBruteforce: Math.floor(baseAttacks * 0.12),
      httpExploit: Math.floor(baseAttacks * 0.08),
      portScan: Math.floor(baseAttacks * 0.05),
      total: baseAttacks,
      blocked: Math.floor(baseAttacks * 0.95),
      uniqueIPs: Math.floor(baseAttacks * 0.3),
    });
  }
  return data;
};

const threatTypeData = [
  { name: 'SSH Bruteforce', value: 263000, color: '#6366f1' },
  { name: 'HTTP Scan', value: 39200, color: '#f59e0b' },
  { name: 'HTTP Bruteforce', value: 29600, color: '#8b5cf6' },
  { name: 'HTTP Exploit', value: 27000, color: '#06b6d4' },
  { name: 'Port Scan', value: 18500, color: '#10b981' },
  { name: 'Other', value: 12000, color: '#64748b' },
];

const topCountries = [
  { country: 'China', attacks: 125420, percentage: 28.5 },
  { country: 'Russia', attacks: 98200, percentage: 22.3 },
  { country: 'United States', attacks: 65400, percentage: 14.8 },
  { country: 'Brazil', attacks: 42300, percentage: 9.6 },
  { country: 'India', attacks: 32100, percentage: 7.3 },
];

const hourlyData = Array.from({ length: 24 }, (_, i) => ({
  hour: `${i}:00`,
  attacks: Math.floor(Math.random() * 1000) + 200,
  blocked: Math.floor(Math.random() * 900) + 180,
}));

export default function Reports() {
  const navigate = useNavigate();
  const [dateRange, setDateRange] = useState<[Dayjs, Dayjs]>(() => {
    const end = dayjs();
    const start = dayjs().subtract(7, 'day');
    return [start, end];
  });
  const [selectedServer, setSelectedServer] = useState<string>('all');
  
  const { data: stats, isLoading: statsLoading } = useStats();
  const { data: threats, isLoading: threatsLoading } = useThreats();
  const { data: servers, isLoading: serversLoading } = useServers();

  const dailyData = useMemo(() => {
    const days = dateRange[1].diff(dateRange[0], 'day') + 1;
    return generateDailyData(dateRange[1].toDate(), days);
  }, [dateRange]);

  const totalAttacks = dailyData.reduce((sum, d) => sum + d.total, 0);
  const totalBlocked = dailyData.reduce((sum, d) => sum + d.blocked, 0);
  const avgAttacksPerDay = Math.round(totalAttacks / dailyData.length);

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
      title: 'Total Attacks',
      dataIndex: 'total',
      key: 'total',
      render: (value: number) => value.toLocaleString(),
    },
    {
      title: 'SSH Bruteforce',
      dataIndex: 'sshBruteforce',
      key: 'ssh',
      render: (value: number) => (
        <Badge color="#6366f1" text={value.toLocaleString()} />
      ),
    },
    {
      title: 'HTTP Scan',
      dataIndex: 'httpScan',
      key: 'scan',
      render: (value: number) => (
        <Badge color="#f59e0b" text={value.toLocaleString()} />
      ),
    },
    {
      title: 'HTTP Bruteforce',
      dataIndex: 'httpBruteforce',
      key: 'httpBrute',
      render: (value: number) => (
        <Badge color="#8b5cf6" text={value.toLocaleString()} />
      ),
    },
    {
      title: 'Blocked',
      dataIndex: 'blocked',
      key: 'blocked',
      render: (value: number, record: any) => (
        <Text style={{ color: '#10b981' }}>
          {value.toLocaleString()} ({((value / record.total) * 100).toFixed(1)}%)
        </Text>
      ),
    },
  ];

  const isLoading = statsLoading || threatsLoading || serversLoading;

  return (
    <div style={{ padding: '24px 48px', maxWidth: 1600, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
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
                ...(servers?.map(s => ({ value: s.id, label: s.hostname })) || []),
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
                  value={totalBlocked.toLocaleString()}
                  valueStyle={{ color: '#10b981', fontSize: 28, fontWeight: 700 }}
                  prefix={<TrendingUp size={20} style={{ marginRight: 8 }} />}
                />
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                  {((totalBlocked / totalAttacks) * 100).toFixed(1)}% blocked rate
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
                      <Text style={{ color: 'var(--text-secondary)' }}>Total Threats</Text>
                    </Space>
                  }
                  value={totalAttacks.toLocaleString()}
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
                      <Text style={{ color: 'var(--text-secondary)' }}>Blocked IPs</Text>
                    </Space>
                  }
                  value={stats?.blocked_ips || 0}
                  valueStyle={{ color: '#ef4444', fontSize: 28, fontWeight: 700 }}
                />
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                  Active in last 24h
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
                      <Text style={{ color: 'var(--text-secondary)' }}>Unique Sources</Text>
                    </Space>
                  }
                  value={dailyData.reduce((sum, d) => sum + d.uniqueIPs, 0).toLocaleString()}
                  valueStyle={{ color: '#06b6d4', fontSize: 28, fontWeight: 700 }}
                />
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                  From {topCountries.length} countries
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
                      <Bar dataKey="sshBruteforce" name="SSH Bruteforce" stackId="a" fill="#6366f1" radius={[0, 0, 4, 4]} />
                      <Bar dataKey="httpScan" name="HTTP Scan" stackId="a" fill="#f59e0b" />
                      <Bar dataKey="httpBruteforce" name="HTTP Bruteforce" stackId="a" fill="#8b5cf6" />
                      <Bar dataKey="httpExploit" name="HTTP Exploit" stackId="a" fill="#06b6d4" />
                      <Bar dataKey="portScan" name="Port Scan" stackId="a" fill="#10b981" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* Threat Type Breakdown Table */}
                <div style={{ marginTop: 24 }}>
                  {threatTypeData.map((threat, index) => (
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
                          {(threat.value / 1000).toFixed(1)}k
                        </Text>
                        <Text style={{ color: 'var(--text-tertiary)', width: 60, textAlign: 'right' }}>
                          {((threat.value / threatTypeData.reduce((s, t) => s + t.value, 0)) * 100).toFixed(1)}%
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
                        {threatTypeData.map((entry, index) => (
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
                  {topCountries.map((country, index) => (
                    <Row key={country.country} justify="space-between" align="middle">
                      <Space>
                        <Text style={{ color: 'var(--text-tertiary)', width: 20 }}>
                          {index + 1}.
                        </Text>
                        <Text style={{ color: 'var(--text-primary)' }}>{country.country}</Text>
                      </Space>
                      <Space size={16}>
                        <Text style={{ color: 'var(--text-secondary)' }}>
                          {(country.attacks / 1000).toFixed(1)}k
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
                  Hourly Activity (Last 24h)
                </Text>
              </Space>
            }
          >
            <div style={{ height: 250 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={hourlyData}>
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
