import { useState } from 'react';
import { 
  Table, 
  Card, 
  Tag, 
  Button, 
  Space, 
  Tooltip, 
  Typography, 
  Statistic,
  Row,
  Col,
  DatePicker,
  Select,
  Input,
  Badge,
  Popconfirm,
  Drawer,
  Descriptions,
  Alert
} from 'antd';
import { 
  useQuery, 
  useMutation, 
  useQueryClient 
} from '@tanstack/react-query';
import { 
  UnlockOutlined, 
  GlobalOutlined,
  SafetyOutlined,
  ClockCircleOutlined,
  EyeOutlined,
  FilterOutlined,
  ExportOutlined,
  CloseCircleOutlined,
  WarningOutlined,
  DesktopOutlined,
  FlagOutlined,
  ApartmentOutlined,
  WifiOutlined
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';

dayjs.extend(relativeTime);

const { Title, Text, Paragraph } = Typography;
const { RangePicker } = DatePicker;
const { Option } = Select;

// Types
interface BlockRecord {
  id: string;
  ip_address: string;
  ip_version: number;
  server_id: string;
  server_name: string;
  threat_score: number;
  threat_level: 'normal' | 'suspicious' | 'malicious' | 'critical';
  reasons: string[];
  
  // Service info
  target_port: number;
  service_name: string;
  protocol: string;
  
  // GeoIP
  country_code: string;
  country_name: string;
  city: string;
  region: string;
  asn: number;
  asn_org: string;
  is_vpn: boolean;
  is_tor: boolean;
  is_datacenter: boolean;
  latitude: number;
  longitude: number;
  
  // Timing
  blocked_at: string;
  expires_at: string;
  duration_seconds: number;
  
  // Status
  is_active: boolean;
  is_auto_blocked: boolean;
  unblocked_at?: string;
  unblocked_by?: string;
  unblock_reason?: string;
}

interface BlockStats {
  total_active: number;
  total_today: number;
  by_service: Record<string, number>;
  by_country: Record<string, number>;
  by_server: Record<string, number>;
}

const serviceIcons: Record<string, any> = {
  ssh: < SafetyOutlined />,
  http: <WifiOutlined />,
  https: <SafetyOutlined />,
  mysql: <DatabaseOutlined />,
  postgres: <DatabaseOutlined />,
  redis: <DatabaseOutlined />,
  mongodb: <DatabaseOutlined />,
  ftp: <FolderOutlined />,
  smtp: <MailOutlined />,
  dns: <GlobalOutlined />,
};

import { 
  DatabaseOutlined, 
  FolderOutlined, 
  MailOutlined 
} from '@ant-design/icons';

export function BlockedIPs() {
  const queryClient = useQueryClient();
  const [selectedBlock, setSelectedBlock] = useState<BlockRecord | null>(null);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [filters, setFilters] = useState({
    server: 'all',
    service: 'all',
    country: 'all',
    status: 'active',
    search: '',
  });

  // Fetch blocks
  const { data: blocks, isLoading } = useQuery({
    queryKey: ['blocks', filters],
    queryFn: () => fetchBlocks(filters),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ['block-stats'],
    queryFn: fetchBlockStats,
  });

  // Unblock mutation
  const unblockMutation = useMutation({
    mutationFn: (ip: string) => unblockIP(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blocks'] });
    },
  });

  const columns: ColumnsType<BlockRecord> = [
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip',
      render: (ip: string, record: BlockRecord) => (
        <div>
          <div className="flex items-center gap-2">
            <Text strong className="font-mono">{ip}</Text>
            {record.ip_version === 6 && <Tag>IPv6</Tag>}
          </div>
          <div className="flex gap-1 mt-1">
            {record.is_datacenter && (
              <Tooltip title="Datacenter IP (AWS, GCP, etc.)">
                <Tag color="orange" className="text-xs">DC</Tag>
              </Tooltip>
            )}
            {record.is_vpn && (
              <Tooltip title="VPN Exit Node">
                <Tag color="purple" className="text-xs">VPN</Tag>
              </Tooltip>
            )}
            {record.is_tor && (
              <Tooltip title="Tor Exit Node">
                <Tag color="red" className="text-xs">TOR</Tag>
              </Tooltip>
            )}
          </div>
        </div>
      ),
    },
    {
      title: 'Threat',
      dataIndex: 'threat_score',
      key: 'threat',
      sorter: (a, b) => a.threat_score - b.threat_score,
      render: (score: number, record: BlockRecord) => (
        <div>
          <div className="flex items-center gap-2">
            <Badge 
              status={
                score >= 80 ? 'error' : 
                score >= 60 ? 'warning' : 
                'default'
              } 
            />
            <Tag 
              color={
                score >= 80 ? 'red' : 
                score >= 60 ? 'orange' : 
                score >= 30 ? 'yellow' : 
                'green'
              }
            >
              {score}
            </Tag>
          </div>
          <Text type="secondary" className="text-xs capitalize">
            {record.threat_level}
          </Text>
        </div>
      ),
    },
    {
      title: 'Service Targeted',
      key: 'service',
      render: (_, record: BlockRecord) => (
        <div>
          <div className="flex items-center gap-2">
            {serviceIcons[record.service_name] || <DesktopOutlined />}
            <Text strong className="uppercase">{record.service_name}</Text>
          </div>
          <Text type="secondary" className="text-xs">
            Port {record.target_port} / {record.protocol?.toUpperCase()}
          </Text>
        </div>
      ),
      filters: [
        { text: 'SSH', value: 'ssh' },
        { text: 'HTTP', value: 'http' },
        { text: 'HTTPS', value: 'https' },
        { text: 'MySQL', value: 'mysql' },
        { text: 'PostgreSQL', value: 'postgres' },
        { text: 'Redis', value: 'redis' },
      ],
      onFilter: (value, record) => record.service_name === value,
    },
    {
      title: 'Location',
      key: 'location',
      render: (_, record: BlockRecord) => (
        <div>
          <div className="flex items-center gap-2">
            <FlagOutlined />
            <Text>
              {record.country_name || 'Unknown'}
              {record.country_code && (
                <span className="ml-1 text-xs text-gray-500">
                  ({record.country_code})
                </span>
              )}
            </Text>
          </div>
          {record.city && (
            <Text type="secondary" className="text-xs block">
              {record.city}, {record.region}
            </Text>
          )}
          {record.asn_org && (
            <Tooltip title={`AS${record.asn}`}>
              <Text type="secondary" className="text-xs block truncate max-w-xs">
                {record.asn_org}
              </Text>
            </Tooltip>
          )}
        </div>
      ),
    },
    {
      title: 'Server',
      dataIndex: 'server_name',
      key: 'server',
      render: (name: string) => (
        <div className="flex items-center gap-2">
          <ApartmentOutlined />
          <Text>{name}</Text>
        </div>
      ),
    },
    {
      title: 'Blocked',
      dataIndex: 'blocked_at',
      key: 'blocked',
      sorter: (a, b) => new Date(a.blocked_at).getTime() - new Date(b.blocked_at).getTime(),
      render: (date: string, record: BlockRecord) => (
        <div>
          <div className="flex items-center gap-2">
            <ClockCircleOutlined />
            <Text>{dayjs(date).format('MMM D, HH:mm')}</Text>
          </div>
          <Text type="secondary" className="text-xs">
            Expires {dayjs(record.expires_at).fromNow()}
          </Text>
          {record.is_active && (
            <div className="mt-1">
              <ProgressBar 
                percent={calculateProgress(record.blocked_at, record.expires_at)} 
                size="small"
              />
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'status',
      render: (active: boolean, record: BlockRecord) => (
        <div>
          {active ? (
            <Tag color="red" icon={<CloseCircleOutlined />}>Blocked</Tag>
          ) : (
            <Tag color="green" icon={<UnlockOutlined />}>Unblocked</Tag>
          )}
          {record.is_auto_blocked ? (
            <Tag color="blue" className="ml-1 text-xs">Auto</Tag>
          ) : (
            <Tag color="purple" className="ml-1 text-xs">Manual</Tag>
          )}
        </div>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record: BlockRecord) => (
        <Space>
          <Button
            size="small"
            icon={<EyeOutlined />}
            onClick={() => {
              setSelectedBlock(record);
              setDrawerVisible(true);
            }}
          >
            Details
          </Button>
          {record.is_active && (
            <Popconfirm
              title="Unblock this IP?"
              description="The IP will be immediately removed from the blocklist."
              onConfirm={() => unblockMutation.mutate(record.ip_address)}
              okText="Yes, unblock"
              cancelText="Cancel"
            >
              <Button
                size="small"
                type="primary"
                danger
                icon={<UnlockOutlined />}
                loading={unblockMutation.isPending}
              >
                Unblock
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div className="p-6">
      <div className="flex justify-between items-start mb-6">
        <div>
          <Title level={2}>Blocked IPs</Title>
          <Paragraph className="text-gray-600">
            View and manage automatically blocked IPs across all your servers.
          </Paragraph>
        </div>
        <Space>
          <Button icon={<ExportOutlined />}>Export CSV</Button>
          <Button type="primary" icon={<FilterOutlined />}>
            Filters
          </Button>
        </Space>
      </div>

      {/* Statistics Cards */}
      <Row gutter={16} className="mb-6">
        <Col span={6}>
          <Card>
            <Statistic
              title="Active Blocks"
              value={stats?.total_active || 0}
              valueStyle={{ color: '#cf1322' }}
              prefix={<CloseCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Blocked Today"
              value={stats?.total_today || 0}
              prefix={<WarningOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Unique Countries"
              value={Object.keys(stats?.by_country || {}).length}
              prefix={<GlobalOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Services Protected"
              value={Object.keys(stats?.by_service || {}).length}
              prefix={<SafetyOutlined />}
            />
          </Card>
        </Col>
      </Row>

      {/* Filters */}
      <Card className="mb-4">
        <Space wrap>
          <Select
            value={filters.server}
            onChange={(val) => setFilters({ ...filters, server: val })}
            style={{ width: 150 }}
            placeholder="Server"
          >
            <Option value="all">All Servers</Option>
            {/* Populate from user's servers */}
          </Select>
          
          <Select
            value={filters.service}
            onChange={(val) => setFilters({ ...filters, service: val })}
            style={{ width: 150 }}
            placeholder="Service"
          >
            <Option value="all">All Services</Option>
            <Option value="ssh">SSH</Option>
            <Option value="http">HTTP</Option>
            <Option value="https">HTTPS</Option>
          </Select>
          
          <Select
            value={filters.status}
            onChange={(val) => setFilters({ ...filters, status: val })}
            style={{ width: 150 }}
          >
            <Option value="active">Active Only</Option>
            <Option value="expired">Expired</Option>
            <Option value="unblocked">Manually Unblocked</Option>
            <Option value="all">All</Option>
          </Select>
          
          <RangePicker 
            onChange={(dates) => console.log(dates)}
          />
          
          <Input.Search
            placeholder="Search IP..."
            value={filters.search}
            onChange={(e) => setFilters({ ...filters, search: e.target.value })}
            style={{ width: 200 }}
          />
        </Space>
      </Card>

      {/* Main Table */}
      <Card>
        <Table
          columns={columns}
          dataSource={blocks}
          loading={isLoading}
          rowKey="id"
          pagination={{ pageSize: 20 }}
          expandable={{
            expandedRowRender: (record) => (
              <div className="p-4 bg-gray-50">
                <Title level={5}>Threat Reasons</Title>
                <ul className="list-disc list-inside">
                  {record.reasons.map((reason, idx) => (
                    <li key={idx} className="text-sm text-gray-700">{reason}</li>
                  ))}
                </ul>
              </div>
            ),
          }}
        />
      </Card>

      {/* Detail Drawer */}
      <Drawer
        title="Block Details"
        placement="right"
        width={600}
        onClose={() => setDrawerVisible(false)}
        open={drawerVisible}
      >
        {selectedBlock && (
          <div className="space-y-6">
            <Alert
              message={`${selectedBlock.is_active ? 'Currently Blocked' : 'Unblocked'}`}
              type={selectedBlock.is_active ? 'error' : 'success'}
              showIcon
            />

            <Descriptions title="IP Information" bordered column={1}>
              <Descriptions.Item label="IP Address">
                <Text copyable className="font-mono text-lg">
                  {selectedBlock.ip_address}
                </Text>
              </Descriptions.Item>
              <Descriptions.Item label="Version">
                IPv{selectedBlock.ip_version}
              </Descriptions.Item>
              <Descriptions.Item label="ASN">
                AS{selectedBlock.asn} - {selectedBlock.asn_org}
              </Descriptions.Item>
              <Descriptions.Item label="Attributes">
                <Space>
                  {selectedBlock.is_datacenter && <Tag color="orange">Datacenter</Tag>}
                  {selectedBlock.is_vpn && <Tag color="purple">VPN</Tag>}
                  {selectedBlock.is_tor && <Tag color="red">Tor</Tag>}
                </Space>
              </Descriptions.Item>
            </Descriptions>

            <Descriptions title="Location" bordered column={1}>
              <Descriptions.Item label="Country">
                {selectedBlock.country_name} ({selectedBlock.country_code})
              </Descriptions.Item>
              <Descriptions.Item label="City/Region">
                {selectedBlock.city}, {selectedBlock.region}
              </Descriptions.Item>
              <Descriptions.Item label="Coordinates">
                {selectedBlock.latitude}, {selectedBlock.longitude}
              </Descriptions.Item>
            </Descriptions>

            <Descriptions title="Attack Details" bordered column={1}>
              <Descriptions.Item label="Target Service">
                <Space>
                  {serviceIcons[selectedBlock.service_name]}
                  <Text strong className="uppercase">{selectedBlock.service_name}</Text>
                  <Text type="secondary">Port {selectedBlock.target_port}</Text>
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="Threat Score">
                <Tag color={selectedBlock.threat_score >= 80 ? 'red' : 'orange'}>
                  {selectedBlock.threat_score} - {selectedBlock.threat_level}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Reasons">
                <ul className="list-disc list-inside">
                  {selectedBlock.reasons.map((reason, idx) => (
                    <li key={idx}>{reason}</li>
                  ))}
                </ul>
              </Descriptions.Item>
            </Descriptions>

            <Descriptions title="Timeline" bordered column={1}>
              <Descriptions.Item label="Blocked At">
                {dayjs(selectedBlock.blocked_at).format('MMMM D, YYYY HH:mm:ss')}
              </Descriptions.Item>
              <Descriptions.Item label="Expires At">
                {dayjs(selectedBlock.expires_at).format('MMMM D, YYYY HH:mm:ss')}
                {' '}
                ({dayjs(selectedBlock.expires_at).fromNow()})
              </Descriptions.Item>
              {selectedBlock.unblocked_at && (
                <Descriptions.Item label="Unblocked At">
                  {dayjs(selectedBlock.unblocked_at).format('MMMM D, YYYY HH:mm:ss')}
                </Descriptions.Item>
              )}
            </Descriptions>

            {selectedBlock.is_active && (
              <div className="mt-4">
                <Popconfirm
                  title="Unblock this IP?"
                  onConfirm={() => {
                    unblockMutation.mutate(selectedBlock.ip_address);
                    setDrawerVisible(false);
                  }}
                >
                  <Button 
                    type="primary" 
                    danger 
                    block 
                    size="large"
                    icon={<UnlockOutlined />}
                  >
                    Unblock IP Address
                  </Button>
                </Popconfirm>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
}

// Helper components
function ProgressBar({ percent, size = 'default' }: { percent: number; size?: 'small' | 'default' }) {
  const height = size === 'small' ? '4px' : '8px';
  return (
    <div 
      className="w-full bg-gray-200 rounded-full overflow-hidden"
      style={{ height }}
    >
      <div
        className="bg-blue-500 h-full transition-all"
        style={{ width: `${percent}%` }}
      />
    </div>
  );
}

function calculateProgress(start: string, end: string): number {
  const startTime = new Date(start).getTime();
  const endTime = new Date(end).getTime();
  const now = Date.now();
  const total = endTime - startTime;
  const elapsed = now - startTime;
  return Math.min(100, Math.max(0, (elapsed / total) * 100));
}

// API functions
async function fetchBlocks(filters: any): Promise<BlockRecord[]> {
  const query = new URLSearchParams(filters).toString();
  const res = await fetch(`/api/blocks?${query}`);
  return res.json();
}

async function fetchBlockStats(): Promise<BlockStats> {
  const res = await fetch('/api/blocks/stats');
  return res.json();
}

async function unblockIP(ip: string): Promise<void> {
  await fetch(`/api/blocks/${ip}/unblock`, { method: 'POST' });
}
