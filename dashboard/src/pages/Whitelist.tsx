import { useState } from 'react';
import { 
  Table, 
  Card, 
  Tag, 
  Button, 
  Space, 
  Typography, 
  Input,
  Modal,
  Form,
  message,
  Popconfirm,
  Row,
  Col,
  Statistic
} from 'antd';
import { 
  PlusOutlined, 
  DeleteOutlined, 
  SearchOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  GlobalOutlined,
} from '@ant-design/icons';
import { useWhitelist, useAddToWhitelist, useRemoveFromWhitelist } from '../hooks/useQueries';

const { Title, Text } = Typography;
const { Search } = Input;

interface WhitelistEntry {
  id: string;
  ip_address: string;
  ip_version: number;
  reason: string;
  is_manual: boolean;
  created_at: string;
  updated_at: string;
}

export default function Whitelist() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form] = Form.useForm();
  const [searchText, setSearchText] = useState('');

  const { data: whitelist, isLoading } = useWhitelist();
  const addMutation = useAddToWhitelist();
  const removeMutation = useRemoveFromWhitelist();

  const handleAdd = async (values: { ip_address: string; reason?: string }) => {
    try {
      await addMutation.mutateAsync({ ip: values.ip_address, reason: values.reason });
      message.success('IP added to whitelist');
      setIsModalOpen(false);
      form.resetFields();
    } catch (error) {
      message.error('Failed to add IP to whitelist');
    }
  };

  const handleRemove = async (ip: string) => {
    try {
      await removeMutation.mutateAsync(ip);
      message.success('IP removed from whitelist');
    } catch (error) {
      message.error('Failed to remove IP from whitelist');
    }
  };

  const filteredData = (whitelist as WhitelistEntry[] || []).filter((item: WhitelistEntry) =>
    item.ip_address.toLowerCase().includes(searchText.toLowerCase())
  );

  const columns = [
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip_address',
      render: (ip: string, record: WhitelistEntry) => (
        <Space>
          <GlobalOutlined />
          <Text strong>{ip}</Text>
          <Tag color={record.ip_version === 6 ? 'purple' : 'blue'}>
            IPv{record.ip_version}
          </Tag>
        </Space>
      ),
    },
    {
      title: 'Reason',
      dataIndex: 'reason',
      key: 'reason',
      render: (reason: string) => (
        <Text type="secondary">{reason || '-'}</Text>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'is_manual',
      key: 'type',
      render: (isManual: boolean) => (
        isManual ? 
          <Tag color="blue">Manual</Tag> : 
          <Tag color="purple">System</Tag>
      ),
    },
    {
      title: 'Added',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => (
        <Space direction="vertical" size={0}>
          <Text>{new Date(date).toLocaleDateString()}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {new Date(date).toLocaleTimeString()}
          </Text>
        </Space>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, record: WhitelistEntry) => (
        <Popconfirm
          title="Remove from whitelist"
          description="Are you sure you want to remove this IP?"
          onConfirm={() => handleRemove(record.ip_address)}
          okText="Yes"
          cancelText="No"
        >
          <Button 
            danger 
            icon={<DeleteOutlined />}
            size="small"
          >
            Remove
          </Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <div style={{ padding: '24px 48px', maxWidth: 1600, margin: '0 auto' }}>
      {/* Header */}
      <Row justify="space-between" align="middle" style={{ marginBottom: 32 }}>
        <Col>
          <Space direction="vertical" size={4}>
            <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
              Whitelist Management
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>
              Manage IPs that should never be blocked
            </Text>
          </Space>
        </Col>
        <Col>
          <Button 
            type="primary" 
            icon={<PlusOutlined />}
            onClick={() => setIsModalOpen(true)}
            size="large"
          >
            Add to Whitelist
          </Button>
        </Col>
      </Row>

      {/* Stats */}
      <Row gutter={[24, 24]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={8}>
          <Card variant="borderless" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <Statistic
              title={<Text style={{ color: 'var(--text-secondary)' }}>Total Whitelisted</Text>}
              value={filteredData.length}
              prefix={<CheckCircleOutlined style={{ color: '#10b981' }} />}
              valueStyle={{ color: 'var(--text-primary)' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card variant="borderless" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <Statistic
              title={<Text style={{ color: 'var(--text-secondary)' }}>Manual Entries</Text>}
              value={filteredData.filter((w: WhitelistEntry) => w.is_manual).length}
              prefix={<ClockCircleOutlined style={{ color: '#6366f1' }} />}
              valueStyle={{ color: 'var(--text-primary)' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Search and Table */}
      <Card
        variant="borderless"
        style={{ 
          background: 'var(--bg-card)', 
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
        }}
      >
        <Space style={{ marginBottom: 16 }}>
          <Search
            placeholder="Search by IP address"
            allowClear
            prefix={<SearchOutlined />}
            style={{ width: 300 }}
            onChange={(e) => setSearchText(e.target.value)}
          />
        </Space>

        <Table
          dataSource={filteredData}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{ pageSize: 20 }}
        />
      </Card>

      {/* Add Modal */}
      <Modal
        title="Add IP to Whitelist"
        open={isModalOpen}
        onCancel={() => {
          setIsModalOpen(false);
          form.resetFields();
        }}
        footer={null}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleAdd}
        >
          <Form.Item
            name="ip_address"
            label="IP Address"
            rules={[
              { required: true, message: 'Please enter an IP address' },
              { 
                pattern: /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
                message: 'Please enter a valid IPv4 or IPv6 address'
              }
            ]}
          >
            <Input placeholder="e.g., 192.168.1.1 or 2001:db8::1" />
          </Form.Item>

          <Form.Item
            name="reason"
            label="Reason (optional)"
          >
            <Input.TextArea rows={2} placeholder="Why is this IP whitelisted?" />
          </Form.Item>

          <Form.Item>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setIsModalOpen(false)}>Cancel</Button>
              <Button type="primary" htmlType="submit" loading={addMutation.isPending}>
                Add to Whitelist
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
