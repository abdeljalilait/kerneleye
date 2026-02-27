import { useState } from 'react'
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
  Alert,
} from 'antd'
import {
  Plus,
  Trash2,
  Search,
  CheckCircle,
  Globe,
  Shield,
  Server,
} from 'lucide-react'
import { useWhitelist, useAddToWhitelist, useRemoveFromWhitelist } from '../hooks/useQueries'

const { Title, Text } = Typography

interface WhitelistEntry {
  id: string
  ip_address: string
  ip_version: number
  reason: string
  is_manual: boolean
  created_at: string
  updated_at: string
}

// IP validation helper
const isValidIP = (ip: string): boolean => {
  // IPv4 validation
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  // IPv6 validation (basic)
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^::$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip)
}

export default function Whitelist() {
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [form] = Form.useForm()
  const [searchText, setSearchText] = useState('')

  const { data: whitelist, isLoading, error } = useWhitelist()
  const addMutation = useAddToWhitelist()
  const removeMutation = useRemoveFromWhitelist()

  const handleAdd = async (values: { ip_address: string; reason?: string }) => {
    try {
      await addMutation.mutateAsync({ ip: values.ip_address, reason: values.reason })
      message.success('IP added to whitelist')
      setIsModalOpen(false)
      form.resetFields()
    } catch (error: any) {
      message.error(error?.response?.data?.error || 'Failed to add IP to whitelist')
    }
  }

  const handleRemove = async (ip: string) => {
    try {
      await removeMutation.mutateAsync(ip)
      message.success('IP removed from whitelist')
    } catch (error) {
      message.error('Failed to remove IP from whitelist')
    }
  }

  const filteredData = ((whitelist as WhitelistEntry[]) || []).filter((item: WhitelistEntry) =>
    item.ip_address.toLowerCase().includes(searchText.toLowerCase())
  )

  const columns = [
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip_address',
      render: (ip: string, record: WhitelistEntry) => (
        <Space>
          <Globe size={18} color="var(--text-secondary)" />
          <Text strong style={{ fontFamily: 'monospace', fontSize: 14 }}>
            {ip}
          </Text>
          <Tag
            color={record.ip_version === 6 ? 'purple' : 'blue'}
            style={{ fontSize: 11 }}
          >
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
        <Text type="secondary" style={{ color: 'var(--text-secondary)' }}>
          {reason || '-'}
        </Text>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'is_manual',
      key: 'type',
      render: (isManual: boolean) =>
        isManual ? (
          <Tag color="blue" icon={<Shield size={12} />}>
            Manual
          </Tag>
        ) : (
          <Tag color="purple" icon={<Server size={12} />}>
            System
          </Tag>
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
          <Button danger icon={<Trash2 size={14} />} size="small">
            Remove
          </Button>
        </Popconfirm>
      ),
    },
  ]

  if (error) {
    return (
      <div style={{ padding: '24px 48px' }}>
        <Alert
          message="Failed to load whitelist"
          description="Please try again later"
          type="error"
          showIcon
        />
      </div>
    )
  }

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
              Manage IPs that should never be blocked by the firewall
            </Text>
          </Space>
        </Col>
        <Col>
          <Button
            type="primary"
            icon={<Plus size={18} />}
            onClick={() => setIsModalOpen(true)}
            size="large"
            style={{
              background: 'var(--primary-color)',
            }}
          >
            Add to Whitelist
          </Button>
        </Col>
      </Row>

      {/* Stats */}
      <Row gutter={[20, 20]} style={{ marginBottom: 32 }}>
        <Col xs={24} sm={8}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space size={16}>
              <div
                style={{
                  width: 48,
                  height: 48,
                  background: 'rgba(16, 185, 129, 0.15)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <CheckCircle size={24} color="#10b981" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Total Whitelisted
                </Text>
                <Title level={3} style={{ margin: 0, color: '#10b981' }}>
                  {filteredData.length}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space size={16}>
              <div
                style={{
                  width: 48,
                  height: 48,
                  background: 'rgba(59, 130, 246, 0.15)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Shield size={24} color="#3b82f6" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  Manual Entries
                </Text>
                <Title level={3} style={{ margin: 0, color: '#3b82f6' }}>
                  {filteredData.filter((w: WhitelistEntry) => w.is_manual).length}
                </Title>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            bodyStyle={{ padding: 20 }}
          >
            <Space size={16}>
              <div
                style={{
                  width: 48,
                  height: 48,
                  background: 'rgba(139, 92, 246, 0.15)',
                  borderRadius: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Server size={24} color="#8b5cf6" />
              </div>
              <div>
                <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
                  System Entries
                </Text>
                <Title level={3} style={{ margin: 0, color: '#8b5cf6' }}>
                  {filteredData.filter((w: WhitelistEntry) => !w.is_manual).length}
                </Title>
              </div>
            </Space>
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
          <Input.Search
            placeholder="Search by IP address"
            allowClear
            prefix={<Search size={16} />}
            style={{ width: 300 }}
            onChange={(e) => setSearchText(e.target.value)}
          />
        </Space>

        <Table
          dataSource={filteredData}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} whitelisted IPs`,
          }}
        />
      </Card>

      {/* Add Modal */}
      <Modal
        title="Add IP to Whitelist"
        open={isModalOpen}
        onCancel={() => {
          setIsModalOpen(false)
          form.resetFields()
        }}
        footer={null}
      >
        <Form form={form} layout="vertical" onFinish={handleAdd}>
          <Form.Item
            name="ip_address"
            label="IP Address"
            rules={[
              { required: true, message: 'Please enter an IP address' },
              {
                validator: (_, value) => {
                  if (!value || isValidIP(value)) {
                    return Promise.resolve()
                  }
                  return Promise.reject(new Error('Please enter a valid IPv4 or IPv6 address'))
                },
              },
            ]}
          >
            <Input placeholder="e.g., 192.168.1.1 or 2001:db8::1" />
          </Form.Item>

          <Form.Item name="reason" label="Reason (optional)">
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
  )
}
