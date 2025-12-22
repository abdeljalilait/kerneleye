import { useEffect } from 'react'
import { Typography, Button, Spin, Alert as AntAlert, Table, Tag, Space } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined, CheckCircleOutlined, CloseCircleOutlined, ExclamationCircleOutlined } from '@ant-design/icons'
import { Alert } from '../types'
import { useWebSocket } from '../context/WebSocketContext'
import { useAlerts } from '../hooks/useQueries'
import { queryClient } from '../lib/queryClient'

const { Title, Text } = Typography

export default function Alerts() {
  const { data: alerts, isLoading: loading, error } = useAlerts()
  const { lastMessage } = useWebSocket()

  useEffect(() => {
    if (lastMessage?.type === 'new_alert') {
      const newAlert = lastMessage.data as Alert
      queryClient.setQueryData(['alerts'], (old: Alert[] | undefined) => {
        return old ? [newAlert, ...old] : [newAlert]
      })
    }
  }, [lastMessage])

  const getSeverityTag = (severity: string) => {
    const colorMap: Record<string, string> = {
      critical: 'error',
      high: 'volcano',
      medium: 'warning',
      low: 'blue',
    }
    return <Tag color={colorMap[severity] || 'default'}>{severity.toUpperCase()}</Tag>
  }

  const getStatusTag = (status: string) => {
    if (status === 'active') {
      return <Tag icon={<ExclamationCircleOutlined />} color="processing">{status}</Tag>
    }
    if (status === 'resolved') {
      return <Tag icon={<CheckCircleOutlined />} color="success">{status}</Tag>
    }
    return <Tag>{status}</Tag>
  }

  const columns: ColumnsType<Alert> = [
    {
      title: 'Received',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => <Text type="secondary" style={{ fontSize: 12 }}>{new Date(date).toLocaleString()}</Text>
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity) => getSeverityTag(severity)
    },
    {
      title: 'Source IP',
      dataIndex: 'source_ip',
      key: 'source_ip',
      render: (ip) => <Text code>{ip}</Text>
    },
    {
      title: 'Reason',
      dataIndex: 'reason',
      key: 'reason',
      ellipsis: true,
      render: (reason) => <Text ellipsis style={{ maxWidth: 300 }}>{reason}</Text>
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status) => getStatusTag(status)
    },
    {
      title: 'Action',
      key: 'action',
      render: () => (
        <Space>
          <Button size="small" type="text" icon={<CheckCircleOutlined />} style={{ color: '#52c41a' }} />
          <Button size="small" type="text" icon={<CloseCircleOutlined />} />
        </Space>
      )
    }
  ]

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 256 }}>
        <Spin size="large" />
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <Title level={2} style={{ marginBottom: 8 }}>Security Alerts</Title>
          <Text type="secondary">Actionable security incidents and warnings</Text>
        </div>
        <Button 
          icon={<ReloadOutlined />}
          onClick={() => queryClient.invalidateQueries({ queryKey: ['alerts'] })}
        >
          Refresh
        </Button>
      </div>

      {error && (
        <AntAlert 
          message="Failed to load alerts" 
          type="error" 
          showIcon 
          style={{ marginBottom: 16 }}
        />
      )}

      <Table 
        columns={columns} 
        dataSource={alerts || []} 
        rowKey="id"
        pagination={{ pageSize: 10 }}
        locale={{ emptyText: 'No active alerts' }}
      />
    </div>
  )
}
