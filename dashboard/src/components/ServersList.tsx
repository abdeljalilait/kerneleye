import { Table, Tag, Typography, Button, Popconfirm, Space, App } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Server } from '../types'
import { Link } from '@tanstack/react-router'
import { useDeleteServer } from '../hooks/useQueries'
import { Trash2 } from 'lucide-react'

const { Text } = Typography

interface ServersListProps {
  servers: Server[]
}

export default function ServersList({ servers }: ServersListProps) {
  const deleteServer = useDeleteServer()
  const { message } = App.useApp()

  const handleDelete = (id: string) => {
    deleteServer.mutate(id, {
      onSuccess: () => {
        message.success('Server deleted successfully')
      },
      onError: () => {
        message.error('Failed to delete server')
      }
    })
  }

  const columns: ColumnsType<Server> = [
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status) => (
        <Tag color={status === 'active' ? 'success' : status === 'offline' ? 'error' : 'warning'}>
          {status ? status.toUpperCase() : 'UNKNOWN'}
        </Tag>
      ),
    },
    {
      title: 'Hostname',
      key: 'hostname',
      render: (_, record) => (
        <Text strong style={{ color: 'inherit' }}>{record.hostname || record.name}</Text>
      ),
    },
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip_address',
      render: (ip) => <Text code>{ip || '-'}</Text>,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space size="middle">
          <Link to="/dashboard/servers/$id" params={{ id: record.id }}>
            <Button size="small">Details</Button>
          </Link>
          <Popconfirm
            title="Delete Server"
            description="Are you sure you want to delete this server? The agent will terminate itself and all data will be lost."
            onConfirm={() => handleDelete(record.id)}
            okText="Yes, Delete"
            cancelText="No"
            okButtonProps={{ danger: true, loading: deleteServer.isPending }}
          >
            <Button 
              size="small" 
              danger 
              icon={<Trash2 size={14} />} 
              loading={deleteServer.isPending}
            />
          </Popconfirm>
        </Space>
      )
    }
  ]

  return (
    <div style={{ marginTop: 24 }}>
      <Table 
        columns={columns} 
        dataSource={servers} 
        rowKey="id"
        pagination={false}
        locale={{ emptyText: 'No servers connected' }}
      />
    </div>
  )
}
