import { Table, Tag, Typography, Button, Popconfirm, Space, Card, Avatar, Badge, Progress } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Server } from '../types'
import { Link } from '@tanstack/react-router'
import { useDeleteServer } from '../hooks/useQueries'
import { Trash2, Server as ServerIcon, Activity, ChevronRight } from 'lucide-react'

const { Text } = Typography

interface ServersListProps {
  servers: Server[]
  showCard?: boolean
}

export default function ServersList({ servers, showCard = true }: ServersListProps) {
  const deleteServer = useDeleteServer()

  const handleDelete = (id: string) => {
    deleteServer.mutate(id)
  }

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'active':
        return { color: '#10b981', bg: 'rgba(16, 185, 129, 0.15)', text: 'ONLINE' }
      case 'offline':
        return { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)', text: 'OFFLINE' }
      case 'pending':
        return { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)', text: 'PENDING' }
      default:
        return { color: '#64748b', bg: 'rgba(100, 116, 139, 0.15)', text: 'UNKNOWN' }
    }
  }

  const columns: ColumnsType<Server> = [
    {
      title: 'Server',
      key: 'server',
      render: (_, record) => {
        const config = getStatusConfig(record.status)
        return (
          <Space size={12}>
            <Badge dot color={config.color} offset={[-4, 32]}>
              <Avatar
                size={44}
                style={{
                  background: config.bg,
                  border: `1px solid ${config.color}30`,
                }}
              >
                <ServerIcon size={22} color={config.color} />
              </Avatar>
            </Badge>
            <div>
              <Text 
                strong 
                style={{ 
                  color: 'var(--text-primary)', 
                  fontSize: 14, 
                  display: 'block',
                  maxWidth: 180,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                title={record.hostname || record.name}
              >
                {record.hostname || record.name}
              </Text>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
                <Text code style={{ fontSize: 11, color: 'var(--text-tertiary)', background: 'var(--bg-tertiary)' }}>
                  {record.ip_address || '-'}
                </Text>
                <Tag 
                  style={{ 
                    margin: 0, 
                    fontSize: 10, 
                    padding: '0 8px',
                    background: config.bg,
                    color: config.color,
                    border: 'none',
                    fontWeight: 600,
                  }}
                >
                  {config.text}
                </Tag>
              </div>
            </div>
          </Space>
        )
      },
    },
    {
      title: 'Health',
      key: 'health',
      width: 150,
      render: () => (
        <div style={{ width: 100 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <Text style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>CPU</Text>
            <Text style={{ fontSize: 11, color: 'var(--success)' }}>12%</Text>
          </div>
          <Progress
            percent={12}
            size="small"
            strokeColor="var(--success)"
            trailColor="rgba(255, 255, 255, 0.05)"
            showInfo={false}
          />
        </div>
      ),
    },
    {
      title: 'Events',
      key: 'events',
      width: 120,
      render: () => (
        <Space size={4}>
          <Activity size={14} color="#6366f1" />
          <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
            {Math.floor(Math.random() * 1000).toLocaleString()}
          </Text>
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>/hr</Text>
        </Space>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 140,
      render: (_, record) => (
        <Space size={4}>
          <Link to="/dashboard/servers/$id" params={{ id: record.id }}>
            <Button 
              size="small" 
              type="text"
              style={{ color: 'var(--text-secondary)' }}
            >
              Details
              <ChevronRight size={14} style={{ marginLeft: 4 }} />
            </Button>
          </Link>
          <Popconfirm
            title="Delete Server"
            description="Are you sure you want to delete this server? This action cannot be undone."
            onConfirm={() => handleDelete(record.id)}
            okText="Delete"
            cancelText="Cancel"
            okButtonProps={{ danger: true, loading: deleteServer.isPending }}
          >
            <Button 
              size="small" 
              type="text" 
              danger 
              icon={<Trash2 size={14} />} 
              loading={deleteServer.isPending}
            />
          </Popconfirm>
        </Space>
      )
    }
  ]

  const content = (
    <Table 
      columns={columns} 
      dataSource={servers} 
      rowKey="id"
      pagination={false}
      locale={{ 
        emptyText: (
          <div style={{ padding: '40px 0', textAlign: 'center' }}>
            <div style={{ marginBottom: 16 }}>
              <ServerIcon size={48} color="var(--text-muted)" opacity={0.3} />
            </div>
            <Text style={{ color: 'var(--text-tertiary)' }}>No servers connected</Text>
            <br />
            <Text style={{ color: 'var(--text-muted)', fontSize: 12 }}>
              Install an agent to start monitoring
            </Text>
          </div>
        ) 
      }}
      style={{
        background: 'transparent',
      }}
    />
  )

  if (!showCard) {
    return content
  }

  return (
    <Card
      variant="borderless"
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        backdropFilter: 'blur(10px)',
        height: '100%',
      }}
      bodyStyle={{ padding: 0, height: '100%' }}
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div 
            style={{
              width: 36,
              height: 36,
              background: 'rgba(99, 102, 241, 0.15)',
              borderRadius: 10,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ServerIcon size={18} color="#818cf8" />
          </div>
          <div>
            <Typography.Title level={5} style={{ margin: 0, color: 'var(--text-primary)', fontSize: 16 }}>
              Monitored Servers
            </Typography.Title>
            <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
              {servers.filter(s => s.status === 'active').length} of {servers.length} online
            </Text>
          </div>
        </div>
      }
      extra={
        <Link to="/dashboard/servers">
          <Button type="text" size="small" style={{ color: 'var(--primary-400)' }}>
            View All
          </Button>
        </Link>
      }
    >
      {content}
    </Card>
  )
}
