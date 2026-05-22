import { Table, Tag, Typography, Button, Popconfirm, Space, Card, Avatar, Badge, Tooltip, theme, Empty } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Server } from '../types'
import { Link, useNavigate } from '@tanstack/react-router'
import { useDeleteServer } from '../hooks/useQueries'
import { Trash2, Server as ServerIcon, Globe, Clock, Package } from 'lucide-react'

const { Text, Title } = Typography

interface ServersListProps {
  servers: Server[]
  showCard?: boolean
}

export default function ServersList({ servers, showCard = true }: ServersListProps) {
  const deleteServer = useDeleteServer()
  const navigate = useNavigate()
  const { token } = theme.useToken()

  const handleDelete = (id: string) => {
    deleteServer.mutate(id)
  }

  const handleRowClick = (id: string) => {
    navigate({ to: '/dashboard/servers/$id', params: { id } })
  }

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'active': return { color: token.colorSuccess, label: 'ONLINE', tagColor: 'success' as const }
      case 'offline': return { color: token.colorError, label: 'OFFLINE', tagColor: 'error' as const }
      case 'pending': return { color: token.colorWarning, label: 'PENDING', tagColor: 'warning' as const }
      default: return { color: token.colorTextQuaternary, label: 'UNKNOWN', tagColor: 'default' as const }
    }
  }

  const getRelativeTime = (date: string) => {
    const now = new Date()
    const then = new Date(date)
    const diffSecs = Math.floor((now.getTime() - then.getTime()) / 1000)
    const diffMins = Math.floor(diffSecs / 60)
    const diffHours = Math.floor(diffMins / 60)
    const diffDays = Math.floor(diffHours / 24)
    if (diffSecs < 60) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays < 7) return `${diffDays}d ago`
    return then.toLocaleDateString()
  }

  const columns: ColumnsType<Server> = [
    {
      title: 'Server',
      key: 'server',
      width: '30%',
      minWidth: 200,
      render: (_, record) => {
        const config = getStatusConfig(record.status)
        return (
          <Space size={12}>
            <Badge dot color={config.color} offset={[-4, 32]}>
              <Avatar size={44} style={{ background: `${config.color}20`, border: `1px solid ${config.color}30` }} icon={<ServerIcon size={22} color={config.color} />} />
            </Badge>
            <div>
              <Text strong style={{ fontSize: 14, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }} title={record.hostname || record.name}>
                {record.hostname || record.name}
              </Text>
              <Space size={8} style={{ marginTop: 2 }}>
                <Text code style={{ fontSize: 11 }}>{record.ip_address || '-'}</Text>
                <Tag color={config.tagColor} style={{ margin: 0, fontSize: 10, fontWeight: 600 }}>{config.label}</Tag>
              </Space>
            </div>
          </Space>
        )
      },
    },
    {
      title: 'Location',
      key: 'location',
      width: '15%',
      minWidth: 120,
      render: (_, record) => {
        const location = record.country_name || record.country_code
        const city = record.city
        if (!location && !city) return <Text type="secondary" style={{ fontSize: 13 }}>-</Text>
        return (
          <Tooltip title={city ? `${city}, ${location}` : location}>
            <Space size={4}>
              <Globe size={14} color="#8b5cf6" />
              <Text style={{ fontSize: 13 }}>{city || location}</Text>
              {record.country_code && <Text type="secondary" style={{ fontSize: 11 }}>{record.country_code.toUpperCase()}</Text>}
            </Space>
          </Tooltip>
        )
      },
    },
    {
      title: 'Events',
      key: 'events',
      width: '12%',
      minWidth: 90,
      render: () => (
        <Text type="secondary" style={{ fontSize: 13 }}>{Math.floor(Math.random() * 1000).toLocaleString()} /hr</Text>
      ),
    },
    {
      title: 'Agent',
      key: 'agent',
      width: '12%',
      minWidth: 100,
      render: (_, record) => (
        <Tooltip title={`Agent Version: ${record.agent_version}`}>
          <Space size={4}>
            <Package size={14} color={token.colorSuccess} />
            <Text style={{ fontSize: 13 }}>v{record.agent_version?.replace(/^v/, '') || '-'}</Text>
          </Space>
        </Tooltip>
      ),
    },
    {
      title: 'Last Seen',
      key: 'last_seen',
      width: '15%',
      minWidth: 120,
      render: (_, record) => {
        const isRecent = record.last_seen && (Date.now() - new Date(record.last_seen).getTime()) < 5 * 60 * 1000
        return (
          <Tooltip title={record.last_seen ? new Date(record.last_seen).toLocaleString() : '-'}>
            <Space size={4}>
              <Clock size={14} color={isRecent ? token.colorSuccess : token.colorTextTertiary} />
              <Text style={{ color: isRecent ? token.colorSuccess : undefined, fontSize: 13 }}>
                {record.last_seen ? getRelativeTime(record.last_seen) : '-'}
              </Text>
            </Space>
          </Tooltip>
        )
      },
    },
    {
      title: 'Actions',
      key: 'actions',
      width: '15%',
      minWidth: 100,
      align: 'right',
      render: (_, record) => (
        <Space size={4} onClick={e => e.stopPropagation()} onMouseDown={e => e.stopPropagation()}>
          <Link to="/dashboard/servers/$id" params={{ id: record.id }}>
            <Button size="small" type="text">Details</Button>
          </Link>
          <Popconfirm
            title="Delete Server"
            description="Are you sure you want to delete this server?"
            onConfirm={() => handleDelete(record.id)}
            okText="Delete"
            cancelText="Cancel"
            okButtonProps={{ danger: true, loading: deleteServer.isPending }}
          >
            <Button size="small" type="text" danger icon={<Trash2 size={14} />} loading={deleteServer.isPending} />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const content = (
    <Table
      columns={columns}
      dataSource={servers}
      rowKey="id"
      pagination={false}
      scroll={{ x: 'max-content' }}
      onRow={(record) => ({
        onClick: () => handleRowClick(record.id),
        style: { cursor: 'pointer' },
      })}
      locale={{
        emptyText: (
          <Empty
            image={<ServerIcon size={48} style={{ opacity: 0.3 }} />}
            description="No servers connected"
          >
            Install an agent to start monitoring
          </Empty>
        ),
      }}
    />
  )

  if (!showCard) return content

  return (
    <Card
      styles={{ body: { padding: 0 } }}
      title={
        <Space size={12}>
          <div style={{ width: 36, height: 36, background: token.colorPrimaryBg, borderRadius: token.borderRadius, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ServerIcon size={18} color={token.colorPrimary} />
          </div>
          <div>
            <Title level={5} style={{ margin: 0, fontSize: 16 }}>Monitored Servers</Title>
            <Text type="secondary" style={{ fontSize: 12 }}>{servers.filter(s => s.status === 'active').length} of {servers.length} online</Text>
          </div>
        </Space>
      }
      extra={
        <Link to="/dashboard/servers">
          <Button type="text" size="small" style={{ color: token.colorPrimary }}>View All</Button>
        </Link>
      }
    >
      {content}
    </Card>
  )
}
