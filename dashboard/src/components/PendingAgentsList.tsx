import { Card, Button, List, Tag, Typography, Space, Avatar } from 'antd'
import { Check, X, Server, Clock, Shield, AlertTriangle } from 'lucide-react'
import { Server as ServerType } from '../types'
import { useUpdateServerStatus } from '../hooks/useQueries'
import { App } from 'antd'

const { Text, Title } = Typography

interface PendingAgentsListProps {
  servers: ServerType[]
  onRefresh: () => void
}

export default function PendingAgentsList({ servers, onRefresh }: PendingAgentsListProps) {
  const { message } = App.useApp()
  const pendingServers = servers.filter(s => s.status === 'pending')
  const updateStatusMutation = useUpdateServerStatus()

  if (pendingServers.length === 0) return null

  const handleAction = (id: string, action: 'active' | 'rejected') => {
    updateStatusMutation.mutate(
      { id, status: action },
      {
        onSuccess: () => {
          message.success(`Server ${action === 'active' ? 'approved' : 'rejected'}`)
          onRefresh()
        },
        onError: () => {
          message.error("Failed to update status")
        },
      }
    )
  }

  return (
    <Card
      variant="borderless"
      style={{
        background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.1), rgba(245, 158, 11, 0.05))',
        border: '1px solid rgba(245, 158, 11, 0.3)',
        borderRadius: 'var(--radius-lg)',
      }}
      bodyStyle={{ padding: 24 }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        <div 
          style={{
            width: 44,
            height: 44,
            background: 'rgba(245, 158, 11, 0.2)',
            borderRadius: 12,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <AlertTriangle size={22} color="#f59e0b" />
        </div>
        <div>
          <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>
            Pending Approval
          </Title>
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 13 }}>
            {pendingServers.length} server{pendingServers.length > 1 ? 's' : ''} waiting for approval
          </Text>
        </div>
      </div>

      <List
        grid={{ gutter: 16, xs: 1, sm: 1, md: 2, lg: 2, xl: 3 }}
        dataSource={pendingServers}
        renderItem={(server) => (
          <List.Item>
            <Card 
              variant="borderless"
              style={{
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
              }}
              bodyStyle={{ padding: 16 }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 16 }}>
                <Avatar
                  size={48}
                  style={{
                    background: 'rgba(245, 158, 11, 0.15)',
                    border: '1px solid rgba(245, 158, 11, 0.2)',
                  }}
                  icon={<Server size={24} color="#f59e0b" />}
                />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <Title level={5} style={{ margin: 0, marginBottom: 4, color: 'var(--text-primary)' }}>
                    {server.hostname || server.name}
                  </Title>
                  <Text style={{ fontSize: 12, color: 'var(--text-tertiary)', display: 'block' }}>
                    ID: {server.id.slice(0, 12)}...
                  </Text>
                  <Tag 
                    style={{ 
                      marginTop: 8,
                      background: 'rgba(245, 158, 11, 0.15)', 
                      color: '#f59e0b', 
                      border: 'none',
                      fontSize: 11,
                    }}
                  >
                    <Clock size={12} style={{ marginRight: 4 }} />
                    Awaiting approval
                  </Tag>
                </div>
              </div>

              <Space style={{ width: '100%' }}>
                <Button 
                  type="primary"
                  icon={<Check size={16} />} 
                  loading={updateStatusMutation.isPending && updateStatusMutation.variables?.id === server.id}
                  onClick={() => handleAction(server.id, 'active')}
                  style={{
                    flex: 1,
                    background: '#10b981',
                    borderColor: '#10b981',
                  }}
                >
                  Approve
                </Button>
                <Button 
                  danger 
                  icon={<X size={16} />}
                  loading={updateStatusMutation.isPending && updateStatusMutation.variables?.id === server.id}
                  onClick={() => handleAction(server.id, 'rejected')}
                  style={{ flex: 1 }}
                >
                  Reject
                </Button>
              </Space>
            </Card>
          </List.Item>
        )}
      />
    </Card>
  )
}
