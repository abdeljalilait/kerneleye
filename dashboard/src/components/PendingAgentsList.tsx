import { Card, Button, List, Tag, Typography, message } from 'antd'
import { Check, X, Server, Clock } from 'lucide-react'
import { Server as ServerType } from '../types'
import { useUpdateServerStatus } from '../hooks/useQueries'

const { Text, Title } = Typography

interface PendingAgentsListProps {
  servers: ServerType[]
  onRefresh: () => void
}

export default function PendingAgentsList({ servers, onRefresh }: PendingAgentsListProps) {
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
    <div style={{ marginBottom: 32 }}>
       <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
           <Clock size={16} color="#faad14" />
           <Title level={4} style={{ margin: 0 }}>Pending Requests ({pendingServers.length})</Title>
       </div>

       <List
         grid={{ gutter: 16, xs: 1, sm: 2, md: 2, lg: 3, xl: 3, xxl: 4 }}
         dataSource={pendingServers}
         renderItem={(server) => (
           <List.Item>
             <Card 
               hoverable
               actions={[
                 <Button 
                    type="text" 
                    icon={<Check size={16} />} 
                    style={{ color: '#52c41a' }}
                    loading={updateStatusMutation.isPending && updateStatusMutation.variables?.id === server.id}
                    onClick={() => handleAction(server.id, 'active')}
                 >
                    Accept
                 </Button>,
                 <Button 
                    type="text" 
                    danger 
                    icon={<X size={16} />}
                    loading={updateStatusMutation.isPending && updateStatusMutation.variables?.id === server.id}
                    onClick={() => handleAction(server.id, 'rejected')}
                 >
                    Refuse
                 </Button>
               ]}
             >
                <Card.Meta 
                  avatar={<Server size={32} style={{ opacity: 0.5 }} />}
                  title={server.hostname || server.name}
                  description={
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <Text type="secondary" style={{ fontSize: 12 }}>ID: {server.id.slice(0, 8)}...</Text>
                      <Tag color="warning">Waiting for approval</Tag>
                    </div>
                  }
                />
             </Card>
           </List.Item>
         )}
       />
    </div>
  )
}
