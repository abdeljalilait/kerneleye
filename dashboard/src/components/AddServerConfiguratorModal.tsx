import { Modal, Button, Typography, Alert, Spin } from 'antd'
import { Server, Crown } from 'lucide-react'
import { useSubscriptionStatus } from '../hooks/useQueries'
import { AgentConfigurator } from './AgentConfigurator'
import { useNavigate } from '@tanstack/react-router'

const { Title, Text } = Typography

interface AddServerConfiguratorModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess?: () => void
}

export default function AddServerConfiguratorModal({ isOpen, onClose }: AddServerConfiguratorModalProps) {
  const navigate = useNavigate()
  const { data: subscription, isLoading: subLoading } = useSubscriptionStatus()

  // Check subscription status
  const noSubscription = subscription && subscription.plan === 'none'

  // Show loading state while fetching subscription
  if (subLoading) {
    return (
      <Modal
        title={<Title level={4}>Add New Server</Title>}
        open={isOpen}
        onCancel={onClose}
        footer={[<Button key="close" onClick={onClose}>Cancel</Button>]}
        width={800}
      >
        <div style={{ padding: '48px 0', textAlign: 'center' }}>
          <Spin size="large" />
          <Text style={{ display: 'block', marginTop: 16, color: 'var(--text-secondary)' }}>
            Checking subscription status...
          </Text>
        </div>
      </Modal>
    )
  }

  // Show subscription required view if no active subscription/trial
  if (noSubscription) {
    return (
      <Modal
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 40, height: 40,
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Crown size={20} color="white" />
            </div>
            <div>
              <Title level={4} style={{ margin: 0 }}>Subscription Required</Title>
            </div>
          </div>
        }
        open={isOpen}
        onCancel={onClose}
        footer={[
          <Button key="close" onClick={onClose}>Cancel</Button>,
          <Button 
            key="subscribe" 
            type="primary"
            onClick={() => {
              onClose()
              navigate({ to: '/dashboard/subscription' })
            }}
          >
            View Plans
          </Button>
        ]}
        width={600}
      >
        <Alert
          message="Active Subscription Required"
          description="You need an active subscription or trial to add and monitor servers. Choose a plan to get started."
          type="info"
          showIcon
          style={{ marginBottom: 24 }}
        />
        <Text style={{ color: 'var(--text-secondary)' }}>
          KernelEye offers flexible plans to fit your security monitoring needs. 
          Start with a 7-day free trial to explore all features.
        </Text>
      </Modal>
    )
  }

  return (
    <Modal
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 40, height: 40,
            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Server size={20} color="white" />
          </div>
          <div>
            <Title level={4} style={{ margin: 0 }}>Add New Server</Title>
            <Text style={{ color: 'var(--text-tertiary)', fontSize: 13 }}>
              Configure your KernelEye agent
            </Text>
          </div>
        </div>
      }
      open={isOpen}
      onCancel={onClose}
      footer={null}
      width={900}
      bodyStyle={{ padding: '24px 0', maxHeight: '70vh', overflow: 'auto' }}
    >
      <AgentConfigurator />
    </Modal>
  )
}
