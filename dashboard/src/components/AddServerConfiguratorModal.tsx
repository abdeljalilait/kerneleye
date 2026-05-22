import { Modal, Button, Typography, Alert, Spin, Space } from 'antd'
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

function ModalIcon({ icon: Icon, color }: { icon: typeof Server; color: string }) {
  return (
    <div
      style={{
        width: 40, height: 40,
        background: `linear-gradient(135deg, #6366f1, #8b5cf6)`,
        borderRadius: 10,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
    >
      <Icon size={20} color="white" />
    </div>
  )
}

export default function AddServerConfiguratorModal({ isOpen, onClose }: AddServerConfiguratorModalProps) {
  const navigate = useNavigate()
  const { data: subscription, isLoading: subLoading } = useSubscriptionStatus()
  const noSubscription = subscription && subscription.plan === 'none'

  if (subLoading) {
    return (
      <Modal
        title={<Title level={4}>Add New Server</Title>}
        open={isOpen}
        onCancel={onClose}
        footer={<Button onClick={onClose}>Cancel</Button>}
        width={800}
      >
        <div style={{ padding: '48px 0', textAlign: 'center' }}>
          <Spin size="large" />
          <Text type="secondary" style={{ display: 'block', marginTop: 16 }}>
            Checking subscription status...
          </Text>
        </div>
      </Modal>
    )
  }

  if (noSubscription) {
    return (
      <Modal
        title={
          <Space size={12}>
            <ModalIcon icon={Crown} color="white" />
            <Title level={4} style={{ margin: 0 }}>Subscription Required</Title>
          </Space>
        }
        open={isOpen}
        onCancel={onClose}
        footer={[
          <Button key="close" onClick={onClose}>Cancel</Button>,
          <Button
            key="subscribe"
            type="primary"
            onClick={() => { onClose(); navigate({ to: '/dashboard/subscription' }) }}
          >
            View Plans
          </Button>,
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
        <Text type="secondary">
          KernelEye offers flexible plans to fit your security monitoring needs.
          Start with a 7-day free trial to explore all features.
        </Text>
      </Modal>
    )
  }

  return (
    <Modal
      title={
        <Space size={12}>
          <ModalIcon icon={Server} color="white" />
          <div>
            <Title level={4} style={{ margin: 0 }}>Add New Server</Title>
            <Text type="secondary" style={{ fontSize: 13 }}>Configure your KernelEye agent</Text>
          </div>
        </Space>
      }
      open={isOpen}
      onCancel={onClose}
      footer={null}
      width={900}
      styles={{ body: { padding: '24px 0', maxHeight: '70vh', overflow: 'auto' } }}
    >
      <AgentConfigurator />
    </Modal>
  )
}
