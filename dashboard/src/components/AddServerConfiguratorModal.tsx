import { Modal, Typography, Space } from 'antd'
import { Server } from 'lucide-react'
import { AgentConfigurator } from './AgentConfigurator'

const { Title, Text } = Typography

interface AddServerConfiguratorModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess?: () => void
}

function ModalIcon({ icon: Icon }: { icon: typeof Server }) {
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
  return (
    <Modal
      title={
        <Space size={12}>
          <ModalIcon icon={Server} />
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
