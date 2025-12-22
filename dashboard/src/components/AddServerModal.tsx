import { useState } from 'react'
import { Modal, Form, Input, Button, Typography, Alert, message } from 'antd'
import { Copy, Check, Terminal } from 'lucide-react'
import { useCreateServer } from '../hooks/useQueries'

const { Text, Title } = Typography

interface AddServerModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess?: () => void
}

export default function AddServerModal({ isOpen, onClose, onSuccess }: AddServerModalProps) {
  const [result, setResult] = useState<{
    api_key: string
    install_command: string
  } | null>(null)
  const [copied, setCopied] = useState(false)
  const createServerMutation = useCreateServer()

  const [form] = Form.useForm()

  const handleSubmit = (values: { hostname: string }) => {
    createServerMutation.mutate(values.hostname, {
      onSuccess: (data) => {
        setResult({
          api_key: data.api_key,
          install_command: data.install_command,
        })
        if (onSuccess) onSuccess()
      },
    })
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    message.success('Copied to clipboard')
    setTimeout(() => setCopied(false), 2000)
  }

  const handleClose = () => {
    form.resetFields()
    setResult(null)
    createServerMutation.reset()
    onClose()
  }

  return (
    <Modal
      title={<Title level={4}>Add New Server</Title>}
      open={isOpen}
      onCancel={handleClose}
      footer={null}
      destroyOnClose
    >
      {!result ? (
        <>
          {createServerMutation.error && (
            <Alert 
              message={(createServerMutation.error as any).response?.data?.error || 'Failed to create server'} 
              type="error" 
              showIcon 
              style={{ marginBottom: 16 }} 
            />
          )}
          <Form form={form} layout="vertical" onFinish={handleSubmit}>
            <Form.Item
              label="Server Hostname"
              name="hostname"
              rules={[{ required: true, message: 'Please enter a hostname' }]}
              extra="A unique name to identify this server in your dashboard."
            >
              <Input placeholder="my-server-1" size="large" />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" block size="large" loading={createServerMutation.isPending}>
                Create Server
              </Button>
            </Form.Item>
          </Form>
        </>
      ) : (
        <div>
          <Alert 
            message="Server created successfully!" 
            type="success" 
            showIcon 
            style={{ marginBottom: 24 }}
          />

          <div style={{ marginBottom: 24 }}>
            <Text strong style={{ display: 'block', marginBottom: 8 }}>Your API Key</Text>
            <div style={{ position: 'relative' }}>
              <div style={{ 
                background: '#141414', 
                padding: 12, 
                borderRadius: 6, 
                border: '1px solid #303030',
                paddingRight: 40
              }}>
                <Text code style={{ wordBreak: 'break-all', color: '#6366f1' }}>{result.api_key}</Text>
              </div>
              <Button 
                size="small" 
                type="text"
                icon={copied ? <Check size={14} style={{ color: '#52c41a' }} /> : <Copy size={14} />}
                onClick={() => copyToClipboard(result.api_key)}
                style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)' }}
              />
            </div>
            <Text type="danger" style={{ fontSize: 12, marginTop: 8, display: 'block' }}>
              ⚠️ Save this key now. It won't be shown again.
            </Text>
          </div>

          <div style={{ marginBottom: 24 }}>
            <Text strong style={{ display: 'block', marginBottom: 8 }}>Install Command</Text>
            <div style={{ 
              background: '#141414', 
              padding: 12, 
              borderRadius: 6, 
              border: '1px solid #303030',
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8
            }}>
              <Terminal size={16} style={{ opacity: 0.5, marginTop: 2, flexShrink: 0 }} />
              <Text code style={{ wordBreak: 'break-all', fontSize: 12 }}>{result.install_command}</Text>
            </div>
            <Text type="secondary" style={{ fontSize: 12, marginTop: 8, display: 'block' }}>
              Run this command on your server to install the KernelEye agent.
            </Text>
          </div>

          <Button block size="large" onClick={handleClose}>
            Done
          </Button>
        </div>
      )}
    </Modal>
  )
}
