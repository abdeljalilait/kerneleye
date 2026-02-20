import { useState } from 'react'
import { Modal, Button, Typography, Steps, Space, Card, Badge, Tooltip, Input, Alert } from 'antd'
import { Copy, Terminal, Check, Key, Server, Shield, ArrowRight } from 'lucide-react'
import { useGenerateApiKey } from '../hooks/useQueries'
import { App } from 'antd'

const { Paragraph, Text, Title } = Typography

interface AddAgentModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess?: () => void
}

export default function AddAgentModal({ isOpen, onClose, onSuccess }: AddAgentModalProps) {
  const { message } = App.useApp()
  const [copied, setCopied] = useState(false)
  const [copiedKey, setCopiedKey] = useState(false)
  const [result, setResult] = useState<{ api_key: string } | null>(null)
  const [currentStep, setCurrentStep] = useState(0)
  
  const generateApiKeyMutation = useGenerateApiKey()

  const serverHost = (() => {
    if (window.location.hostname === 'localhost') return 'localhost:9091'
    const apiUrl = import.meta.env.VITE_API_URL as string | undefined
    if (apiUrl) {
      try {
        const url = new URL(apiUrl)
        return url.port ? `${url.hostname}:${url.port}` : `${url.hostname}:443`
      } catch { /* fall through */ }
    }
    return `${window.location.hostname}:443`
  })()

  // Derive install domain from build-time env var or window.location
  const installDomainRaw = (import.meta.env.VITE_INSTALL_DOMAIN as string) || window.location.hostname
  const installDomain = installDomainRaw.replace(/^https?:\/\//, '')
  const installProtocol = window.location.protocol

  const installCommand = result 
    ? `sudo kerneleye-agent -server "${serverHost}" -apikey "${result.api_key}" -enable-remediation`
    : ''

  const fullInstallCommand = result
    ? `curl -fsSL ${installProtocol}//${installDomain}/install.sh | bash && ${installCommand}`
    : ''

  const handleGenerate = () => {
    generateApiKeyMutation.mutate(undefined, {
      onSuccess: (data) => {
        setResult({ api_key: data.api_key })
        setCurrentStep(1)
        if (onSuccess) onSuccess()
      },
    })
  }

  const handleCopy = (text: string, type: 'cmd' | 'key') => {
    navigator.clipboard.writeText(text)
    message.success(type === 'cmd' ? 'Command copied to clipboard' : 'API Key copied to clipboard')
    if (type === 'cmd') {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } else {
      setCopiedKey(true)
      setTimeout(() => setCopiedKey(false), 2000)
    }
  }

  const handleClose = () => {
    setResult(null)
    setCurrentStep(0)
    onClose()
  }

  const steps = [
    {
      title: 'Generate API Key',
      description: 'Create a secure API key for your new agent',
    },
    {
      title: 'Configure Agent',
      description: 'Run the installation command on your server',
    },
    {
      title: 'Approve',
      description: 'Approve the pending request',
    },
  ]

  return (
    <Modal
      title={
        <Space>
          <div 
            style={{
              width: 40,
              height: 40,
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              borderRadius: 10,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Server size={20} color="white" />
          </div>
          <div>
            <Title level={4} style={{ margin: 0 }}>Install New Agent</Title>
            <Text style={{ color: 'var(--text-tertiary)', fontSize: 13 }}>
              Add a new server to your monitoring network
            </Text>
          </div>
        </Space>
      }
      open={isOpen}
      onCancel={handleClose}
      footer={[
        <Button key="close" onClick={handleClose}>
          {result ? 'Done' : 'Cancel'}
        </Button>
      ]}
      width={700}
      bodyStyle={{ padding: '24px 32px' }}
    >
      {!result ? (
        <Space direction="vertical" size={24} style={{ width: '100%' }}>
          <Steps
            current={currentStep}
            items={steps}
            style={{ marginBottom: 16 }}
          />
          
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
              textAlign: 'center',
              padding: '40px 0',
            }}
          >
            <div 
              style={{
                width: 80,
                height: 80,
                background: 'rgba(99, 102, 241, 0.15)',
                borderRadius: 20,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 24px',
              }}
            >
              <Key size={36} color="#818cf8" />
            </div>
            <Title level={4} style={{ margin: 0, marginBottom: 8 }}>
              Generate API Key
            </Title>
            <Paragraph style={{ color: 'var(--text-secondary)', maxWidth: 400, margin: '0 auto 24px' }}>
              Create a secure API key to authenticate your new server agent. 
              This key will be used to establish an encrypted connection.
            </Paragraph>
            
            <Button 
              type="primary" 
              size="large"
              loading={generateApiKeyMutation.isPending}
              onClick={handleGenerate}
              style={{
                height: 48,
                padding: '0 32px',
                fontSize: 16,
              }}
            >
              Generate API Key
              <ArrowRight size={18} style={{ marginLeft: 8 }} />
            </Button>

            {generateApiKeyMutation.isError && (
              <Alert 
                message="Error" 
                description="Failed to generate API key. Please try again." 
                type="error" 
                showIcon 
                style={{ 
                  marginTop: 24,
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                }}
              />
            )}
          </Card>
        </Space>
      ) : (
        <Space direction="vertical" size={24} style={{ width: '100%' }}>
          <Steps
            current={currentStep}
            items={steps.map((step, idx) => ({
              ...step,
              status: idx < currentStep ? 'finish' : idx === currentStep ? 'process' : 'wait',
            }))}
          />

          {/* API Key Card */}
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            title={
              <Space>
                <Key size={16} color="#818cf8" />
                <Text strong>Your API Key</Text>
                <Badge count="SECURE" style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#10b981' }} />
              </Space>
            }
            extra={
              <Tooltip title="Copy API Key">
                <Button
                  type="text"
                  icon={copiedKey ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
                  onClick={() => handleCopy(result.api_key, 'key')}
                >
                  {copiedKey ? 'Copied' : 'Copy'}
                </Button>
              </Tooltip>
            }
          >
            <Input.Password
              value={result.api_key}
              readOnly
              style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-default)',
                fontFamily: 'monospace',
              }}
            />
            <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, marginTop: 8, display: 'block' }}>
              <Shield size={12} style={{ marginRight: 4 }} />
              Keep this key secure. It provides access to your server monitoring data.
            </Text>
          </Card>

          {/* Installation Command */}
          <Card
            variant="borderless"
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
            }}
            title={
              <Space>
                <Terminal size={16} color="#818cf8" />
                <Text strong>Installation Command</Text>
              </Space>
            }
            extra={
              <Tooltip title="Copy command">
                <Button
                  type="text"
                  icon={copied ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
                  onClick={() => handleCopy(fullInstallCommand, 'cmd')}
                >
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              </Tooltip>
            }
          >
            <div 
              style={{
                background: '#0a0a0f',
                padding: 16,
                borderRadius: 'var(--radius-md)',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 13,
                color: '#d1d5db',
                wordBreak: 'break-all',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <span style={{ color: '#10b981' }}>$</span> {fullInstallCommand}
            </div>
            <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, marginTop: 12, display: 'block' }}>
              Run this command on your Linux server to install and start the agent.
            </Text>
          </Card>

          {/* Next Steps */}
          <Card
            variant="borderless"
            style={{
              background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(16, 185, 129, 0.05))',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              borderRadius: 'var(--radius-lg)',
            }}
          >
            <Space align="start">
              <div 
                style={{
                  width: 40,
                  height: 40,
                  background: 'rgba(16, 185, 129, 0.15)',
                  borderRadius: 10,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Check size={20} color="#10b981" />
              </div>
              <div>
                <Text strong style={{ color: '#10b981', display: 'block', marginBottom: 4 }}>
                  Next Step: Approve Request
                </Text>
                <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
                  After running the agent, return to the Servers page and approve the pending request.
                </Text>
              </div>
            </Space>
          </Card>
        </Space>
      )}
    </Modal>
  )
}
