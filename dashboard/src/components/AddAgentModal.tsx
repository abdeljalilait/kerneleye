import { useState } from 'react'
import { Modal, Button, Typography, message, Steps, Alert } from 'antd'
import { Copy, Terminal, Check, Key } from 'lucide-react'
import { useGenerateApiKey } from '../hooks/useQueries'

const { Paragraph, Text, Title } = Typography

interface AddAgentModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess?: () => void
}

export default function AddAgentModal({ isOpen, onClose, onSuccess }: AddAgentModalProps) {
  const [copied, setCopied] = useState(false)
  const [result, setResult] = useState<{ api_key: string } | null>(null)
  
  const generateApiKeyMutation = useGenerateApiKey()

  const serverHost = window.location.hostname === 'localhost' 
    ? 'localhost:9091' 
    : 'api.kerneleye.io:443'

  const installCommand = result 
    ? `sudo ./kerneleye-agent -server "${serverHost}" -apikey "${result.api_key}"`
    : ''

  const handleGenerate = () => {
    generateApiKeyMutation.mutate(undefined, {
      onSuccess: (data) => {
        setResult({ api_key: data.api_key })
        if (onSuccess) onSuccess()
      },
    })
  }

  const handleCopy = () => {
    if (result) {
      navigator.clipboard.writeText(installCommand)
      setCopied(true)
      message.success('Command copied to clipboard')
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const handleCopyAPIKey = () => {
    if (result) {
      navigator.clipboard.writeText(result.api_key)
      message.success('API Key copied to clipboard')
    }
  }

  const handleClose = () => {
    setResult(null)
    onClose()
  }

  return (
    <Modal
      title={<Title level={4}>Install New Agent</Title>}
      open={isOpen}
      onCancel={handleClose}
      footer={[
        <Button key="close" onClick={handleClose}>
          {result ? 'Done' : 'Cancel'}
        </Button>
      ]}
      width={600}
    >
      {!result ? (
        <div>
          <Paragraph type="secondary" style={{ marginBottom: 24 }}>
            Generate an API key to securely connect your server. After running the agent, 
            approve it from the Pending Requests section.
          </Paragraph>
          
          <Button 
            type="primary" 
            block 
            size="large"
            loading={generateApiKeyMutation.isPending}
            onClick={handleGenerate}
          >
            Generate API Key
          </Button>

          {generateApiKeyMutation.isError && (
            <Alert 
              message="Error" 
              description="Failed to generate API key. Please try again." 
              type="error" 
              showIcon 
              style={{ marginTop: 16 }}
            />
          )}
        </div>
      ) : (
        <Steps
          direction="vertical"
          current={1}
          items={[
            {
              title: 'Your API Key',
              description: (
                <div style={{ marginTop: 8 }}>
                  <Paragraph type="secondary">Keep this key secure:</Paragraph>
                  <div style={{ background: '#1f1f1f', padding: 12, borderRadius: 6, position: 'relative' }}>
                    <Text code style={{ color: '#6366f1', wordBreak: 'break-all', fontSize: 11 }}>{result.api_key}</Text>
                    <Button 
                      size="small" 
                      icon={<Copy size={14} />} 
                      style={{ position: 'absolute', right: 8, top: 8 }}
                      onClick={handleCopyAPIKey}
                    />
                  </div>
                </div>
              ),
              icon: <Key size={20} />,
              status: 'finish'
            },
            {
              title: 'Run on your server',
              description: (
                <div style={{ marginTop: 8 }}>
                  <Paragraph type="secondary">Execute this command on your Linux server:</Paragraph>
                  <div style={{ background: '#1f1f1f', padding: 12, borderRadius: 6, position: 'relative' }}>
                    <Text code style={{ color: '#d1d5db', wordBreak: 'break-all', fontSize: 12 }}>{installCommand}</Text>
                    <Button 
                      size="small" 
                      icon={copied ? <Check size={14} /> : <Copy size={14} />} 
                      style={{ position: 'absolute', right: 8, top: 8 }}
                      onClick={handleCopy}
                    />
                  </div>
                </div>
              ),
              icon: <Terminal size={20} />
            },
            {
              title: 'Approve Request',
              description: 'After the agent starts, approve it from Pending Requests.',
              icon: <Check size={20} />
            }
          ]}
        />
      )}
    </Modal>
  )
}
