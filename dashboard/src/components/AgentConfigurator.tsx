import { useState } from 'react';
import { 
  Card, 
  Steps, 
  Button, 
  Radio, 
  Switch, 
  Tooltip, 
  Typography, 
  Space, 
  Tag,
  Slider,
  Select,
  Input,
  Alert,
  Divider,
} from 'antd';
import { 
  CheckCircleFilled,
  CopyFilled,
  CheckCircleOutlined,
  InfoCircleOutlined,
  SafetyOutlined,
  ThunderboltOutlined,
  CodeOutlined,
  WarningOutlined,
  ArrowRightOutlined,
  ArrowLeftOutlined,
  CloudServerOutlined,
  SettingOutlined,
  SafetyCertificateOutlined,
  ConsoleSqlOutlined,
} from '@ant-design/icons';
import { useDeploymentModes, useAgentFeatures, useCreateServerWithConfig } from '../hooks/useQueries';

const { Title, Text, Paragraph } = Typography;
const { Option } = Select;

// Types
interface DeploymentMode {
  key: string;
  name: string;
  description: string;
  requirements: string;
  performance: string;
  compatibility: string;
}

interface FeatureInfo {
  key: string;
  name: string;
  description: string;
  flag: string;
  env_var: string;
  default_value: boolean;
  available_in: string[];
  details: string;
  example: string;
  benefits: string[];
  risks?: string[];
}

interface AgentConfig {
  mode: string;
  features: Record<string, boolean>;
  threshold: number;
  duration: string;
  daemon: boolean;
}

interface AgentConfiguratorProps {
  onClose?: () => void;
}

export function AgentConfigurator({ onClose }: AgentConfiguratorProps = {}) {
  const [currentStep, setCurrentStep] = useState(0);
  const [serverName, setServerName] = useState('');
  const [config, setConfig] = useState<AgentConfig>({
    mode: 'block_hybrid',
    features: {
      auto_block: true,
      geoip_enrich: true,
      bandwidth_tracking: true,
      rate_limit: false,
    },
    threshold: 80,
    duration: '1h',
    daemon: true,
  });
  const [generatedCommand, setGeneratedCommand] = useState<string | null>(null);
  const [, setInstallData] = useState<{
    api_key: string;
    server_id: string;
    commands: Record<string, string>;
  } | null>(null);
  const [copied, setCopied] = useState(false);

  const { data: modes } = useDeploymentModes();
  const { data: features } = useAgentFeatures();
  const createServerMutation = useCreateServerWithConfig();

  const handleModeChange = (mode: string) => {
    setConfig({ ...config, mode });
  };

  const handleFeatureToggle = (key: string, enabled: boolean) => {
    setConfig({
      ...config,
      features: { ...config.features, [key]: enabled },
    });
  };

  const handleGenerate = () => {
    createServerMutation.mutate(
      {
        server_name: serverName,
        config: config,
      },
      {
        onSuccess: (data) => {
          setInstallData(data);
          setGeneratedCommand(data.commands?.binary || data.commands?.download);
          setCurrentStep(3);
        },
      }
    );
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Step icons
  const stepIcons = [
    <CloudServerOutlined key="server" />,
    <SafetyCertificateOutlined key="safety" />,
    <SettingOutlined key="settings" />,
    <ConsoleSqlOutlined key="terminal" />,
  ];

  const renderServerNameStep = () => (
    <div style={{ maxWidth: '28rem', margin: '0 auto', padding: '32px 0' }}>
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <div style={{ 
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center', 
          width: 64, height: 64, background: 'rgba(59, 130, 246, 0.1)', borderRadius: '50%', marginBottom: 16 
        }}>
          <CloudServerOutlined style={{ fontSize: 32, color: '#3b82f6' }} />
        </div>
        <Title level={3} style={{ marginBottom: 8 }}>Name Your Server</Title>
        <Paragraph style={{ color: 'var(--text-secondary)' }}>
          Give this agent a descriptive name so you can identify it in the dashboard
        </Paragraph>
      </div>

      <Card style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <Text strong style={{ display: 'block', marginBottom: 8 }}>Server Name</Text>
            <Input
              size="large"
              placeholder="e.g., production-web-01, database-primary"
              value={serverName}
              onChange={(e) => setServerName(e.target.value)}
              prefix={<CloudServerOutlined style={{ color: 'var(--text-tertiary)' }} />}
              style={{ borderRadius: 8 }}
            />
          </div>
          
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <Text type="secondary" style={{ fontSize: 12, display: 'block', width: '100%', marginBottom: 4 }}>Suggestions:</Text>
            {['web-server-01', 'api-prod', 'database-primary', 'load-balancer'].map((name) => (
              <Tag 
                key={name} 
                style={{ cursor: 'pointer' }}
                onClick={() => setServerName(name)}
              >
                {name}
              </Tag>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );

  const renderModeSelection = () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ textAlign: 'center', marginBottom: 24 }}>
        <Title level={4} style={{ marginBottom: 8 }}>Choose Your Protection Level</Title>
        <Paragraph style={{ color: 'var(--text-secondary)' }}>
          Select how aggressive you want threat protection to be
        </Paragraph>
      </div>
      
      <Radio.Group
        value={config.mode}
        onChange={(e) => handleModeChange(e.target.value)}
        style={{ width: '100%' }}
      >
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          {modes?.map((mode: DeploymentMode) => (
            <Card
              key={mode.key}
              style={{ 
                cursor: 'pointer',
                borderColor: config.mode === mode.key ? '#1890ff' : undefined,
                boxShadow: config.mode === mode.key ? '0 4px 12px rgba(0,0,0,0.1)' : undefined,
                background: config.mode === mode.key ? 'rgba(24, 144, 255, 0.05)' : undefined
              }}
              onClick={() => handleModeChange(mode.key)}
              bodyStyle={{ padding: 20 }}
            >
              <Radio value={mode.key} style={{ width: '100%' }}>
                <div style={{ marginLeft: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                    <Text strong style={{ fontSize: 18 }}>{mode.name}</Text>
                    {mode.key === 'block_hybrid' && (
                      <Tag color="green">Recommended</Tag>
                    )}
                  </div>
                  <Paragraph style={{ color: 'var(--text-secondary)', marginBottom: 12 }}>
                    {mode.description}
                  </Paragraph>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    <Tag icon={<InfoCircleOutlined />} style={{ borderRadius: 16 }}>
                      {mode.requirements}
                    </Tag>
                    <Tag icon={<ThunderboltOutlined />} color="blue" style={{ borderRadius: 16 }}>
                      {mode.performance}
                    </Tag>
                    <Tag icon={<SafetyOutlined />} color="green" style={{ borderRadius: 16 }}>
                      {mode.compatibility}
                    </Tag>
                  </div>
                </div>
              </Radio>
            </Card>
          ))}
        </Space>
      </Radio.Group>
    </div>
  );

  const renderFeatureConfiguration = () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ textAlign: 'center', marginBottom: 24 }}>
        <Title level={4} style={{ marginBottom: 8 }}>Configure Protection Features</Title>
        <Paragraph style={{ color: 'var(--text-secondary)' }}>
          Toggle features based on your security requirements
        </Paragraph>
      </div>

      {/* Auto-blocking Section */}
      {config.mode !== 'monitor' && (
        <Card 
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <SafetyOutlined style={{ color: '#1890ff' }} />
              <span>Automatic Protection</span>
            </div>
          }
          style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <Text strong style={{ fontSize: 16 }}>Auto-Blocking</Text>
                  <Tooltip title="Automatically block IPs that exceed the threat threshold">
                    <InfoCircleOutlined style={{ color: 'var(--text-tertiary)' }} />
                  </Tooltip>
                </div>
                <Paragraph style={{ fontSize: 14, color: 'var(--text-secondary)', margin: 0 }}>
                  Block malicious IPs automatically when threat score exceeds threshold
                </Paragraph>
              </div>
              <Switch
                checked={config.features.auto_block}
                onChange={(checked) => handleFeatureToggle('auto_block', checked)}
                size="default"
              />
            </div>

            {config.features.auto_block && (
              <div style={{ background: 'var(--bg-tertiary)', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <Text strong>Block Threshold</Text>
                    <Tag color="red" style={{ fontSize: 16, padding: '4px 12px' }}>{config.threshold}</Tag>
                  </div>
                  <Slider
                    min={40}
                    max={95}
                    value={config.threshold}
                    onChange={(val) => setConfig({ ...config, threshold: val })}
                    marks={{
                      40: { label: <span style={{ fontSize: 12 }}>Aggressive</span> },
                      60: { label: <span style={{ fontSize: 12 }}>Balanced</span> },
                      80: { label: <span style={{ fontSize: 12 }}>Conservative</span> },
                    }}
                    tooltip={{ formatter: (val) => `Score: ${val}` }}
                  />
                </div>

                <div>
                  <Text strong style={{ display: 'block', marginBottom: 8 }}>Block Duration</Text>
                  <Select
                    value={config.duration}
                    onChange={(val) => setConfig({ ...config, duration: val })}
                    style={{ width: '100%' }}
                    size="large"
                  >
                    <Option value="1h">1 Hour - Good for testing</Option>
                    <Option value="4h">4 Hours - Recommended</Option>
                    <Option value="24h">24 Hours - High security</Option>
                  </Select>
                </div>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Runtime Mode */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <SettingOutlined style={{ color: '#1890ff' }} />
            <span>Runtime Mode</span>
          </div>
        }
        style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div style={{ flex: 1, paddingRight: 16 }}>
            <Text strong style={{ fontSize: 16 }}>Run as Daemon</Text>
            <Paragraph style={{ fontSize: 14, color: 'var(--text-secondary)', margin: 0 }}>
              Keep the agent running in the background. Disable to run in foreground.
            </Paragraph>
          </div>
          <Switch
            checked={config.daemon}
            onChange={(checked) => setConfig({ ...config, daemon: checked })}
          />
        </div>
      </Card>

      {/* Features List */}
      <Card 
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <CodeOutlined style={{ color: '#722ed1' }} />
            <span>Additional Features</span>
          </div>
        }
        style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {features
            ?.filter((f: FeatureInfo) => f.available_in.includes(config.mode))
            .map((feature: FeatureInfo) => (
              <div
                key={feature.key}
                style={{
                  display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
                  padding: 16, borderRadius: 8, border: '1px solid',
                  borderColor: config.features[feature.key] ?? feature.default_value ? '#bae7ff' : 'var(--border-subtle)',
                  background: config.features[feature.key] ?? feature.default_value ? 'rgba(24, 144, 255, 0.05)' : undefined,
                  transition: 'all 0.2s'
                }}
              >
                <div style={{ flex: 1, paddingRight: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <Text strong style={{ fontSize: 16 }}>{feature.name}</Text>
                    <Tooltip title={feature.details}>
                      <InfoCircleOutlined style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                    </Tooltip>
                  </div>
                  <Paragraph style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 8 }}>
                    {feature.description}
                  </Paragraph>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {feature.benefits.slice(0, 2).map((benefit, idx) => (
                      <Tag key={idx} color="success" style={{ fontSize: 12, borderRadius: 16 }}>
                        <CheckCircleOutlined style={{ marginRight: 4 }} />
                        {benefit}
                      </Tag>
                    ))}
                    {feature.risks?.slice(0, 1).map((risk, idx) => (
                      <Tag key={idx} color="warning" style={{ fontSize: 12, borderRadius: 16 }}>
                        <WarningOutlined style={{ marginRight: 4 }} />
                        {risk}
                      </Tag>
                    ))}
                  </div>
                </div>
                <Switch
                  checked={config.features[feature.key] ?? feature.default_value}
                  onChange={(checked) => handleFeatureToggle(feature.key, checked)}
                  style={{ marginTop: 4 }}
                />
              </div>
            ))}
        </div>
      </Card>
    </div>
  );

  const renderInstallCommand = () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {generatedCommand && (
        <>
          <div style={{ textAlign: 'center' }}>
            <div style={{ 
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center', 
              width: 64, height: 64, background: 'rgba(16, 185, 129, 0.1)', borderRadius: '50%', marginBottom: 16 
            }}>
              <CheckCircleFilled style={{ fontSize: 32, color: '#10b981' }} />
            </div>
            <Title level={4} style={{ marginBottom: 4 }}>Installation Ready!</Title>
            <Paragraph style={{ color: 'var(--text-secondary)' }}>
              Run this command on your Linux server to install the agent
            </Paragraph>
          </div>

          <Card style={{ boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <Text strong>One-Line Installer</Text>
              <Tag color="blue">{config.mode}</Tag>
            </div>

            <div style={{ position: 'relative' }}>
              <div style={{ background: '#0a0a0f', borderRadius: 8, padding: 16, overflowX: 'auto' }}>
                <code style={{ color: '#10b981', fontSize: 14, fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {generatedCommand}
                </code>
              </div>
              <Button
                type="primary"
                icon={copied ? <CheckCircleFilled /> : <CopyFilled />}
                style={{ position: 'absolute', top: 12, right: 12 }}
                onClick={() => copyToClipboard(generatedCommand)}
                size="small"
              >
                {copied ? 'Copied!' : 'Copy'}
              </Button>
            </div>

            <Divider />

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <Text strong style={{ display: 'block' }}>What happens when you run this:</Text>
              <ol style={{ fontSize: 14, color: 'var(--text-secondary)', margin: 0, paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <li>1. Downloads the KernelEye agent binary to <code>/usr/local/bin/kerneleye-agent</code></li>
                <li>2. Starts the agent with your API key and configuration</li>
                <li>3. Agent connects to KernelEye and appears in your dashboard</li>
                <li>4. <strong>Approve the agent</strong> in the dashboard to activate monitoring</li>
              </ol>
            </div>
          </Card>

          <Card style={{ background: 'rgba(24, 144, 255, 0.05)', borderColor: '#91caff' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
              <InfoCircleOutlined style={{ color: '#1890ff', fontSize: 18, marginTop: 2 }} />
              <div>
                <Text strong style={{ display: 'block', color: '#0958d9' }}>Requirements</Text>
                <ul style={{ fontSize: 14, color: '#096dd9', margin: '4px 0 0 0', padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <li>• Linux server with kernel 5.8+</li>
                  <li>• Root privileges (required for eBPF)</li>
                  <li>• Outbound HTTPS access to kerneleye.cloud</li>
                </ul>
              </div>
            </div>
          </Card>

          {onClose && (
            <div style={{ textAlign: 'center', paddingTop: 16 }}>
              <Button type="primary" size="large" onClick={onClose}>
                Done
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );

  const steps = [
    {
      title: 'Server',
      description: 'Name',
      content: renderServerNameStep(),
    },
    {
      title: 'Protection',
      description: 'Mode',
      content: renderModeSelection(),
    },
    {
      title: 'Features',
      description: 'Config',
      content: renderFeatureConfiguration(),
    },
    {
      title: 'Install',
      description: 'Command',
      content: renderInstallCommand(),
    },
  ];

  const canProceed = () => {
    if (currentStep === 0) return serverName.trim().length > 0;
    return true;
  };

  return (
    <div style={{ padding: '0 24px' }}>
      {/* Steps */}
      <Steps 
        current={currentStep} 
        style={{ marginBottom: 32 }}
        items={steps.map((step, index) => ({
          title: step.title,
          description: step.description,
          icon: stepIcons[index],
        }))}
      />

      {/* Content */}
      <div style={{ minHeight: 400 }}>
        {steps[currentStep].content}
      </div>

      {/* Navigation */}
      {currentStep < 3 && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 32, paddingTop: 24, borderTop: '1px solid var(--border-subtle)' }}>
          <Button 
            size="large"
            onClick={() => setCurrentStep(currentStep - 1)}
            disabled={currentStep === 0}
            icon={<ArrowLeftOutlined />}
            style={{ paddingLeft: 24, paddingRight: 24 }}
          >
            Back
          </Button>
          
          {currentStep === 2 ? (
            <Button
              type="primary"
              size="large"
              loading={createServerMutation.isPending}
              onClick={handleGenerate}
              icon={<ConsoleSqlOutlined />}
              style={{ 
                paddingLeft: 32, paddingRight: 32, height: 48, fontSize: 16, fontWeight: 500,
                background: 'linear-gradient(135deg, #1890ff, #722ed1)',
                border: 'none',
                boxShadow: '0 4px 14px rgba(24, 144, 255, 0.4)'
              }}
            >
              Generate Install Command
            </Button>
          ) : (
            <Button 
              type="primary" 
              size="large"
              onClick={() => setCurrentStep(currentStep + 1)}
              disabled={!canProceed()}
              icon={<ArrowRightOutlined />}
              style={{ paddingLeft: 24, paddingRight: 24 }}
            >
              Continue
            </Button>
          )}
        </div>
      )}

      {/* Error Display */}
      {createServerMutation.error && (
        <Alert
          message="Failed to create server"
          description={
            (createServerMutation.error as any)?.response?.data?.message || 
            'An error occurred. Please try again.'
          }
          type="error"
          showIcon
          style={{ marginTop: 16 }}
          action={
            (createServerMutation.error as any)?.response?.data?.code === 'NO_SUBSCRIPTION' ? (
              <Button size="small" type="primary" danger href="/subscription">
                Subscribe
              </Button>
            ) : undefined
          }
        />
      )}
    </div>
  );
}

export default AgentConfigurator;
