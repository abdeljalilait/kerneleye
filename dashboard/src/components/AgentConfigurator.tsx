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
  TerminalOutlined,
} from '@ant-design/icons';
import { useDeploymentModes, useAgentFeatures, useCreateServerWithConfig } from '../hooks/useQueries';

const { Title, Text, Paragraph } = Typography;
const { Step } = Steps;
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
  });
  const [generatedCommand, setGeneratedCommand] = useState<string | null>(null);
  const [installData, setInstallData] = useState<{
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
    <TerminalOutlined key="terminal" />,
  ];

  const renderServerNameStep = () => (
    <div className="max-w-md mx-auto py-8">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4">
          <CloudServerOutlined className="text-3xl text-blue-500" />
        </div>
        <Title level={3} className="mb-2">Name Your Server</Title>
        <Paragraph className="text-gray-500">
          Give this agent a descriptive name so you can identify it in the dashboard
        </Paragraph>
      </div>

      <Card className="shadow-sm">
        <div className="space-y-4">
          <div>
            <Text strong className="block mb-2">Server Name</Text>
            <Input
              size="large"
              placeholder="e.g., production-web-01, database-primary"
              value={serverName}
              onChange={(e) => setServerName(e.target.value)}
              prefix={<CloudServerOutlined className="text-gray-400" />}
              className="rounded-lg"
            />
          </div>
          
          <div className="flex gap-2 flex-wrap">
            <Text type="secondary" className="text-xs block w-full mb-1">Suggestions:</Text>
            {['web-server-01', 'api-prod', 'database-primary', 'load-balancer'].map((name) => (
              <Tag 
                key={name} 
                className="cursor-pointer hover:bg-blue-50"
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
    <div className="space-y-6">
      <div className="text-center mb-6">
        <Title level={4} className="mb-2">Choose Your Protection Level</Title>
        <Paragraph className="text-gray-500">
          Select how aggressive you want threat protection to be
        </Paragraph>
      </div>
      
      <Radio.Group
        value={config.mode}
        onChange={(e) => handleModeChange(e.target.value)}
        className="w-full"
      >
        <Space direction="vertical" className="w-full" size="middle">
          {modes?.map((mode: DeploymentMode) => (
            <Card
              key={mode.key}
              className={`cursor-pointer transition-all duration-300 hover:shadow-lg ${
                config.mode === mode.key 
                  ? 'border-blue-500 shadow-md bg-blue-50/30' 
                  : 'border-gray-200 hover:border-blue-300'
              }`}
              onClick={() => handleModeChange(mode.key)}
              bodyStyle={{ padding: '20px' }}
            >
              <Radio value={mode.key} className="w-full">
                <div className="ml-3">
                  <div className="flex items-center gap-3 mb-2">
                    <Text strong className="text-lg">{mode.name}</Text>
                    {mode.key === 'block_hybrid' && (
                      <Tag color="green">Recommended</Tag>
                    )}
                  </div>
                  <Paragraph className="text-gray-600 mb-3">
                    {mode.description}
                  </Paragraph>
                  <div className="flex flex-wrap gap-2">
                    <Tag icon={<InfoCircleOutlined />} className="rounded-full">
                      {mode.requirements}
                    </Tag>
                    <Tag icon={<ThunderboltOutlined />} color="blue" className="rounded-full">
                      {mode.performance}
                    </Tag>
                    <Tag icon={<SafetyOutlined />} color="green" className="rounded-full">
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
    <div className="space-y-6">
      <div className="text-center mb-6">
        <Title level={4} className="mb-2">Configure Protection Features</Title>
        <Paragraph className="text-gray-500">
          Toggle features based on your security requirements
        </Paragraph>
      </div>

      {/* Auto-blocking Section */}
      {config.mode !== 'monitor' && (
        <Card 
          title={
            <div className="flex items-center gap-2">
              <SafetyOutlined className="text-blue-500" />
              <span>Automatic Protection</span>
            </div>
          }
          className="shadow-sm"
        >
          <div className="space-y-6">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <Text strong className="text-base">Auto-Blocking</Text>
                  <Tooltip title="Automatically block IPs that exceed the threat threshold">
                    <InfoCircleOutlined className="text-gray-400" />
                  </Tooltip>
                </div>
                <Paragraph className="text-sm text-gray-500 mb-0">
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
              <div className="bg-gray-50 rounded-lg p-4 space-y-4">
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <Text strong>Block Threshold</Text>
                    <Tag color="red" className="text-base px-3 py-1">{config.threshold}</Tag>
                  </div>
                  <Slider
                    min={40}
                    max={95}
                    value={config.threshold}
                    onChange={(val) => setConfig({ ...config, threshold: val })}
                    marks={{
                      40: { label: <span className="text-xs">Aggressive</span> },
                      60: { label: <span className="text-xs">Balanced</span> },
                      80: { label: <span className="text-xs">Conservative</span> },
                    }}
                    tooltip={{ formatter: (val) => `Score: ${val}` }}
                  />
                </div>

                <div>
                  <Text strong className="block mb-2">Block Duration</Text>
                  <Select
                    value={config.duration}
                    onChange={(val) => setConfig({ ...config, duration: val })}
                    className="w-full"
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

      {/* Features List */}
      <Card 
        title={
          <div className="flex items-center gap-2">
            <CodeOutlined className="text-purple-500" />
            <span>Additional Features</span>
          </div>
        }
        className="shadow-sm"
      >
        <div className="space-y-2">
          {features
            ?.filter((f: FeatureInfo) => f.available_in.includes(config.mode))
            .map((feature: FeatureInfo) => (
              <div
                key={feature.key}
                className={`flex items-start justify-between p-4 rounded-lg border transition-all duration-200 ${
                  config.features[feature.key] ?? feature.default_value
                    ? 'border-blue-200 bg-blue-50/30' 
                    : 'border-gray-100 hover:border-gray-200'
                }`}
              >
                <div className="flex-1 pr-4">
                  <div className="flex items-center gap-2 mb-1">
                    <Text strong className="text-base">{feature.name}</Text>
                    <Tooltip title={feature.details}>
                      <InfoCircleOutlined className="text-gray-400 hover:text-blue-500 cursor-help" />
                    </Tooltip>
                  </div>
                  <Paragraph className="text-sm text-gray-600 mb-2">
                    {feature.description}
                  </Paragraph>
                  <div className="flex flex-wrap gap-2">
                    {feature.benefits.slice(0, 2).map((benefit, idx) => (
                      <Tag key={idx} color="success" className="text-xs rounded-full">
                        <CheckCircleOutlined className="mr-1" />
                        {benefit}
                      </Tag>
                    ))}
                    {feature.risks?.slice(0, 1).map((risk, idx) => (
                      <Tag key={idx} color="warning" className="text-xs rounded-full">
                        <WarningOutlined className="mr-1" />
                        {risk}
                      </Tag>
                    ))}
                  </div>
                </div>
                <Switch
                  checked={config.features[feature.key] ?? feature.default_value}
                  onChange={(checked) => handleFeatureToggle(feature.key, checked)}
                  className="mt-1"
                />
              </div>
            ))}
        </div>
      </Card>
    </div>
  );

  const renderInstallCommand = () => (
    <div className="space-y-6">
      {generatedCommand && (
        <>
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 rounded-full mb-4">
              <CheckCircleFilled className="text-3xl text-green-500" />
            </div>
            <Title level={4} className="mb-1">Installation Ready!</Title>
            <Paragraph className="text-gray-500">
              Run this command on your Linux server to install the agent
            </Paragraph>
          </div>

          <Card className="shadow-md">
            <div className="flex items-center justify-between mb-4">
              <Text strong>One-Line Installer</Text>
              <Tag color="blue">{config.mode}</Tag>
            </div>

            <div className="relative">
              <div className="bg-gray-900 rounded-lg p-4 overflow-x-auto">
                <code className="text-green-400 text-sm font-mono whitespace-pre-wrap break-all">
                  {generatedCommand}
                </code>
              </div>
              <Button
                type="primary"
                icon={copied ? <CheckCircleFilled /> : <CopyFilled />}
                className="absolute top-3 right-3"
                onClick={() => copyToClipboard(generatedCommand)}
                size="small"
              >
                {copied ? 'Copied!' : 'Copy'}
              </Button>
            </div>

            <Divider />

            <div className="space-y-3">
              <Text strong className="block">What happens when you run this:</Text>
              <ol className="text-sm text-gray-600 space-y-2 ml-4">
                <li>1. Downloads the KernelEye agent binary to <code>/usr/local/bin/kerneleye-agent</code></li>
                <li>2. Starts the agent with your API key and configuration</li>
                <li>3. Agent connects to KernelEye and appears in your dashboard</li>
                <li>4. <strong>Approve the agent</strong> in the dashboard to activate monitoring</li>
              </ol>
            </div>
          </Card>

          <Card className="bg-blue-50 border-blue-200">
            <div className="flex items-start gap-3">
              <InfoCircleOutlined className="text-blue-500 text-lg mt-0.5" />
              <div>
                <Text strong className="block text-blue-900">Requirements</Text>
                <ul className="text-sm text-blue-800 mt-1 space-y-1">
                  <li>• Linux server with kernel 5.8+</li>
                  <li>• Root privileges (required for eBPF)</li>
                  <li>• Outbound HTTPS access to kerneleye.cloud</li>
                </ul>
              </div>
            </div>
          </Card>

          {onClose && (
            <div className="text-center pt-4">
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
    <div className="agent-configurator">
      {/* Header */}
      <div className="text-center mb-8">
        <Title level={3} className="mb-2">Add New Server</Title>
        <Paragraph className="text-gray-500">
          Configure your KernelEye agent and get the install command
        </Paragraph>
      </div>

      {/* Steps */}
      <Steps 
        current={currentStep} 
        className="mb-8"
        items={steps.map((step, index) => ({
          title: step.title,
          description: step.description,
          icon: stepIcons[index],
        }))}
      />

      {/* Content */}
      <div className="min-h-[400px]">
        {steps[currentStep].content}
      </div>

      {/* Navigation */}
      {currentStep < 3 && (
        <div className="flex justify-between mt-8 pt-6 border-t border-gray-200">
          <Button 
            size="large"
            onClick={() => setCurrentStep(currentStep - 1)}
            disabled={currentStep === 0}
            icon={<ArrowLeftOutlined />}
            className="px-6"
          >
            Back
          </Button>
          
          {currentStep === 2 ? (
            <Button
              type="primary"
              size="large"
              loading={createServerMutation.isPending}
              onClick={handleGenerate}
              icon={<TerminalOutlined />}
              className="px-8 h-12 text-base font-medium"
              style={{ 
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
              className="px-6"
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
          className="mt-4"
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
