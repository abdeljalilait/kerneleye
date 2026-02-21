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
  Alert,
  Tag,
  Slider,
  Select,
  Tabs,
} from 'antd';
import { 
  CheckCircleFilled,
  CopyFilled,
  DownloadOutlined,
  FileTextOutlined,
  LinuxOutlined,
  DockerOutlined,
  CheckCircleOutlined,
  InfoCircleOutlined,
  SafetyOutlined,
  ThunderboltOutlined,
  CodeOutlined,
  WarningOutlined
} from '@ant-design/icons';
import { useDeploymentModes, useAgentFeatures, useCreateServerWithConfig } from '../hooks/useQueries';

const { Title, Text, Paragraph } = Typography;
const { Step } = Steps;
const { TabPane } = Tabs;
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

export function AgentConfigurator() {
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
  const [generatedKey, setGeneratedKey] = useState<{
    api_key: string;
    server_id: string;
    commands: Record<string, string>;
    environment: Record<string, string>;
  } | null>(null);
  const [copied, setCopied] = useState(false);

  // Fetch deployment modes
  const { data: modes } = useDeploymentModes();

  // Fetch features
  const { data: features } = useAgentFeatures();

  // Create server with config mutation
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
          setGeneratedKey(data);
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

  const renderModeSelection = () => (
    <div className="space-y-4">
      <Alert
        message="Choose Your Protection Level"
        description="Select how aggressive you want threat protection to be. You can change this later."
        type="info"
        showIcon
      />
      
      <Radio.Group
        value={config.mode}
        onChange={(e) => handleModeChange(e.target.value)}
        className="w-full"
      >
        <Space direction="vertical" className="w-full">
          {modes?.map((mode: DeploymentMode) => (
            <Card
              key={mode.key}
              className={`cursor-pointer transition-all ${
                config.mode === mode.key ? 'border-blue-500 shadow-md' : ''
              }`}
              onClick={() => handleModeChange(mode.key)}
            >
              <Radio value={mode.key} className="w-full">
                <div className="ml-4">
                  <div className="flex items-center gap-2">
                    <Text strong className="text-lg">{mode.name}</Text>
                    {mode.key === 'block_hybrid' && (
                      <Tag color="green" icon={<CheckCircleOutlined />}>Recommended</Tag>
                    )}
                  </div>
                  <Paragraph className="text-gray-600 mt-1">
                    {mode.description}
                  </Paragraph>
                  <div className="flex gap-4 mt-2 text-sm">
                    <Tooltip title="System requirements">
                      <Tag icon={<InfoCircleOutlined />}>
                        {mode.requirements}
                      </Tag>
                    </Tooltip>
                    <Tooltip title="Performance impact">
                      <Tag icon={<ThunderboltOutlined />} color="blue">
                        {mode.performance}
                      </Tag>
                    </Tooltip>
                    <Tooltip title="Compatibility">
                      <Tag icon={<SafetyOutlined />} color="green">
                        {mode.compatibility}
                      </Tag>
                    </Tooltip>
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
      <Alert
        message="Configure Protection Features"
        description="Toggle features based on your security requirements. Hover over each feature for details."
        type="info"
        showIcon
      />

      {/* Auto-blocking Section */}
      {config.mode !== 'monitor' && (
        <Card 
          title={<><SafetyOutlined /> Automatic Protection</>}
          className="bg-blue-50"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Text strong>Auto-Blocking</Text>
                <Paragraph className="text-sm text-gray-600 mb-0">
                  Automatically block IPs that exceed threat threshold
                </Paragraph>
              </div>
              <Switch
                checked={config.features.auto_block}
                onChange={(checked) => handleFeatureToggle('auto_block', checked)}
              />
            </div>

            {config.features.auto_block && (
              <div className="ml-6 space-y-4 border-l-2 border-blue-200 pl-4">
                <div>
                  <Text>Block Threshold: <Tag color="red">{config.threshold}</Tag></Text>
                  <Tooltip title="Higher = less aggressive, fewer false positives. Lower = more aggressive.">
                    <Slider
                      min={40}
                      max={95}
                      value={config.threshold}
                      onChange={(val) => setConfig({ ...config, threshold: val })}
                      marks={{
                        40: 'Aggressive',
                        60: 'Balanced',
                        80: 'Conservative',
                      }}
                    />
                  </Tooltip>
                  <div className="flex justify-between text-xs text-gray-500">
                    <span>Catches more threats</span>
                    <span>Fewer false positives</span>
                  </div>
                </div>

                <div>
                  <Text>Block Duration</Text>
                  <Select
                    value={config.duration}
                    onChange={(val) => setConfig({ ...config, duration: val })}
                    className="w-full"
                  >
                    <Option value="1h">
                      <Text>1 Hour <Text type="secondary">- Good for testing</Text></Text>
                    </Option>
                    <Option value="4h">
                      <Text>4 Hours <Text type="secondary">- Recommended</Text></Text>
                    </Option>
                    <Option value="24h">
                      <Text>24 Hours <Text type="secondary">- High security</Text></Text>
                    </Option>
                  </Select>
                  <Paragraph className="text-xs text-gray-500 mt-1">
                    First offense: selected duration. Repeat offenders: 2x, 4x, up to 24h max.
                  </Paragraph>
                </div>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Features List */}
      <Card title={<><CodeOutlined /> Additional Features</>}>
        <div className="space-y-4">
          {features
            ?.filter((f: FeatureInfo) => f.available_in.includes(config.mode))
            .map((feature: FeatureInfo) => (
              <div
                key={feature.key}
                className="flex items-start justify-between p-3 rounded hover:bg-gray-50"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <Text strong>{feature.name}</Text>
                    <Tooltip title={feature.details}>
                      <InfoCircleOutlined className="text-gray-400" />
                    </Tooltip>
                  </div>
                  <Paragraph className="text-sm text-gray-600 mb-1">
                    {feature.description}
                  </Paragraph>
                  <div className="flex gap-2">
                    {feature.benefits.slice(0, 2).map((benefit, idx) => (
                      <Tag key={idx} color="green" className="text-xs">
                        {benefit}
                      </Tag>
                    ))}
                  </div>
                  {feature.risks && (
                    <div className="mt-2">
                      {feature.risks.map((risk, idx) => (
                        <Tag key={idx} color="orange" className="text-xs">
                          <WarningOutlined /> {risk}
                        </Tag>
                      ))}
                    </div>
                  )}
                </div>
                <Switch
                  checked={config.features[feature.key] ?? feature.default_value}
                  onChange={(checked) => handleFeatureToggle(feature.key, checked)}
                />
              </div>
            ))}
        </div>
      </Card>
    </div>
  );

  const renderCommandOutput = () => (
    <div className="space-y-6">
      {generatedKey && (
        <>
          <Alert
            message="API Key Generated Successfully!"
            description={`Server: ${serverName} | Mode: ${config.mode}`}
            type="success"
            showIcon
            icon={<CheckCircleFilled />}
          />

          <Card>
            <div className="flex items-center justify-between mb-4">
              <Text strong>API Key:</Text>
              <Tag color="blue" className="font-mono">
                {generatedKey.api_key?.substring(0, 12)}...
                {generatedKey.api_key?.substring(generatedKey.api_key.length - 4)}
              </Tag>
            </div>

            <Tabs defaultActiveKey="binary">
              <TabPane
                tab={<><CodeOutlined /> Binary (Quick Start)</>}
                key="binary"
              >
                <div className="relative">
                  <pre className="bg-gray-900 text-green-400 p-4 rounded overflow-x-auto text-sm">
                    {generatedKey.commands?.binary}
                  </pre>
                  <Button
                    icon={copied ? <CheckCircleFilled /> : <CopyFilled />}
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(generatedKey.commands?.binary || '')}
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </Button>
                </div>
              </TabPane>

              <TabPane
                tab={<><DockerOutlined /> Docker</>}
                key="docker"
              >
                <div className="relative">
                  <pre className="bg-gray-900 text-green-400 p-4 rounded overflow-x-auto text-sm">
                    {generatedKey.commands?.docker}
                  </pre>
                  <Button
                    icon={copied ? <CheckCircleFilled /> : <CopyFilled />}
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(generatedKey.commands?.docker || '')}
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </Button>
                </div>
              </TabPane>

              <TabPane
                tab={<><LinuxOutlined /> Systemd</>}
                key="systemd"
              >
                <div className="relative">
                  <pre className="bg-gray-900 text-green-400 p-4 rounded overflow-x-auto text-sm">
                    {generatedKey.commands?.systemd}
                  </pre>
                  <Button
                    icon={copied ? <CheckCircleFilled /> : <CopyFilled />}
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(generatedKey.commands?.systemd || '')}
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </Button>
                </div>
              </TabPane>

              <TabPane
                tab={<><FileTextOutlined /> Environment</>}
                key="env"
              >
                <Card size="small" title="Environment Variables">
                  {Object.entries(generatedKey.environment || {}).map(([key, value]) => (
                    <div key={key} className="flex justify-between py-1 border-b last:border-0">
                      <Text code className="text-xs">{key}</Text>
                      <Text className="text-xs" copyable>{value as string}</Text>
                    </div>
                  ))}
                </Card>
              </TabPane>
            </Tabs>
          </Card>

          <Card title="What's Next?">
            <Steps direction="vertical" current={0}>
              <Step
                title="Run the command"
                description="Copy and paste the command above into your server terminal"
              />
              <Step
                title="Wait for connection"
                description="Agent will appear in your dashboard within 30 seconds"
              />
              <Step
                title="Approve the agent"
                description="Click 'Approve' in the dashboard to activate monitoring"
              />
              <Step
                title="Monitor threats"
                description="Watch the Threats tab for blocked IPs and attacks"
              />
            </Steps>
          </Card>
        </>
      )}
    </div>
  );

  const steps = [
    {
      title: 'Server Name',
      content: (
        <Card>
          <Title level={4}>Name Your Server</Title>
          <Paragraph>
            Give this agent a descriptive name so you can identify it in the dashboard.
          </Paragraph>
          <input
            className="w-full p-2 border rounded"
            placeholder="e.g., production-web-01, database-primary"
            value={serverName}
            onChange={(e) => setServerName(e.target.value)}
          />
          <Button
            type="primary"
            className="mt-4"
            disabled={!serverName}
            onClick={() => setCurrentStep(1)}
          >
            Continue
          </Button>
        </Card>
      ),
    },
    {
      title: 'Protection Mode',
      content: renderModeSelection(),
    },
    {
      title: 'Features',
      content: renderFeatureConfiguration(),
    },
    {
      title: 'Install',
      content: renderCommandOutput(),
    },
  ];

  return (
    <div className="max-w-4xl mx-auto p-6">
      <Title level={2}>Add New Server</Title>
      <Paragraph className="text-gray-600 mb-6">
        Configure your KernelEye agent with the protection level and features you need.
      </Paragraph>

      <Steps current={currentStep} className="mb-8">
        {steps.map((step) => (
          <Step key={step.title} title={step.title} />
        ))}
      </Steps>

      <div className="mb-8">{steps[currentStep].content}</div>

      {currentStep < 3 && currentStep > 0 && (
        <div className="flex justify-between">
          <Button onClick={() => setCurrentStep(currentStep - 1)}>
            Back
          </Button>
          {currentStep === 2 ? (
            <Button
              type="primary"
              loading={createServerMutation.isPending}
              onClick={handleGenerate}
              icon={<DownloadOutlined />}
            >
              Generate API Key & Command
            </Button>
          ) : (
            <Button type="primary" onClick={() => setCurrentStep(currentStep + 1)}>
              Continue
            </Button>
          )}
        </div>
      )}
    </div>
  );
}