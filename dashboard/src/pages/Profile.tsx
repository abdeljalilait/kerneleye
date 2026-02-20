import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import {
  Card,
  Button,
  Typography,
  Form,
  Input,
  Switch,
  Divider,
  Space,
  Row,
  Col,
  Avatar,
  Badge,
  Tabs,
  Radio,
  Alert,
  message,
  Spin,
} from 'antd';
import {
  ArrowLeft,
  User,
  Mail,
  Shield,
  Moon,
  Sun,
  Monitor,
  Bell,
  Key,
  Trash2,
  Save,
  Palette,
  Check,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { useSubscriptionStatus } from '../hooks/useQueries';

const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;

export default function Profile() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { theme, setTheme, resolvedTheme } = useTheme();
  const { data: subscription, isLoading: subLoading } = useSubscriptionStatus();
  
  const [profileForm] = Form.useForm();
  const [passwordForm] = Form.useForm();
  const [saving, setSaving] = useState(false);
  const [notifications, setNotifications] = useState({
    emailAlerts: true,
    threatAlerts: true,
    weeklyReport: false,
    productUpdates: true,
  });

  const handleSaveProfile = async (values: any) => {
    setSaving(true);
    // TODO: Implement profile update API
    setTimeout(() => {
      message.success('Profile updated successfully');
      setSaving(false);
    }, 1000);
  };

  const handleChangePassword = async (values: any) => {
    setSaving(true);
    // TODO: Implement password change API
    setTimeout(() => {
      message.success('Password changed successfully');
      passwordForm.resetFields();
      setSaving(false);
    }, 1000);
  };

  const getInitials = (email: string) => {
    return email?.split('@')[0]?.slice(0, 2).toUpperCase() || 'U';
  };

  const themeOptions = [
    { value: 'dark', label: 'Dark', icon: Moon },
    { value: 'light', label: 'Light', icon: Sun },
    { value: 'system', label: 'System', icon: Monitor },
  ];

  return (
    <div style={{ padding: '24px 48px', maxWidth: 1200, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <Button
          icon={<ArrowLeft size={16} />}
          type="text"
          onClick={() => navigate({ to: '/dashboard' })}
          style={{ marginBottom: 16 }}
        >
          Back to Dashboard
        </Button>
        <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
          Profile & Settings
        </Title>
        <Text style={{ color: 'var(--text-secondary)' }}>
          Manage your account, preferences, and application settings
        </Text>
      </div>

      <Row gutter={[24, 24]}>
        {/* Left Column - Profile Summary */}
        <Col xs={24} lg={8}>
          <Card
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              textAlign: 'center',
            }}
            bodyStyle={{ padding: 32 }}
          >
            <Badge
              dot
              color="var(--success)"
              offset={[-8, 80]}
              style={{ transform: 'scale(1.5)' }}
            >
              <Avatar
                size={100}
                style={{
                  background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                  fontSize: 36,
                  fontWeight: 600,
                }}
              >
                {user?.email ? getInitials(user.email) : 'U'}
              </Avatar>
            </Badge>

            <Title level={4} style={{ marginTop: 16, marginBottom: 4, color: 'var(--text-primary)' }}>
              {user?.email?.split('@')[0] || 'User'}
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>{user?.email}</Text>

            <div style={{ marginTop: 16 }}>
              {subLoading ? (
                <Spin size="small" />
              ) : (
                <Badge
                  count={subscription?.plan_display_name || 'No Plan'}
                  style={{
                    background: subscription?.is_trialing
                      ? '#f59e0b'
                      : subscription?.status === 'active'
                      ? '#10b981'
                      : '#6b7280',
                    fontSize: 12,
                    padding: '4px 12px',
                  }}
                />
              )}
            </div>

            <Divider style={{ borderColor: 'var(--border-subtle)', margin: '24px 0' }} />

            <Space direction="vertical" style={{ width: '100%' }}>
              <Button
                block
                icon={<Key size={16} />}
                onClick={() => navigate({ to: '/subscription' })}
              >
                Manage Subscription
              </Button>
              <Button
                block
                danger
                icon={<Trash2 size={16} />}
                style={{ marginTop: 8 }}
              >
                Delete Account
              </Button>
            </Space>
          </Card>

          {/* Quick Stats */}
          <Card
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              marginTop: 24,
            }}
            title={
              <Space>
                <Shield size={16} color="#818cf8" />
                <Text strong style={{ color: 'var(--text-primary)' }}>
                  Account Status
                </Text>
              </Space>
            }
          >
            <Space direction="vertical" style={{ width: '100%' }}>
              <Row justify="space-between">
                <Text style={{ color: 'var(--text-secondary)' }}>Member since</Text>
                <Text style={{ color: 'var(--text-primary)' }}>{new Date().toLocaleDateString()}</Text>
              </Row>
              <Row justify="space-between">
                <Text style={{ color: 'var(--text-secondary)' }}>Last login</Text>
                <Text style={{ color: 'var(--text-primary)' }}>Today</Text>
              </Row>
              <Row justify="space-between">
                <Text style={{ color: 'var(--text-secondary)' }}>Two-factor auth</Text>
                <Badge status="default" text="Disabled" />
              </Row>
            </Space>
          </Card>
        </Col>

        {/* Right Column - Settings Tabs */}
        <Col xs={24} lg={16}>
          <Card
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              minHeight: 600,
            }}
            bodyStyle={{ padding: 0 }}
          >
            <Tabs
              defaultActiveKey="profile"
              style={{ padding: '0 24px' }}
              items={[
                {
                  key: 'profile',
                  label: (
                    <Space>
                      <User size={16} />
                      Profile
                    </Space>
                  ),
                  children: (
                    <div style={{ padding: '24px 8px' }}>
                      <Title level={5} style={{ color: 'var(--text-primary)', marginBottom: 24 }}>
                        Personal Information
                      </Title>

                      <Form
                        form={profileForm}
                        layout="vertical"
                        onFinish={handleSaveProfile}
                        initialValues={{
                          email: user?.email,
                          displayName: user?.email?.split('@')[0] || '',
                        }}
                      >
                        <Row gutter={16}>
                          <Col span={12}>
                            <Form.Item
                              label={<Text style={{ color: 'var(--text-secondary)' }}>Display Name</Text>}
                              name="displayName"
                            >
                              <Input
                                prefix={<User size={16} style={{ color: 'var(--text-tertiary)' }} />}
                                placeholder="Your name"
                                size="large"
                                style={{
                                  background: 'var(--bg-tertiary)',
                                  borderColor: 'var(--border-subtle)',
                                  color: 'var(--text-primary)',
                                }}
                              />
                            </Form.Item>
                          </Col>
                          <Col span={12}>
                            <Form.Item
                              label={<Text style={{ color: 'var(--text-secondary)' }}>Email</Text>}
                              name="email"
                            >
                              <Input
                                prefix={<Mail size={16} style={{ color: 'var(--text-tertiary)' }} />}
                                disabled
                                size="large"
                                style={{
                                  background: 'var(--bg-tertiary)',
                                  borderColor: 'var(--border-subtle)',
                                  color: 'var(--text-primary)',
                                }}
                              />
                            </Form.Item>
                          </Col>
                        </Row>

                        <Form.Item
                          label={<Text style={{ color: 'var(--text-secondary)' }}>Bio</Text>}
                          name="bio"
                        >
                          <Input.TextArea
                            rows={4}
                            placeholder="Tell us about yourself..."
                            style={{
                              background: 'var(--bg-tertiary)',
                              borderColor: 'var(--border-subtle)',
                              color: 'var(--text-primary)',
                              resize: 'none',
                            }}
                          />
                        </Form.Item>

                        <Form.Item>
                          <Button
                            type="primary"
                            htmlType="submit"
                            icon={<Save size={16} />}
                            loading={saving}
                            size="large"
                          >
                            Save Changes
                          </Button>
                        </Form.Item>
                      </Form>

                      <Divider style={{ borderColor: 'var(--border-subtle)', margin: '32px 0' }} />

                      <Title level={5} style={{ color: 'var(--text-primary)', marginBottom: 24 }}>
                        Change Password
                      </Title>

                      <Form
                        form={passwordForm}
                        layout="vertical"
                        onFinish={handleChangePassword}
                      >
                        <Form.Item
                          label={<Text style={{ color: 'var(--text-secondary)' }}>Current Password</Text>}
                          name="currentPassword"
                          rules={[{ required: true, message: 'Please enter current password' }]}
                        >
                          <Input.Password
                            placeholder="Enter current password"
                            size="large"
                            style={{
                              background: 'var(--bg-tertiary)',
                              borderColor: 'var(--border-subtle)',
                              color: 'var(--text-primary)',
                            }}
                          />
                        </Form.Item>

                        <Row gutter={16}>
                          <Col span={12}>
                            <Form.Item
                              label={<Text style={{ color: 'var(--text-secondary)' }}>New Password</Text>}
                              name="newPassword"
                              rules={[{ required: true, message: 'Please enter new password' }]}
                            >
                              <Input.Password
                                placeholder="Enter new password"
                                size="large"
                                style={{
                                  background: 'var(--bg-tertiary)',
                                  borderColor: 'var(--border-subtle)',
                                  color: 'var(--text-primary)',
                                }}
                              />
                            </Form.Item>
                          </Col>
                          <Col span={12}>
                            <Form.Item
                              label={<Text style={{ color: 'var(--text-secondary)' }}>Confirm Password</Text>}
                              name="confirmPassword"
                              rules={[
                                { required: true, message: 'Please confirm password' },
                                ({ getFieldValue }) => ({
                                  validator(_, value) {
                                    if (!value || getFieldValue('newPassword') === value) {
                                      return Promise.resolve();
                                    }
                                    return Promise.reject(new Error('Passwords do not match'));
                                  },
                                }),
                              ]}
                            >
                              <Input.Password
                                placeholder="Confirm new password"
                                size="large"
                                style={{
                                  background: 'var(--bg-tertiary)',
                                  borderColor: 'var(--border-subtle)',
                                  color: 'var(--text-primary)',
                                }}
                              />
                            </Form.Item>
                          </Col>
                        </Row>

                        <Form.Item>
                          <Button
                            type="primary"
                            htmlType="submit"
                            icon={<Key size={16} />}
                            loading={saving}
                            size="large"
                          >
                            Update Password
                          </Button>
                        </Form.Item>
                      </Form>
                    </div>
                  ),
                },
                {
                  key: 'appearance',
                  label: (
                    <Space>
                      <Palette size={16} />
                      Appearance
                    </Space>
                  ),
                  children: (
                    <div style={{ padding: '24px 8px' }}>
                      <Title level={5} style={{ color: 'var(--text-primary)', marginBottom: 24 }}>
                        Theme
                      </Title>

                      <Paragraph style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
                        Choose your preferred theme. The system theme will automatically match your device's settings.
                      </Paragraph>

                      <Radio.Group
                        value={theme}
                        onChange={(e) => setTheme(e.target.value)}
                        style={{ width: '100%' }}
                      >
                        <Row gutter={16}>
                          {themeOptions.map((option) => {
                            const Icon = option.icon;
                            const isSelected = theme === option.value;
                            return (
                              <Col span={8} key={option.value}>
                                <Radio.Button
                                  value={option.value}
                                  style={{
                                    width: '100%',
                                    height: 'auto',
                                    padding: '20px',
                                    borderRadius: 12,
                                    background: isSelected
                                      ? 'linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(139, 92, 246, 0.1))'
                                      : 'var(--bg-tertiary)',
                                    border: `2px solid ${
                                      isSelected ? '#6366f1' : 'var(--border-subtle)'
                                    }`,
                                  }}
                                >
                                  <Space direction="vertical" align="center" style={{ width: '100%' }}>
                                    <div
                                      style={{
                                        width: 48,
                                        height: 48,
                                        borderRadius: 12,
                                        background: isSelected
                                          ? 'linear-gradient(135deg, #6366f1, #8b5cf6)'
                                          : 'var(--bg-secondary)',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                      }}
                                    >
                                      <Icon
                                        size={24}
                                        color={isSelected ? 'white' : 'var(--text-secondary)'}
                                      />
                                    </div>
                                    <Text
                                      strong
                                      style={{
                                        color: isSelected
                                          ? 'var(--text-primary)'
                                          : 'var(--text-secondary)',
                                      }}
                                    >
                                      {option.label}
                                    </Text>
                                    {isSelected && (
                                      <Badge
                                        count={<Check size={12} />}
                                        style={{
                                          background: '#10b981',
                                          color: 'white',
                                        }}
                                      />
                                    )}
                                  </Space>
                                </Radio.Button>
                              </Col>
                            );
                          })}
                        </Row>
                      </Radio.Group>

                      <Alert
                        message={`Current theme: ${resolvedTheme === 'dark' ? 'Dark' : 'Light'} Mode`}
                        description={
                          theme === 'system'
                            ? 'Using your system preference'
                            : `Manually set to ${theme} mode`
                        }
                        type="info"
                        showIcon
                        style={{
                          marginTop: 24,
                          background: 'rgba(99, 102, 241, 0.1)',
                          border: '1px solid rgba(99, 102, 241, 0.3)',
                        }}
                      />
                    </div>
                  ),
                },
                {
                  key: 'notifications',
                  label: (
                    <Space>
                      <Bell size={16} />
                      Notifications
                    </Space>
                  ),
                  children: (
                    <div style={{ padding: '24px 8px' }}>
                      <Title level={5} style={{ color: 'var(--text-primary)', marginBottom: 24 }}>
                        Email Notifications
                      </Title>

                      <Space direction="vertical" style={{ width: '100%' }} size={24}>
                        <Card
                          variant="borderless"
                          style={{
                            background: 'var(--bg-tertiary)',
                            border: '1px solid var(--border-subtle)',
                          }}
                          bodyStyle={{ padding: 16 }}
                        >
                          <Row justify="space-between" align="middle">
                            <Space direction="vertical" size={4}>
                              <Text strong style={{ color: 'var(--text-primary)' }}>
                                Security Alerts
                              </Text>
                              <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
                                Get notified when threats are detected
                              </Text>
                            </Space>
                            <Switch
                              checked={notifications.threatAlerts}
                              onChange={(checked) =>
                                setNotifications({ ...notifications, threatAlerts: checked })
                              }
                            />
                          </Row>
                        </Card>

                        <Card
                          variant="borderless"
                          style={{
                            background: 'var(--bg-tertiary)',
                            border: '1px solid var(--border-subtle)',
                          }}
                          bodyStyle={{ padding: 16 }}
                        >
                          <Row justify="space-between" align="middle">
                            <Space direction="vertical" size={4}>
                              <Text strong style={{ color: 'var(--text-primary)' }}>
                                Email Alerts
                              </Text>
                              <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
                                Receive alerts via email
                              </Text>
                            </Space>
                            <Switch
                              checked={notifications.emailAlerts}
                              onChange={(checked) =>
                                setNotifications({ ...notifications, emailAlerts: checked })
                              }
                            />
                          </Row>
                        </Card>

                        <Card
                          variant="borderless"
                          style={{
                            background: 'var(--bg-tertiary)',
                            border: '1px solid var(--border-subtle)',
                          }}
                          bodyStyle={{ padding: 16 }}
                        >
                          <Row justify="space-between" align="middle">
                            <Space direction="vertical" size={4}>
                              <Text strong style={{ color: 'var(--text-primary)' }}>
                                Weekly Report
                              </Text>
                              <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
                                Get a summary of your security status every week
                              </Text>
                            </Space>
                            <Switch
                              checked={notifications.weeklyReport}
                              onChange={(checked) =>
                                setNotifications({ ...notifications, weeklyReport: checked })
                              }
                            />
                          </Row>
                        </Card>

                        <Card
                          variant="borderless"
                          style={{
                            background: 'var(--bg-tertiary)',
                            border: '1px solid var(--border-subtle)',
                          }}
                          bodyStyle={{ padding: 16 }}
                        >
                          <Row justify="space-between" align="middle">
                            <Space direction="vertical" size={4}>
                              <Text strong style={{ color: 'var(--text-primary)' }}>
                                Product Updates
                              </Text>
                              <Text style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
                                News about new features and improvements
                              </Text>
                            </Space>
                            <Switch
                              checked={notifications.productUpdates}
                              onChange={(checked) =>
                                setNotifications({ ...notifications, productUpdates: checked })
                              }
                            />
                          </Row>
                        </Card>
                      </Space>

                      <Button
                        type="primary"
                        icon={<Save size={16} />}
                        style={{ marginTop: 24 }}
                        onClick={() => message.success('Notification preferences saved')}
                      >
                        Save Preferences
                      </Button>
                    </div>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
