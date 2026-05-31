import { useState } from 'react';
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
  Alert,
  message,
} from 'antd';
import {
  User,
  Mail,
  Shield,
  Moon,
  Sun,
  Monitor,
  Bell,
  Trash2,
  Save,
  Palette,
  Settings,
  Key,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';

const { Title, Text } = Typography;

export default function Profile() {
  const { user } = useAuth();
  const { theme, setTheme, resolvedTheme } = useTheme();
  
  const [profileForm] = Form.useForm();
  const [saving, setSaving] = useState(false);
  const [activeSection, setActiveSection] = useState<'general' | 'appearance' | 'notifications'>('general');
  const [notifications, setNotifications] = useState({
    emailAlerts: true,
    threatAlerts: true,
    weeklyReport: false,
    productUpdates: true,
  });

  const handleSaveProfile = async () => {
    setSaving(true);
    setTimeout(() => {
      message.success('Profile updated successfully');
      setSaving(false);
    }, 1000);
  };

  const getInitials = (email: string) => {
    return email?.split('@')[0]?.slice(0, 2).toUpperCase() || 'U';
  };

  const themeOptions = [
    { value: 'dark', label: 'Dark', icon: Moon, color: '#6366f1' },
    { value: 'light', label: 'Light', icon: Sun, color: '#f59e0b' },
    { value: 'system', label: 'System', icon: Monitor, color: '#10b981' },
  ];

  const menuItems = [
    { key: 'general', label: 'General', icon: Settings },
    { key: 'appearance', label: 'Appearance', icon: Palette },
    { key: 'notifications', label: 'Notifications', icon: Bell },
  ];

  return (
    <div>
      {/* Header */}
      <Row justify="space-between" align="middle" style={{ marginBottom: 32 }}>
        <Col>
          <Space direction="vertical" size={4}>
            <Title level={2} style={{ margin: 0, color: 'var(--kerneleye-colorText)' }}>
              Profile & Settings
            </Title>
            <Text style={{ color: 'var(--kerneleye-colorTextSecondary)' }}>
              Manage your account, preferences, and application settings
            </Text>
          </Space>
        </Col>
      </Row>

      <Row gutter={[24, 24]}>
        {/* Left Column - Profile Summary & Navigation */}
        <Col xs={24} lg={7}>
          {/* Profile Card */}
          <Card
            variant="borderless"
            style={{
              background: 'var(--kerneleye-colorBgContainer)',
              border: '1px solid var(--kerneleye-colorBorderSecondary)',
              borderRadius: 'var(--kerneleye-borderRadiusLG)',
              marginBottom: 24,
            }}
            bodyStyle={{ padding: 24 }}
          >
            <div style={{ textAlign: 'center', marginBottom: 20 }}>
              <Avatar
                size={80}
                style={{
                  background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                  fontSize: 28,
                  fontWeight: 600,
                }}
              >
                {user?.email ? getInitials(user.email) : 'U'}
              </Avatar>
            </div>

            <div style={{ textAlign: 'center' }}>
              <Text 
                strong 
                style={{ 
                  fontSize: 16, 
                  color: 'var(--kerneleye-colorText)', 
                  display: 'block',
                  marginBottom: 4,
                }}
              >
                {user?.email?.split('@')[0] || 'User'}
              </Text>
              <Text style={{ color: 'var(--kerneleye-colorTextSecondary)', fontSize: 13 }}>
                {user?.email}
              </Text>
            </div>

            <Divider style={{ borderColor: 'var(--kerneleye-colorBorderSecondary)', margin: '20px 0' }} />

            <Space direction="vertical" style={{ width: '100%' }} size={8}>
              <Button
                block
                danger
                icon={<Trash2 size={16} />}
              >
                Delete Account
              </Button>
            </Space>
          </Card>

          {/* Settings Navigation */}
          <Card
            variant="borderless"
            style={{
              background: 'var(--kerneleye-colorBgContainer)',
              border: '1px solid var(--kerneleye-colorBorderSecondary)',
              borderRadius: 'var(--kerneleye-borderRadiusLG)',
            }}
            bodyStyle={{ padding: 8 }}
          >
            <Space direction="vertical" style={{ width: '100%' }} size={4}>
              {menuItems.map((item) => {
                const Icon = item.icon;
                const isActive = activeSection === item.key;
                return (
                  <Button
                    key={item.key}
                    type="text"
                    block
                    onClick={() => setActiveSection(item.key as any)}
                    style={{
                      justifyContent: 'flex-start',
                      height: 44,
                      background: isActive ? 'var(--kerneleye-colorFillAlter)' : 'transparent',
                      color: isActive ? 'var(--kerneleye-colorText)' : 'var(--kerneleye-colorTextSecondary)',
                      fontWeight: isActive ? 600 : 400,
                      borderRadius: 8,
                    }}
                  >
                    <Icon 
                      size={18} 
                      style={{ 
                        marginRight: 12,
                        color: isActive ? '#6366f1' : 'var(--kerneleye-colorTextTertiary)',
                      }} 
                    />
                    {item.label}
                  </Button>
                );
              })}
            </Space>
          </Card>
        </Col>

        {/* Right Column - Settings Content */}
        <Col xs={24} lg={17}>
          {/* General Settings */}
          {activeSection === 'general' && (
            <>
              {/* Profile Information Card */}
              <Card
                variant="borderless"
                style={{
                  background: 'var(--kerneleye-colorBgContainer)',
                  border: '1px solid var(--kerneleye-colorBorderSecondary)',
                  borderRadius: 'var(--kerneleye-borderRadiusLG)',
                  marginBottom: 24,
                }}
                title={
                  <Space>
                    <div 
                      style={{
                        width: 36,
                        height: 36,
                        background: 'rgba(99, 102, 241, 0.15)',
                        borderRadius: 10,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <User size={18} color="#818cf8" />
                    </div>
                    <Text strong style={{ color: 'var(--kerneleye-colorText)', fontSize: 16 }}>
                      Profile Information
                    </Text>
                  </Space>
                }
                bodyStyle={{ padding: 24 }}
              >
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
                    <Col xs={24} md={12}>
                      <Form.Item
                        label={<Text style={{ color: 'var(--kerneleye-colorTextSecondary)' }}>Display Name</Text>}
                        name="displayName"
                      >
                        <Input
                          prefix={<User size={16} style={{ color: 'var(--kerneleye-colorTextTertiary)' }} />}
                          placeholder="Your name"
                          size="large"
                          style={{
                            background: 'var(--kerneleye-colorFillAlter)',
                            borderColor: 'var(--kerneleye-colorBorderSecondary)',
                            color: 'var(--kerneleye-colorText)',
                          }}
                        />
                      </Form.Item>
                    </Col>
                    <Col xs={24} md={12}>
                      <Form.Item
                        label={<Text style={{ color: 'var(--kerneleye-colorTextSecondary)' }}>Email</Text>}
                        name="email"
                      >
                        <Input
                          prefix={<Mail size={16} style={{ color: 'var(--kerneleye-colorTextTertiary)' }} />}
                          disabled
                          size="large"
                          style={{
                            background: 'var(--kerneleye-colorFillAlter)',
                            borderColor: 'var(--kerneleye-colorBorderSecondary)',
                            color: 'var(--kerneleye-colorText)',
                          }}
                        />
                      </Form.Item>
                    </Col>
                  </Row>

                  <Form.Item
                    label={<Text style={{ color: 'var(--kerneleye-colorTextSecondary)' }}>Bio</Text>}
                    name="bio"
                  >
                    <Input.TextArea
                      rows={3}
                      placeholder="Tell us about yourself..."
                      style={{
                        background: 'var(--kerneleye-colorFillAlter)',
                        borderColor: 'var(--kerneleye-colorBorderSecondary)',
                        color: 'var(--kerneleye-colorText)',
                        resize: 'none',
                      }}
                    />
                  </Form.Item>

                  <Form.Item style={{ marginBottom: 0 }}>
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
              </Card>

              {/* Security Card */}
              <Card
                variant="borderless"
                style={{
                  background: 'var(--kerneleye-colorBgContainer)',
                  border: '1px solid var(--kerneleye-colorBorderSecondary)',
                  borderRadius: 'var(--kerneleye-borderRadiusLG)',
                }}
                title={
                  <Space>
                    <div 
                      style={{
                        width: 36,
                        height: 36,
                        background: 'rgba(16, 185, 129, 0.15)',
                        borderRadius: 10,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <Shield size={18} color="#10b981" />
                    </div>
                    <Text strong style={{ color: 'var(--kerneleye-colorText)', fontSize: 16 }}>
                      Security
                    </Text>
                  </Space>
                }
                bodyStyle={{ padding: 24 }}
              >
                <Space direction="vertical" style={{ width: '100%' }} size={16}>
                  <Row justify="space-between" align="middle">
                    <Space direction="vertical" size={4}>
                      <Text strong style={{ color: 'var(--kerneleye-colorText)' }}>
                        Two-Factor Authentication
                      </Text>
                      <Text style={{ color: 'var(--kerneleye-colorTextSecondary)', fontSize: 13 }}>
                        Add an extra layer of security to your account
                      </Text>
                    </Space>
                    <Badge status="default" text="Disabled" style={{ color: 'var(--kerneleye-colorTextSecondary)' }} />
                  </Row>
                  <Divider style={{ borderColor: 'var(--kerneleye-colorBorderSecondary)', margin: '8px 0' }} />
                  <Row justify="space-between" align="middle">
                    <Space direction="vertical" size={4}>
                      <Text strong style={{ color: 'var(--kerneleye-colorText)' }}>
                        Change Password
                      </Text>
                      <Text style={{ color: 'var(--kerneleye-colorTextSecondary)', fontSize: 13 }}>
                        Update your password regularly for better security
                      </Text>
                    </Space>
                    <Button type="primary" ghost icon={<Key size={16} />}>
                      Update
                    </Button>
                  </Row>
                </Space>
              </Card>
            </>
          )}

          {/* Appearance Settings */}
          {activeSection === 'appearance' && (
            <Card
              variant="borderless"
              style={{
                background: 'var(--kerneleye-colorBgContainer)',
                border: '1px solid var(--kerneleye-colorBorderSecondary)',
                borderRadius: 'var(--kerneleye-borderRadiusLG)',
              }}
              title={
                <Space>
                  <div 
                    style={{
                      width: 36,
                      height: 36,
                      background: 'rgba(139, 92, 246, 0.15)',
                      borderRadius: 10,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Palette size={18} color="#8b5cf6" />
                  </div>
                  <Text strong style={{ color: 'var(--kerneleye-colorText)', fontSize: 16 }}>
                    Appearance
                  </Text>
                </Space>
              }
              bodyStyle={{ padding: 24 }}
            >
              <Text style={{ color: 'var(--kerneleye-colorTextSecondary)', display: 'block', marginBottom: 20 }}>
                Choose your preferred theme. The system theme will automatically match your device's settings.
              </Text>

              <Row gutter={[16, 16]}>
                {themeOptions.map((option) => {
                  const Icon = option.icon;
                  const isSelected = theme === option.value;
                  return (
                    <Col xs={24} sm={8} key={option.value}>
                      <Card
                        variant="borderless"
                        onClick={() => setTheme(option.value as any)}
                        style={{
                          background: isSelected 
                            ? `${option.color}15`
                            : 'var(--kerneleye-colorFillAlter)',
                          border: `2px solid ${isSelected ? option.color : 'var(--kerneleye-colorBorderSecondary)'}`,
                          borderRadius: 12,
                          cursor: 'pointer',
                          transition: 'all 0.2s',
                        }}
                        bodyStyle={{ padding: 20, textAlign: 'center' }}
                      >
                        <div
                          style={{
                            width: 48,
                            height: 48,
                            borderRadius: 12,
                            background: isSelected ? option.color : 'var(--kerneleye-colorBgContainer)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            margin: '0 auto 12px',
                          }}
                        >
                          <Icon size={24} color={isSelected ? 'white' : 'var(--kerneleye-colorTextSecondary)'} />
                        </div>
                        <Text
                          strong
                          style={{
                            color: isSelected ? 'var(--kerneleye-colorText)' : 'var(--kerneleye-colorTextSecondary)',
                            display: 'block',
                          }}
                        >
                          {option.label}
                        </Text>
                        {isSelected && (
                          <CheckCircle2 
                            size={16} 
                            color="#10b981" 
                            style={{ marginTop: 8 }} 
                          />
                        )}
                      </Card>
                    </Col>
                  );
                })}
              </Row>

              <Alert
                message={`Current theme: ${resolvedTheme === 'dark' ? 'Dark' : 'Light'} Mode`}
                description={
                  theme === 'system'
                    ? 'Using your system preference'
                    : `Manually set to ${theme} mode`
                }
                type="info"
                showIcon
                icon={<CheckCircle2 size={16} />}
                style={{
                  marginTop: 24,
                  background: 'rgba(99, 102, 241, 0.1)',
                  border: '1px solid rgba(99, 102, 241, 0.3)',
                  borderRadius: 'var(--kerneleye-borderRadiusLG)',
                }}
              />
            </Card>
          )}

          {/* Notifications Settings */}
          {activeSection === 'notifications' && (
            <Card
              variant="borderless"
              style={{
                background: 'var(--kerneleye-colorBgContainer)',
                border: '1px solid var(--kerneleye-colorBorderSecondary)',
                borderRadius: 'var(--kerneleye-borderRadiusLG)',
              }}
              title={
                <Space>
                  <div 
                    style={{
                      width: 36,
                      height: 36,
                      background: 'rgba(245, 158, 11, 0.15)',
                      borderRadius: 10,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Bell size={18} color="#f59e0b" />
                  </div>
                  <Text strong style={{ color: 'var(--kerneleye-colorText)', fontSize: 16 }}>
                    Notifications
                  </Text>
                </Space>
              }
              bodyStyle={{ padding: 24 }}
            >
              <Space direction="vertical" style={{ width: '100%' }} size={16}>
                {[
                  {
                    key: 'threatAlerts',
                    title: 'Security Alerts',
                    description: 'Get notified when threats are detected on your servers',
                    icon: AlertCircle,
                    color: '#ef4444',
                  },
                  {
                    key: 'emailAlerts',
                    title: 'Email Alerts',
                    description: 'Receive critical alerts via email',
                    icon: Mail,
                    color: '#6366f1',
                  },
                  {
                    key: 'weeklyReport',
                    title: 'Weekly Report',
                    description: 'Get a summary of your security status every week',
                    icon: Shield,
                    color: '#10b981',
                  },
                  {
                    key: 'productUpdates',
                    title: 'Product Updates',
                    description: 'News about new features and improvements',
                    icon: CheckCircle2,
                    color: '#8b5cf6',
                  },
                ].map((item) => {
                  const Icon = item.icon;
                  return (
                    <Card
                      key={item.key}
                      variant="borderless"
                      style={{
                        background: 'var(--kerneleye-colorFillAlter)',
                        border: '1px solid var(--kerneleye-colorBorderSecondary)',
                        borderRadius: 12,
                      }}
                      bodyStyle={{ padding: 16 }}
                    >
                      <Row justify="space-between" align="middle">
                        <Space size={12}>
                          <div
                            style={{
                              width: 40,
                              height: 40,
                              borderRadius: 10,
                              background: `${item.color}15`,
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                            }}
                          >
                            <Icon size={20} color={item.color} />
                          </div>
                          <Space direction="vertical" size={2}>
                            <Text strong style={{ color: 'var(--kerneleye-colorText)' }}>
                              {item.title}
                            </Text>
                            <Text style={{ color: 'var(--kerneleye-colorTextSecondary)', fontSize: 13 }}>
                              {item.description}
                            </Text>
                          </Space>
                        </Space>
                        <Switch
                          checked={notifications[item.key as keyof typeof notifications]}
                          onChange={(checked) =>
                            setNotifications({ ...notifications, [item.key]: checked })
                          }
                        />
                      </Row>
                    </Card>
                  );
                })}
              </Space>

              <Button
                type="primary"
                icon={<Save size={16} />}
                size="large"
                style={{ marginTop: 24 }}
                onClick={() => message.success('Notification preferences saved')}
              >
                Save Preferences
              </Button>
            </Card>
          )}
        </Col>
      </Row>
    </div>
  );
}
