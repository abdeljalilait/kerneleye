import { useRouter, Link } from '@tanstack/react-router'
import { Shield, Eye, EyeOff, Lock, Mail, ArrowRight } from 'lucide-react'
import { Form, Input, Button, Card, Typography, Alert, Space, Divider } from 'antd'
import { useLogin } from '../hooks/useQueries'
import { useState } from 'react'

const { Title, Text } = Typography

export default function Login() {
  const router = useRouter()
  const loginMutation = useLogin()
  const [showPassword, setShowPassword] = useState(false)

  const onFinish = async (values: any) => {
    loginMutation.mutate(
      { email: values.email, password: values.password },
      {
        onSuccess: (data) => {
          localStorage.setItem('kerneleye_token', data.token)
          router.navigate({ to: '/dashboard' })
        },
      }
    )
  }

  return (
    <div 
      style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center', 
        background: 'var(--bg-primary)',
        padding: 24,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background Effects */}
      <div 
        style={{
          position: 'absolute',
          top: '-20%',
          right: '-10%',
          width: 600,
          height: 600,
          background: 'radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, transparent 70%)',
          pointerEvents: 'none',
        }}
      />
      <div 
        style={{
          position: 'absolute',
          bottom: '-20%',
          left: '-10%',
          width: 500,
          height: 500,
          background: 'radial-gradient(circle, rgba(6, 182, 212, 0.1) 0%, transparent 70%)',
          pointerEvents: 'none',
        }}
      />
      
      {/* Grid Pattern */}
      <div 
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: `
            linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
          pointerEvents: 'none',
        }}
      />

      <div style={{ width: '100%', maxWidth: 420, position: 'relative', zIndex: 1 }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div 
            style={{ 
              display: 'inline-flex', 
              alignItems: 'center', 
              justifyContent: 'center', 
              width: 80, 
              height: 80, 
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              borderRadius: 20, 
              marginBottom: 24,
              boxShadow: '0 8px 32px rgba(99, 102, 241, 0.4)',
            }}
          >
            <Shield size={40} color="white" />
          </div>
          <Title level={2} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>
            KernelEye
          </Title>
          <Text style={{ color: 'var(--text-secondary)', fontSize: 15 }}>
            Security Intelligence Dashboard
          </Text>
        </div>

        {/* Login Card */}
        <Card 
          variant="borderless" 
          style={{ 
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-xl)',
            backdropFilter: 'blur(10px)',
            boxShadow: '0 20px 50px rgba(0, 0, 0, 0.4)',
          }}
          bodyStyle={{ padding: 40 }}
        >
          <Space direction="vertical" size={24} style={{ width: '100%' }}>
            <div>
              <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>
                Welcome back
              </Title>
              <Text style={{ color: 'var(--text-tertiary)' }}>
                Enter your credentials to access the dashboard
              </Text>
            </div>

            {loginMutation.error && (
              <Alert 
                message={(loginMutation.error as any).response?.data?.error || 'Login failed'} 
                type="error" 
                showIcon 
                style={{ 
                  background: 'rgba(239, 68, 68, 0.1)', 
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                }}
              />
            )}

            <Form
              layout="vertical"
              onFinish={onFinish}
              initialValues={{ email: '', password: '' }}
              style={{ marginTop: 8 }}
            >
              <Form.Item
                label={<Text style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>Email</Text>}
                name="email"
                rules={[
                  { required: true, message: 'Please input your email!' },
                  { type: 'email', message: 'Please enter a valid email!' }
                ]}
              >
                <Input 
                  placeholder="you@example.com" 
                  size="large"
                  prefix={<Mail size={18} color="var(--text-tertiary)" style={{ marginRight: 8 }} />}
                  style={{
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    height: 48,
                  }}
                />
              </Form.Item>

              <Form.Item
                label={
                  <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                    <Text style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>Password</Text>
                    <Link to="/forgot-password" style={{ fontSize: 13 }}>
                      Forgot password?
                    </Link>
                  </div>
                }
                name="password"
                rules={[{ required: true, message: 'Please input your password!' }]}
              >
                <Input 
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••" 
                  size="large"
                  prefix={<Lock size={18} color="var(--text-tertiary)" style={{ marginRight: 8 }} />}
                  suffix={
                    <Button
                      type="text"
                      icon={showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      onClick={() => setShowPassword(!showPassword)}
                      style={{ color: 'var(--text-tertiary)' }}
                    />
                  }
                  style={{
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    height: 48,
                  }}
                />
              </Form.Item>

              <Form.Item style={{ marginTop: 24 }}>
                <Button 
                  type="primary" 
                  htmlType="submit" 
                  block 
                  size="large" 
                  loading={loginMutation.isPending}
                  style={{
                    height: 48,
                    fontSize: 16,
                    fontWeight: 600,
                    borderRadius: 'var(--radius-md)',
                  }}
                >
                  Sign In
                  <ArrowRight size={18} style={{ marginLeft: 8 }} />
                </Button>
              </Form.Item>
            </Form>

            <Divider style={{ borderColor: 'var(--border-subtle)', margin: '8px 0' }}>
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                OR
              </Text>
            </Divider>

            <div style={{ textAlign: 'center' }}>
              <Text type="secondary">
                Don't have an account?{' '}
                <Link to="/register" style={{ fontWeight: 600 }}>
                  Create one
                </Link>
              </Text>
            </div>
          </Space>
        </Card>

        {/* Demo Credentials */}
        <Card
          variant="borderless"
          style={{
            background: 'rgba(16, 185, 129, 0.08)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            borderRadius: 'var(--radius-lg)',
            marginTop: 24,
          }}
          bodyStyle={{ padding: '16px 20px' }}
        >
          <Space align="start">
            <div 
              style={{
                width: 32,
                height: 32,
                background: 'rgba(16, 185, 129, 0.15)',
                borderRadius: 8,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Text style={{ color: '#10b981', fontWeight: 700 }}>?</Text>
            </div>
            <div>
              <Text strong style={{ color: '#10b981', fontSize: 13 }}>
                Demo Credentials
              </Text>
              <br />
              <Text style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                Email: demo@kerneleye.io<br />
                Password: demo
              </Text>
            </div>
          </Space>
        </Card>

        {/* Footer */}
        <div style={{ textAlign: 'center', marginTop: 32 }}>
          <Text style={{ color: 'var(--text-muted)', fontSize: 12 }}>
            © 2026 KernelEye. All rights reserved.
          </Text>
        </div>
      </div>
    </div>
  )
}
