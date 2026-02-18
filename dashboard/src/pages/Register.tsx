import { useRouter, Link } from '@tanstack/react-router'
import { Shield, Eye, EyeOff, Lock, Mail, User, ArrowRight } from 'lucide-react'
import { Form, Input, Button, Card, Typography, Alert, Space, Progress } from 'antd'
import { useRegister } from '../hooks/useQueries'
import { useState } from 'react'

const { Title, Text } = Typography

export default function Register() {
  const router = useRouter()
  const registerMutation = useRegister()
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [passwordStrength, setPasswordStrength] = useState(0)
  const [form] = Form.useForm()

  const checkPasswordStrength = (value: string) => {
    let strength = 0
    if (value.length >= 6) strength += 25
    if (value.length >= 10) strength += 25
    if (/[A-Z]/.test(value)) strength += 25
    if (/[0-9!@#$%^&*]/.test(value)) strength += 25
    setPasswordStrength(strength)
  }

  const onFinish = async (values: any) => {
    registerMutation.mutate(
      { email: values.email, password: values.password },
      {
        onSuccess: (data) => {
          localStorage.setItem('kerneleye_token', data.token)
          router.navigate({ to: '/dashboard' })
        },
      }
    )
  }

  const getPasswordStatus = () => {
    if (passwordStrength === 0) return 'exception'
    if (passwordStrength < 50) return 'exception'
    if (passwordStrength < 75) return 'normal'
    return 'success'
  }

  const getPasswordColor = () => {
    if (passwordStrength < 50) return '#ef4444'
    if (passwordStrength < 75) return '#f59e0b'
    return '#10b981'
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

      <div style={{ width: '100%', maxWidth: 440, position: 'relative', zIndex: 1 }}>
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
            Create your security dashboard account
          </Text>
        </div>

        {/* Register Card */}
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
                Create Account
              </Title>
              <Text style={{ color: 'var(--text-tertiary)' }}>
                Join thousands of security professionals
              </Text>
            </div>

            {registerMutation.error && (
              <Alert 
                message={(registerMutation.error as any).response?.data?.error || 'Registration failed'} 
                type="error" 
                showIcon 
                style={{ 
                  background: 'rgba(239, 68, 68, 0.1)', 
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                }}
              />
            )}

            <Form
              form={form}
              layout="vertical"
              onFinish={onFinish}
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
                label={<Text style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>Password</Text>}
                name="password"
                rules={[
                  { required: true, message: 'Please input your password!' },
                  { min: 6, message: 'Password must be at least 6 characters' }
                ]}
              >
                <Input 
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Create a strong password" 
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
                  onChange={(e) => checkPasswordStrength(e.target.value)}
                  style={{
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    height: 48,
                  }}
                />
              </Form.Item>

              {/* Password Strength Indicator */}
              <Form.Item style={{ marginTop: -12, marginBottom: 16 }}>
                <Progress 
                  percent={passwordStrength} 
                  size="small" 
                  showInfo={false}
                  strokeColor={getPasswordColor()}
                  trailColor="rgba(255, 255, 255, 0.05)"
                />
                <Text style={{ fontSize: 11, color: getPasswordColor() }}>
                  {passwordStrength === 0 ? 'Enter password' : 
                   passwordStrength < 50 ? 'Weak password' : 
                   passwordStrength < 75 ? 'Medium strength' : 'Strong password'}
                </Text>
              </Form.Item>

              <Form.Item
                label={<Text style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>Confirm Password</Text>}
                name="confirmPassword"
                dependencies={['password']}
                rules={[
                  { required: true, message: 'Please confirm your password!' },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      if (!value || getFieldValue('password') === value) {
                        return Promise.resolve()
                      }
                      return Promise.reject(new Error('Passwords do not match!'))
                    },
                  }),
                ]}
              >
                <Input 
                  type={showConfirmPassword ? 'text' : 'password'}
                  placeholder="Confirm your password" 
                  size="large"
                  prefix={<Lock size={18} color="var(--text-tertiary)" style={{ marginRight: 8 }} />}
                  suffix={
                    <Button
                      type="text"
                      icon={showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
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
                  loading={registerMutation.isPending}
                  style={{
                    height: 48,
                    fontSize: 16,
                    fontWeight: 600,
                    borderRadius: 'var(--radius-md)',
                  }}
                >
                  Create Account
                  <ArrowRight size={18} style={{ marginLeft: 8 }} />
                </Button>
              </Form.Item>
            </Form>

            <div style={{ textAlign: 'center' }}>
              <Text type="secondary">
                Already have an account?{' '}
                <Link to="/login" style={{ fontWeight: 600 }}>
                  Sign in
                </Link>
              </Text>
            </div>
          </Space>
        </Card>

        {/* Footer */}
        <div style={{ textAlign: 'center', marginTop: 32 }}>
          <Text style={{ color: 'var(--text-muted)', fontSize: 12 }}>
            By creating an account, you agree to our Terms of Service and Privacy Policy
          </Text>
        </div>
      </div>
    </div>
  )
}
