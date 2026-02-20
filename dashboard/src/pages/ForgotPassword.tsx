import { Link } from '@tanstack/react-router'
import { Shield, Mail, ArrowLeft } from 'lucide-react'
import { Form, Input, Button, Card, Typography, Alert, Space } from 'antd'
import { useState } from 'react'
import { publicApi } from '../api/client'

const { Title, Text } = Typography

export default function ForgotPassword() {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isSuccess, setIsSuccess] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const onFinish = async (values: { email: string }) => {
    setIsSubmitting(true)
    setError(null)
    
    try {
      await publicApi.post('/auth/forgot-password', { email: values.email })
      setIsSuccess(true)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to send reset email. Please try again.')
    } finally {
      setIsSubmitting(false)
    }
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
      }}
    >
      <div style={{ width: '100%', maxWidth: 420 }}>
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
            }}
          >
            <Shield size={40} color="white" />
          </div>
          <Title level={2} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>
            KernelEye
          </Title>
        </div>

        {/* Forgot Password Card */}
        <Card 
          variant="borderless" 
          style={{ 
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-xl)',
          }}
          bodyStyle={{ padding: 40 }}
        >
          <Space direction="vertical" size={24} style={{ width: '100%' }}>
            <div>
              <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>
                Forgot Password?
              </Title>
              <Text style={{ color: 'var(--text-tertiary)' }}>
                Enter your email address and we'll send you a link to reset your password.
              </Text>
            </div>

            {isSuccess ? (
              <Alert
                message="Check your email"
                description="If an account exists with this email, you'll receive a password reset link."
                type="success"
                showIcon
              />
            ) : (
              <Form
                layout="vertical"
                onFinish={onFinish}
                initialValues={{ email: '' }}
              >
                {error && (
                  <Alert 
                    message={error}
                    type="error" 
                    showIcon 
                    style={{ marginBottom: 16 }}
                  />
                )}

                <Form.Item
                  label={<Text style={{ color: 'var(--text-secondary)' }}>Email</Text>}
                  name="email"
                  rules={[
                    { required: true, message: 'Please input your email!' },
                    { type: 'email', message: 'Please enter a valid email!' }
                  ]}
                >
                  <Input 
                    placeholder="you@example.com" 
                    size="large"
                    prefix={<Mail size={18} style={{ marginRight: 8, opacity: 0.5 }} />}
                    style={{
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-subtle)',
                      height: 48,
                    }}
                  />
                </Form.Item>

                <Form.Item>
                  <Button 
                    type="primary" 
                    htmlType="submit" 
                    block 
                    size="large" 
                    loading={isSubmitting}
                    style={{ height: 48 }}
                  >
                    Send Reset Link
                  </Button>
                </Form.Item>
              </Form>
            )}

            <div style={{ textAlign: 'center' }}>
              <Link to="/login" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                <ArrowLeft size={16} />
                Back to Login
              </Link>
            </div>
          </Space>
        </Card>
      </div>
    </div>
  )
}
