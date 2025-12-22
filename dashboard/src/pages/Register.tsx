import { useRouter, Link } from '@tanstack/react-router'
import { Shield } from 'lucide-react'
import { Form, Input, Button, Card, Typography, Alert, theme } from 'antd'
import { useRegister } from '../hooks/useQueries'

const { Title, Text } = Typography

export default function Register() {
  const router = useRouter()
  const registerMutation = useRegister()
  const {
      token: { colorBgBase, colorBgContainer },
  } = theme.useToken();

  const onFinish = async (values: any) => {
    if (values.password !== values.confirmPassword) {
      return
    }

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

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: colorBgBase, padding: 24 }}>
      <div style={{ width: '100%', maxWidth: 400 }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
            <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 64, height: 64, background: '#4f46e5', borderRadius: 12, marginBottom: 16 }}>
            <Shield size={32} color="white" />
            </div>
            <Title level={2} style={{ margin: 0, marginBottom: 8 }}>KernelEye</Title>
            <Text type="secondary">Create your account</Text>
        </div>

        <Card title="Sign Up" variant="borderless" style={{ background: colorBgContainer }}>
            {registerMutation.error && (
                <Alert message={(registerMutation.error as any).response?.data?.error || 'Registration failed'} type="error" showIcon style={{ marginBottom: 24 }} />
            )}
            
            <Form
                layout="vertical"
                onFinish={onFinish}
            >
                <Form.Item
                    label="Email"
                    name="email"
                    rules={[{ required: true, message: 'Please input your email!' }, { type: 'email', message: 'Please enter a valid email!' }]}
                >
                    <Input placeholder="you@example.com" size="large" />
                </Form.Item>

                <Form.Item
                    label="Password"
                    name="password"
                    rules={[{ required: true, message: 'Please input your password!' }, { min: 6, message: 'Password must be at least 6 characters' }]}
                >
                    <Input.Password placeholder="••••••••" size="large" />
                </Form.Item>

                <Form.Item
                    label="Confirm Password"
                    name="confirmPassword"
                    dependencies={['password']}
                    rules={[
                        { required: true, message: 'Please confirm your password!' },
                        ({ getFieldValue }) =>({
                            validator(_, value) {
                                if (!value || getFieldValue('password') === value) {
                                    return Promise.resolve();
                                }
                                return Promise.reject(new Error('Passwords do not match!'));
                            },
                        }),
                    ]}
                >
                    <Input.Password placeholder="••••••••" size="large" />
                </Form.Item>

                <Form.Item>
                    <Button type="primary" htmlType="submit" block size="large" loading={registerMutation.isPending} style={{ marginTop: 8 }}>
                        Create Account
                    </Button>
                </Form.Item>
            </Form>

            <div style={{ textAlign: 'center', marginTop: 16, paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                <Text type="secondary">
                    Already have an account? <Link to="/login">Sign in</Link>
                </Text>
            </div>
        </Card>
      </div>
    </div>
  )
}
