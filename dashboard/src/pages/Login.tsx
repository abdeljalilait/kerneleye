import { useRouter, Link } from '@tanstack/react-router'
import { Shield } from 'lucide-react'
import { Form, Input, Button, Card, Typography, Alert, theme } from 'antd'
import { useLogin } from '../hooks/useQueries'

const { Title, Text } = Typography

export default function Login() {
  const router = useRouter()
  const loginMutation = useLogin()
  const {
      token: { colorBgBase, colorBgContainer },
  } = theme.useToken();

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
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: colorBgBase, padding: 24 }}>
      <div style={{ width: '100%', maxWidth: 400 }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 64, height: 64, background: '#4f46e5', borderRadius: 12, marginBottom: 16 }}>
            <Shield size={32} color="white" />
          </div>
          <Title level={2} style={{ margin: 0, marginBottom: 8 }}>KernelEye</Title>
          <Text type="secondary">Traffic Intelligence Dashboard</Text>
        </div>

        <Card title="Sign In" variant="borderless" style={{ background: colorBgContainer }}>
         {loginMutation.error && (
                 <Alert message={(loginMutation.error as any).response?.data?.error || 'Login failed'} type="error" showIcon style={{ marginBottom: 24 }} />
             )}
            <Form
                layout="vertical"
                onFinish={onFinish}
                initialValues={{ email: '', password: '' }}
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
                    rules={[{ required: true, message: 'Please input your password!' }]}
                >
                    <Input.Password placeholder="••••••••" size="large" />
                </Form.Item>

                <Form.Item>
                    <Button type="primary" htmlType="submit" block size="large" loading={loginMutation.isPending} style={{ marginTop: 8 }}>
                        Sign In
                    </Button>
                </Form.Item>
            </Form>

            <div style={{ textAlign: 'center', marginTop: 16, paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                <Text type="secondary">
                    Don't have an account? <Link to="/register">Create one</Link>
                </Text>
                <br />
                <Text type="secondary" style={{ fontSize: 12 }}>
                    Demo: demo@kerneleye.io / demo
                </Text>
            </div>
        </Card>
      </div>
    </div>
  )
}
