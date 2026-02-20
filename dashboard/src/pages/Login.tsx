import { Link } from '@tanstack/react-router'
import { Shield, Github, Chrome } from 'lucide-react'
import { Button, Card, Typography, Space } from 'antd'
import { useOAuthProviders } from '../hooks/useQueries'

const { Title, Text } = Typography

export default function Login() {
  const { data: providers = [] } = useOAuthProviders()

  const handleOAuthLogin = (provider: string) => {
    const apiUrl = import.meta.env.VITE_API_URL || '/api/v1'
    window.location.href = `${apiUrl}/auth/${provider}`
  }

  const getProviderIcon = (icon: string) => {
    switch (icon) {
      case 'github': return <Github size={20} />
      case 'google': return <Chrome size={20} />
      default: return null
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
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background Effects */}
      <div style={{ position: 'absolute', top: '-20%', right: '-10%', width: 600, height: 600, background: 'radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', bottom: '-20%', left: '-10%', width: 500, height: 500, background: 'radial-gradient(circle, rgba(6, 182, 212, 0.1) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', inset: 0, backgroundImage: `linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)`, backgroundSize: '50px 50px', pointerEvents: 'none' }} />

      <div style={{ width: '100%', maxWidth: 420, position: 'relative', zIndex: 1 }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 80, height: 80, background: 'linear-gradient(135deg, #6366f1, #8b5cf6)', borderRadius: 20, marginBottom: 24, boxShadow: '0 8px 32px rgba(99, 102, 241, 0.4)' }}>
            <Shield size={40} color="white" />
          </div>
          <Title level={2} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>KernelEye</Title>
          <Text style={{ color: 'var(--text-secondary)', fontSize: 15 }}>Security Intelligence Dashboard</Text>
        </div>

        <Card
          variant="borderless"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xl)', backdropFilter: 'blur(10px)', boxShadow: '0 20px 50px rgba(0, 0, 0, 0.4)' }}
          bodyStyle={{ padding: 40 }}
        >
          <Space direction="vertical" size={24} style={{ width: '100%' }}>
            <div style={{ textAlign: 'center' }}>
              <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>Welcome back</Title>
              <Text style={{ color: 'var(--text-tertiary)' }}>Sign in with your account to continue</Text>
            </div>

            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              {providers.length > 0 ? providers.map((provider) => (
                <Button
                  key={provider.id}
                  block
                  size="large"
                  onClick={() => handleOAuthLogin(provider.id)}
                  icon={getProviderIcon(provider.icon)}
                  style={{ height: 48, background: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)', fontWeight: 500 }}
                >
                  Continue with {provider.name}
                </Button>
              )) : (
                <>
                  <Button block size="large" icon={<Github size={20} />} onClick={() => handleOAuthLogin('github')} style={{ height: 48, background: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)', fontWeight: 500 }}>
                    Continue with GitHub
                  </Button>
                  <Button block size="large" icon={<Chrome size={20} />} onClick={() => handleOAuthLogin('google')} style={{ height: 48, background: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)', fontWeight: 500 }}>
                    Continue with Google
                  </Button>
                </>
              )}
            </Space>

            <div style={{ textAlign: 'center' }}>
              <Text type="secondary">
                Don't have an account?{' '}
                <Link to="/register" style={{ fontWeight: 600 }}>Sign up</Link>
              </Text>
            </div>
          </Space>
        </Card>

        <div style={{ textAlign: 'center', marginTop: 32 }}>
          <Text style={{ color: 'var(--text-muted)', fontSize: 12 }}>© 2026 KernelEye. All rights reserved.</Text>
        </div>
      </div>
    </div>
  )
}
