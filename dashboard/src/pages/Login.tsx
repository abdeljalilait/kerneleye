import { Link } from '@tanstack/react-router'
import { Github, Chrome } from 'lucide-react'
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
        background: 'var(--kerneleye-colorBgLayout)',
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
          <div style={{ 
            display: 'inline-block',
            background: 'linear-gradient(135deg, #1a1a2e, #16213e)', 
            padding: '24px 32px', 
            borderRadius: 16, 
            marginBottom: 20,
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)'
          }}>
            <img 
              src="https://r2.kerneleye.net/logo_kerneleye_dark.png" 
              alt="KernelEye" 
              style={{ width: 180, height: 'auto', display: 'block' }}
            />
          </div>
          <div>
            <Text style={{ color: 'var(--kerneleye-colorTextSecondary)', fontSize: 15 }}>Security Intelligence Dashboard</Text>
          </div>
        </div>

        <Card
          variant="borderless"
          style={{ background: 'var(--kerneleye-colorBgContainer)', border: '1px solid var(--kerneleye-colorBorderSecondary)', borderRadius: '20px', backdropFilter: 'blur(10px)', boxShadow: '0 20px 50px rgba(0, 0, 0, 0.4)' }}
          bodyStyle={{ padding: 40 }}
        >
          <Space direction="vertical" size={24} style={{ width: '100%' }}>
            <div style={{ textAlign: 'center' }}>
              <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--kerneleye-colorText)' }}>Welcome back</Title>
              <Text style={{ color: 'var(--kerneleye-colorTextTertiary)' }}>Sign in with your account to continue</Text>
            </div>

            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              {providers.length > 0 ? providers.map((provider) => (
                <Button
                  key={provider.id}
                  block
                  size="large"
                  onClick={() => handleOAuthLogin(provider.id)}
                  icon={getProviderIcon(provider.icon)}
                  style={{ height: 48, background: 'var(--kerneleye-colorFillAlter)', border: '1px solid var(--kerneleye-colorBorderSecondary)', color: 'var(--kerneleye-colorText)', fontWeight: 500 }}
                >
                  Continue with {provider.name}
                </Button>
              )) : (
                <>
                  <Button block size="large" icon={<Github size={20} />} onClick={() => handleOAuthLogin('github')} style={{ height: 48, background: 'var(--kerneleye-colorFillAlter)', border: '1px solid var(--kerneleye-colorBorderSecondary)', color: 'var(--kerneleye-colorText)', fontWeight: 500 }}>
                    Continue with GitHub
                  </Button>
                  <Button block size="large" icon={<Chrome size={20} />} onClick={() => handleOAuthLogin('google')} style={{ height: 48, background: 'var(--kerneleye-colorFillAlter)', border: '1px solid var(--kerneleye-colorBorderSecondary)', color: 'var(--kerneleye-colorText)', fontWeight: 500 }}>
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
          <Text style={{ color: 'var(--kerneleye-colorTextQuaternary)', fontSize: 12 }}>© 2026 KernelEye. All rights reserved.</Text>
        </div>
      </div>
    </div>
  )
}
