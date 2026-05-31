import { useEffect, useState } from 'react'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { Card, Spin, Typography, Alert, Button } from 'antd'
import { Shield, CheckCircle, XCircle } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

const { Title, Text } = Typography

function getErrorMessage(code: string): { title: string; message: string } {
  switch (code) {
    case 'owner_not_configured':
      return {
        title: 'Instance not configured',
        message: 'AUTH_OWNER_EMAIL is not set. Configure the owner email in your environment variables before signing in.',
      }
    case 'unauthorized_owner':
      return {
        title: 'Access denied',
        message: 'Your account is not the configured instance owner. Only the owner email set in AUTH_OWNER_EMAIL can sign in.',
      }
    default:
      return {
        title: 'Sign in failed',
        message: code || 'Authentication failed',
      }
  }
}

export default function OAuthCallback() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const search = useSearch({ from: '/oauth/callback' })
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing')
  const [errorCode, setErrorCode] = useState('')

  useEffect(() => {
    const handleOAuthCallback = async () => {
      const params = search as any
      const token = params?.token
      const error = params?.error

      if (error) {
        setStatus('error')
        setErrorCode(error)
        return
      }

      if (token) {
        try {
          await login(token)
          setStatus('success')
          
          // Redirect after a short delay
          setTimeout(() => {
            navigate({ to: '/dashboard' })
          }, 1000)
        } catch (err: any) {
          setStatus('error')
          setErrorCode(err?.message || 'Failed to complete authentication')
        }
      } else {
        setStatus('error')
        setErrorCode('No authentication token received')
      }
    }

    handleOAuthCallback()
  }, [search, login, navigate])

  const errorDetails = getErrorMessage(errorCode)

  return (
    <div 
      style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center', 
        background: 'var(--kerneleye-colorBgLayout)',
        padding: 24,
      }}
    >
      <Card
        variant="borderless"
        style={{ 
          width: '100%',
          maxWidth: 400,
          background: 'var(--kerneleye-colorBgContainer)',
          border: '1px solid var(--kerneleye-colorBorderSecondary)',
          borderRadius: '20px',
          textAlign: 'center',
          padding: 40,
        }}
      >
        {/* Logo */}
        <div 
          style={{ 
            display: 'inline-flex', 
            alignItems: 'center', 
            justifyContent: 'center', 
            width: 64, 
            height: 64, 
            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            borderRadius: 16, 
            marginBottom: 24,
          }}
        >
          <Shield size={32} color="white" />
        </div>

        {status === 'processing' && (
          <>
            <Spin size="large" style={{ marginBottom: 24 }} />
            <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--kerneleye-colorText)' }}>
              Completing sign in...
            </Title>
            <Text style={{ color: 'var(--kerneleye-colorTextSecondary)' }}>
              Please wait while we authenticate you
            </Text>
          </>
        )}

        {status === 'success' && (
          <>
            <CheckCircle size={48} style={{ color: '#10b981', marginBottom: 16 }} />
            <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--kerneleye-colorText)' }}>
              Sign in successful!
            </Title>
            <Text style={{ color: 'var(--kerneleye-colorTextSecondary)' }}>
              Redirecting to your dashboard...
            </Text>
          </>
        )}

        {status === 'error' && (
          <>
            <XCircle size={48} style={{ color: '#ef4444', marginBottom: 16 }} />
            <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--kerneleye-colorText)' }}>
              {errorDetails.title}
            </Title>
            <Alert
              message={errorDetails.message}
              type="error"
              showIcon
              style={{ 
                marginBottom: 24, 
                textAlign: 'left',
                background: 'rgba(239, 68, 68, 0.1)', 
                border: '1px solid rgba(239, 68, 68, 0.2)',
              }}
            />
            <Button 
              type="primary" 
              onClick={() => navigate({ to: '/login' })}
            >
              Back to Login
            </Button>
          </>
        )}
      </Card>
    </div>
  )
}
