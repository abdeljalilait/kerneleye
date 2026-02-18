import React from 'react'
import { App as AntdApp, ConfigProvider, theme } from 'antd'
import ReactDOM from 'react-dom/client'
import { RouterProvider } from '@tanstack/react-router'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from './lib/queryClient'
import { router } from './router'
import './index.css'

// Modern dark theme configuration
const customTheme = {
  algorithm: theme.darkAlgorithm,
  token: {
    // Primary colors - Electric Indigo
    colorPrimary: '#6366f1',
    colorPrimaryHover: '#818cf8',
    colorPrimaryActive: '#4f46e5',
    colorPrimaryBg: 'rgba(99, 102, 241, 0.1)',
    colorPrimaryBgHover: 'rgba(99, 102, 241, 0.2)',
    
    // Background colors
    colorBgBase: '#0a0a0f',
    colorBgContainer: '#111118',
    colorBgElevated: '#1a1a25',
    colorBgLayout: '#0a0a0f',
    
    // Text colors
    colorText: '#f8fafc',
    colorTextSecondary: '#94a3b8',
    colorTextTertiary: '#64748b',
    
    // Border colors
    colorBorder: 'rgba(255, 255, 255, 0.06)',
    colorBorderSecondary: 'rgba(255, 255, 255, 0.1)',
    
    // Border radius
    borderRadius: 10,
    borderRadiusSM: 6,
    borderRadiusLG: 14,
    borderRadiusXS: 4,
    
    // Font
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    
    // Shadow
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -2px rgba(0, 0, 0, 0.3)',
    boxShadowSecondary: '0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -4px rgba(0, 0, 0, 0.4)',
    
    // Success/Warning/Error colors
    colorSuccess: '#10b981',
    colorWarning: '#f59e0b',
    colorError: '#ef4444',
    colorInfo: '#3b82f6',
  },
  components: {
    Layout: {
      siderBg: 'transparent',
      headerBg: 'transparent',
      bodyBg: '#0a0a0f',
    },
    Menu: {
      itemBg: 'transparent',
      itemSelectedBg: 'rgba(99, 102, 241, 0.15)',
      itemHoverBg: 'rgba(255, 255, 255, 0.05)',
      itemColor: '#94a3b8',
      itemSelectedColor: '#818cf8',
      itemHoverColor: '#f8fafc',
      itemActiveBg: 'rgba(99, 102, 241, 0.2)',
      itemBorderRadius: 8,
      itemMarginInline: 12,
      itemMarginBlock: 4,
    },
    Card: {
      borderRadiusLG: 14,
      borderRadius: 10,
      colorBgContainer: 'rgba(26, 26, 37, 0.6)',
      colorBorderSecondary: 'rgba(255, 255, 255, 0.06)',
      headerBg: 'transparent',
    },
    Table: {
      borderRadius: 10,
      colorBgContainer: 'transparent',
      headerBg: '#1a1a25',
      headerColor: '#94a3b8',
      rowHoverBg: 'rgba(99, 102, 241, 0.05)',
    },
    Button: {
      borderRadius: 10,
      colorBgContainer: '#1a1a25',
      colorBorder: 'rgba(255, 255, 255, 0.1)',
    },
    Input: {
      borderRadius: 10,
      colorBgContainer: '#1a1a25',
      colorBorder: 'rgba(255, 255, 255, 0.06)',
      hoverBorderColor: '#6366f1',
      activeBorderColor: '#6366f1',
    },
    Select: {
      borderRadius: 10,
      colorBgContainer: '#1a1a25',
    },
    Modal: {
      borderRadiusLG: 20,
      colorBgElevated: '#111118',
    },
    Tag: {
      borderRadiusSM: 4,
    },
    Statistic: {
      colorTextDescription: '#94a3b8',
    },
    Tooltip: {
      borderRadius: 8,
      colorBgSpotlight: '#1a1a25',
    },
    Dropdown: {
      borderRadius: 12,
      colorBgElevated: '#111118',
    },
    Alert: {
      borderRadius: 10,
    },
  },
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <ConfigProvider theme={customTheme}>
        <AntdApp>
          <RouterProvider router={router} />
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>
  </React.StrictMode>,
)
