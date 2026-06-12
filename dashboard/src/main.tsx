// SPDX-License-Identifier: Apache-2.0

import React from 'react'
import { App as AntdApp, ConfigProvider } from 'antd'
import ReactDOM from 'react-dom/client'
import { RouterProvider } from '@tanstack/react-router'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from './lib/queryClient'
import { router } from './router'
import { ThemeProvider, useTheme } from './context/ThemeContext'
import { AuthProvider } from './context/AuthContext'
import { getAntdTheme } from './theme/antdTheme'
import './index.css'

// Theme wrapper component
function ThemedApp() {
  const { resolvedTheme } = useTheme()

  return (
    <ConfigProvider theme={getAntdTheme(resolvedTheme)}>
      <AntdApp>
        <RouterProvider router={router} />
      </AntdApp>
    </ConfigProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ThemeProvider>
          <ThemedApp />
        </ThemeProvider>
      </AuthProvider>
    </QueryClientProvider>
  </React.StrictMode>,
)
