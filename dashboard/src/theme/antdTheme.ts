import { theme, type ThemeConfig } from 'antd'

type AppThemeMode = 'dark' | 'light'

const sharedTokens: ThemeConfig['token'] = {
  colorPrimary: '#6366f1',
  colorSuccess: '#10b981',
  colorWarning: '#f59e0b',
  colorError: '#ef4444',
  colorInfo: '#3b82f6',
  borderRadius: 10,
  borderRadiusSM: 6,
  borderRadiusLG: 14,
  borderRadiusXS: 4,
  controlHeight: 42,
  controlHeightSM: 36,
  controlHeightLG: 46,
  fontSize: 14,
  fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
}

const sharedComponents: ThemeConfig['components'] = {
  Menu: {
    itemBg: 'transparent',
    itemBorderRadius: 8,
    itemMarginInline: 12,
    itemMarginBlock: 4,
  },
  Card: {
    borderRadius: 10,
    borderRadiusLG: 14,
    headerBg: 'transparent',
  },
  Table: {
    borderRadius: 10,
    colorBgContainer: 'transparent',
  },
  Button: {
    borderRadius: 10,
    controlHeight: 42,
  },
  Input: {
    borderRadius: 10,
    controlHeight: 42,
  },
  Select: {
    borderRadius: 10,
  },
  Modal: {
    borderRadiusLG: 20,
  },
  Tag: {
    borderRadiusSM: 4,
  },
  Tooltip: {
    borderRadius: 8,
  },
  Dropdown: {
    borderRadius: 12,
  },
  Alert: {
    borderRadius: 10,
  },
}

const lightTheme: ThemeConfig = {
  algorithm: theme.defaultAlgorithm,
  hashed: false,
  cssVar: {
    prefix: 'kerneleye',
    key: 'light',
  },
  token: {
    ...sharedTokens,
    colorPrimaryHover: '#4f46e5',
    colorPrimaryActive: '#4338ca',
    colorPrimaryBg: 'rgba(99, 102, 241, 0.1)',
    colorPrimaryBgHover: 'rgba(99, 102, 241, 0.2)',
    colorBgBase: '#ffffff',
    colorBgContainer: '#f8fafc',
    colorBgElevated: '#ffffff',
    colorBgLayout: '#f1f5f9',
    colorText: '#0f172a',
    colorTextSecondary: '#475569',
    colorTextTertiary: '#64748b',
    colorBorder: '#e2e8f0',
    colorBorderSecondary: '#cbd5e1',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1)',
    boxShadowSecondary:
      '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)',
  },
  components: {
    ...sharedComponents,
    Layout: {
      siderBg: '#ffffff',
      headerBg: '#ffffff',
      bodyBg: '#f1f5f9',
    },
    Menu: {
      ...sharedComponents?.Menu,
      itemSelectedBg: 'rgba(99, 102, 241, 0.1)',
      itemHoverBg: 'rgba(0, 0, 0, 0.02)',
      itemColor: '#475569',
      itemSelectedColor: '#6366f1',
      itemHoverColor: '#0f172a',
      itemActiveBg: 'rgba(99, 102, 241, 0.15)',
    },
    Card: {
      ...sharedComponents?.Card,
      colorBgContainer: '#ffffff',
      colorBorderSecondary: '#e2e8f0',
    },
    Table: {
      ...sharedComponents?.Table,
      headerBg: '#f8fafc',
      headerColor: '#475569',
      rowHoverBg: 'rgba(99, 102, 241, 0.02)',
    },
    Button: {
      ...sharedComponents?.Button,
      colorBgContainer: '#f8fafc',
      colorBorder: '#e2e8f0',
    },
    Input: {
      ...sharedComponents?.Input,
      colorBgContainer: '#f8fafc',
      colorBorder: '#e2e8f0',
      hoverBorderColor: '#6366f1',
      activeBorderColor: '#6366f1',
    },
    Select: {
      ...sharedComponents?.Select,
      colorBgContainer: '#f8fafc',
    },
    Modal: {
      ...sharedComponents?.Modal,
      colorBgElevated: '#ffffff',
    },
    Statistic: {
      colorTextDescription: '#475569',
    },
    Tooltip: {
      ...sharedComponents?.Tooltip,
      colorBgSpotlight: '#1e293b',
    },
    Dropdown: {
      ...sharedComponents?.Dropdown,
      colorBgElevated: '#ffffff',
    },
  },
}

const darkTheme: ThemeConfig = {
  algorithm: theme.darkAlgorithm,
  hashed: false,
  cssVar: {
    prefix: 'kerneleye',
    key: 'dark',
  },
  token: {
    ...sharedTokens,
    colorPrimaryHover: '#818cf8',
    colorPrimaryActive: '#4f46e5',
    colorPrimaryBg: 'rgba(99, 102, 241, 0.1)',
    colorPrimaryBgHover: 'rgba(99, 102, 241, 0.2)',
    colorBgBase: '#0a0a0f',
    colorBgContainer: '#111118',
    colorBgElevated: '#1a1a25',
    colorBgLayout: '#0a0a0f',
    colorText: '#f8fafc',
    colorTextSecondary: '#94a3b8',
    colorTextTertiary: '#64748b',
    colorBorder: 'rgba(255, 255, 255, 0.06)',
    colorBorderSecondary: 'rgba(255, 255, 255, 0.1)',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -2px rgba(0, 0, 0, 0.3)',
    boxShadowSecondary:
      '0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -4px rgba(0, 0, 0, 0.4)',
  },
  components: {
    ...sharedComponents,
    Layout: {
      siderBg: 'transparent',
      headerBg: 'transparent',
      bodyBg: '#0a0a0f',
    },
    Menu: {
      ...sharedComponents?.Menu,
      itemSelectedBg: 'rgba(99, 102, 241, 0.15)',
      itemHoverBg: 'rgba(255, 255, 255, 0.05)',
      itemColor: '#94a3b8',
      itemSelectedColor: '#818cf8',
      itemHoverColor: '#f8fafc',
      itemActiveBg: 'rgba(99, 102, 241, 0.2)',
    },
    Card: {
      ...sharedComponents?.Card,
      colorBgContainer: 'rgba(26, 26, 37, 0.6)',
      colorBorderSecondary: 'rgba(255, 255, 255, 0.06)',
    },
    Table: {
      ...sharedComponents?.Table,
      headerBg: '#1a1a25',
      headerColor: '#94a3b8',
      rowHoverBg: 'rgba(99, 102, 241, 0.05)',
    },
    Button: {
      ...sharedComponents?.Button,
      colorBgContainer: '#1a1a25',
      colorBorder: 'rgba(255, 255, 255, 0.1)',
    },
    Input: {
      ...sharedComponents?.Input,
      colorBgContainer: '#1a1a25',
      colorBorder: 'rgba(255, 255, 255, 0.06)',
      hoverBorderColor: '#6366f1',
      activeBorderColor: '#6366f1',
    },
    Select: {
      ...sharedComponents?.Select,
      colorBgContainer: '#1a1a25',
    },
    Modal: {
      ...sharedComponents?.Modal,
      colorBgElevated: '#111118',
    },
    Statistic: {
      colorTextDescription: '#94a3b8',
    },
    Tooltip: {
      ...sharedComponents?.Tooltip,
      colorBgSpotlight: '#1a1a25',
    },
    Dropdown: {
      ...sharedComponents?.Dropdown,
      colorBgElevated: '#111118',
    },
  },
}

export function getAntdTheme(mode: AppThemeMode): ThemeConfig {
  return mode === 'dark' ? darkTheme : lightTheme
}
