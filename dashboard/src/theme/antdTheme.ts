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
  sizeStep: 4,
  sizeUnit: 4,
  paddingXS: 8,
  paddingSM: 12,
  padding: 16,
  paddingMD: 20,
  paddingLG: 24,
  paddingXL: 32,
  marginXS: 8,
  marginSM: 12,
  margin: 16,
  marginMD: 20,
  marginLG: 24,
  marginXL: 32,
}

const sharedComponents: ThemeConfig['components'] = {
  Card: {
    paddingLG: 24,
    borderRadiusLG: 14,
  },
  Table: {
    borderRadiusLG: 10,
    headerBorderRadius: 10,
    cellPaddingBlock: 12,
    cellPaddingInline: 16,
  },
  Button: {
    borderRadius: 10,
    controlHeight: 42,
    controlHeightSM: 34,
    paddingInlineSM: 12,
    paddingInline: 20,
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
    borderRadiusSM: 6,
  },
  Tooltip: {
    borderRadius: 8,
  },
  Dropdown: {
    borderRadius: 12,
  },
  Alert: {
    borderRadiusLG: 10,
  },
  Segmented: {
    borderRadius: 10,
    itemSelectedBg: 'rgba(99, 102, 241, 0.15)',
    itemSelectedColor: '#6366f1',
  },
  Statistic: {
    titleFontSize: 12,
    contentFontSize: 32,
    marginXXS: 4,
  },
  Badge: {
    indicatorHeight: 8,
    dotSize: 8,
    lineHeight: 1,
  },
}

const makeTheme = (
  algorithm: ThemeConfig['algorithm'],
  tokens: ThemeConfig['token'],
  components: ThemeConfig['components'],
  cssVarKey: string,
): ThemeConfig => ({
  algorithm,
  hashed: false,
  cssVar: { prefix: 'kerneleye', key: cssVarKey },
  token: { ...sharedTokens, ...tokens },
  components: {
    ...sharedComponents,
    ...components,
  },
})

const lightTheme = makeTheme(
  theme.defaultAlgorithm,
  {
    colorPrimaryHover: '#4f46e5',
    colorPrimaryActive: '#4338ca',
    colorPrimaryBg: 'rgba(99, 102, 241, 0.08)',
    colorPrimaryBgHover: 'rgba(99, 102, 241, 0.15)',
    colorPrimaryBorder: 'rgba(99, 102, 241, 0.2)',
    colorPrimaryBorderHover: 'rgba(99, 102, 241, 0.35)',
    colorBgBase: '#ffffff',
    colorBgContainer: '#ffffff',
    colorBgElevated: '#ffffff',
    colorBgLayout: '#f1f5f9',
    colorBgSpotlight: '#1e293b',
    colorFillAlter: '#f1f5f9',
    colorFillContent: 'rgba(0, 0, 0, 0.04)',
    colorFillContentHover: 'rgba(0, 0, 0, 0.06)',
    colorText: '#0f172a',
    colorTextSecondary: '#475569',
    colorTextTertiary: '#64748b',
    colorTextQuaternary: '#94a3b8',
    colorBorder: '#e2e8f0',
    colorBorderSecondary: '#cbd5e1',
    boxShadow:
      '0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -2px rgba(0, 0, 0, 0.05)',
    boxShadowSecondary:
      '0 10px 15px -3px rgba(0, 0, 0, 0.07), 0 4px 6px -4px rgba(0, 0, 0, 0.05)',
  },
  {
    Layout: {
      siderBg: '#ffffff',
      headerBg: '#ffffff',
      bodyBg: '#f1f5f9',
      triggerBg: 'transparent',
      triggerColor: '#64748b',
      headerHeight: 72,
      headerPadding: '0 32px',
    },
    Menu: {
      itemBg: 'transparent',
      itemBorderRadius: 8,
      itemMarginInline: 8,
      itemMarginBlock: 2,
      itemHeight: 44,
      iconSize: 18,
      collapsedIconSize: 20,
      itemSelectedBg: 'rgba(99, 102, 241, 0.08)',
      itemHoverBg: 'rgba(0, 0, 0, 0.03)',
      itemColor: '#475569',
      itemSelectedColor: '#6366f1',
      itemHoverColor: '#0f172a',
      itemActiveBg: 'rgba(99, 102, 241, 0.12)',
      subMenuItemBg: 'transparent',
      groupTitleColor: '#94a3b8',
    },
    Card: {
      ...sharedComponents.Card,
      colorBgContainer: '#ffffff',
      colorBorderSecondary: '#e2e8f0',
      headerBg: 'transparent',
    },
    Table: {
      ...sharedComponents.Table,
      headerBg: '#f8fafc',
      headerColor: '#475569',
      headerSplitColor: '#e2e8f0',
      rowHoverBg: 'rgba(99, 102, 241, 0.02)',
      rowSelectedBg: 'rgba(99, 102, 241, 0.05)',
      rowSelectedHoverBg: 'rgba(99, 102, 241, 0.08)',
      borderColor: '#e2e8f0',
    },
    Button: {
      ...sharedComponents.Button,
      defaultBg: '#f8fafc',
      defaultBorderColor: '#e2e8f0',
      defaultHoverBorderColor: '#6366f1',
      defaultHoverColor: '#6366f1',
      defaultActiveBorderColor: '#4f46e5',
      defaultActiveColor: '#4f46e5',
      primaryShadow: '0 2px 8px rgba(99, 102, 241, 0.3)',
    },
    Input: {
      ...sharedComponents.Input,
      colorBgContainer: '#f8fafc',
      colorBorder: '#e2e8f0',
      hoverBorderColor: '#6366f1',
      activeBorderColor: '#6366f1',
      activeShadow: '0 0 0 2px rgba(99, 102, 241, 0.1)',
      addonBg: '#f1f5f9',
    },
    Select: {
      ...sharedComponents.Select,
      colorBgContainer: '#f8fafc',
    },
    Modal: {
      ...sharedComponents.Modal,
      colorBgElevated: '#ffffff',
      headerBg: 'transparent',
      contentBg: '#ffffff',
    },
    Statistic: {
      ...sharedComponents.Statistic,
      colorTextDescription: '#475569',
    },
    Tooltip: {
      ...sharedComponents.Tooltip,
      colorBgSpotlight: '#1e293b',
    },
    Dropdown: {
      ...sharedComponents.Dropdown,
      colorBgElevated: '#ffffff',
    },
    Tag: {
      ...sharedComponents.Tag,
      defaultBg: '#f1f5f9',
      defaultColor: '#64748b',
    },
    Badge: {
      ...sharedComponents.Badge,
      colorText: '#ffffff',
    },
    Segmented: {
      ...sharedComponents.Segmented,
      trackBg: '#f1f5f9',
    },
    Avatar: {
      borderRadius: 10,
    },
    Progress: {
      defaultColor: '#6366f1',
      remainingColor: 'rgba(0, 0, 0, 0.04)',
    },
  },
  'light',
)

const darkTheme = makeTheme(
  theme.darkAlgorithm,
  {
    colorPrimaryHover: '#818cf8',
    colorPrimaryActive: '#4f46e5',
    colorPrimaryBg: 'rgba(99, 102, 241, 0.12)',
    colorPrimaryBgHover: 'rgba(99, 102, 241, 0.2)',
    colorPrimaryBorder: 'rgba(99, 102, 241, 0.25)',
    colorPrimaryBorderHover: 'rgba(99, 102, 241, 0.4)',
    colorBgBase: '#09090b',
    colorBgContainer: 'rgba(255, 255, 255, 0.04)',
    colorBgElevated: '#18181b',
    colorBgLayout: '#09090b',
    colorBgSpotlight: '#27272a',
    colorFillAlter: 'rgba(255, 255, 255, 0.04)',
    colorFillContent: 'rgba(255, 255, 255, 0.06)',
    colorFillContentHover: 'rgba(255, 255, 255, 0.08)',
    colorText: '#fafafa',
    colorTextSecondary: '#a1a1aa',
    colorTextTertiary: '#71717a',
    colorTextQuaternary: '#52525b',
    colorBorder: 'rgba(255, 255, 255, 0.08)',
    colorBorderSecondary: 'rgba(255, 255, 255, 0.12)',
    boxShadow:
      '0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -2px rgba(0, 0, 0, 0.2)',
    boxShadowSecondary:
      '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -4px rgba(0, 0, 0, 0.3)',
  },
  {
    Layout: {
      siderBg: 'transparent',
      headerBg: 'transparent',
      bodyBg: '#09090b',
      triggerBg: 'transparent',
      triggerColor: '#71717a',
      headerHeight: 72,
      headerPadding: '0 32px',
    },
    Menu: {
      itemBg: 'transparent',
      itemBorderRadius: 8,
      itemMarginInline: 8,
      itemMarginBlock: 2,
      itemHeight: 44,
      iconSize: 18,
      collapsedIconSize: 20,
      itemSelectedBg: 'rgba(99, 102, 241, 0.12)',
      itemHoverBg: 'rgba(255, 255, 255, 0.05)',
      itemColor: '#a1a1aa',
      itemSelectedColor: '#818cf8',
      itemHoverColor: '#fafafa',
      itemActiveBg: 'rgba(99, 102, 241, 0.18)',
      subMenuItemBg: 'transparent',
      groupTitleColor: '#52525b',
    },
    Card: {
      ...sharedComponents.Card,
      colorBgContainer: 'rgba(255, 255, 255, 0.04)',
      colorBorderSecondary: 'rgba(255, 255, 255, 0.08)',
      headerBg: 'transparent',
    },
    Table: {
      ...sharedComponents.Table,
      headerBg: 'rgba(255, 255, 255, 0.04)',
      headerColor: '#a1a1aa',
      headerSplitColor: 'rgba(255, 255, 255, 0.08)',
      rowHoverBg: 'rgba(99, 102, 241, 0.04)',
      rowSelectedBg: 'rgba(99, 102, 241, 0.06)',
      rowSelectedHoverBg: 'rgba(99, 102, 241, 0.1)',
      borderColor: 'rgba(255, 255, 255, 0.08)',
    },
    Button: {
      ...sharedComponents.Button,
      defaultBg: 'rgba(255, 255, 255, 0.04)',
      defaultBorderColor: 'rgba(255, 255, 255, 0.1)',
      defaultHoverBorderColor: '#6366f1',
      defaultHoverColor: '#818cf8',
      defaultActiveBorderColor: '#4f46e5',
      defaultActiveColor: '#4f46e5',
      primaryShadow: '0 2px 8px rgba(99, 102, 241, 0.4)',
    },
    Input: {
      ...sharedComponents.Input,
      colorBgContainer: 'rgba(255, 255, 255, 0.04)',
      colorBorder: 'rgba(255, 255, 255, 0.08)',
      hoverBorderColor: '#6366f1',
      activeBorderColor: '#6366f1',
      activeShadow: '0 0 0 2px rgba(99, 102, 241, 0.15)',
      addonBg: 'rgba(255, 255, 255, 0.06)',
    },
    Select: {
      ...sharedComponents.Select,
      colorBgContainer: 'rgba(255, 255, 255, 0.04)',
    },
    Modal: {
      ...sharedComponents.Modal,
      colorBgElevated: '#18181b',
      headerBg: 'transparent',
      contentBg: '#18181b',
      footerBg: 'transparent',
    },
    Statistic: {
      ...sharedComponents.Statistic,
      colorTextDescription: '#a1a1aa',
    },
    Tooltip: {
      ...sharedComponents.Tooltip,
      colorBgSpotlight: '#27272a',
    },
    Dropdown: {
      ...sharedComponents.Dropdown,
      colorBgElevated: '#18181b',
    },
    Tag: {
      ...sharedComponents.Tag,
      defaultBg: 'rgba(255, 255, 255, 0.06)',
      defaultColor: '#a1a1aa',
    },
    Badge: {
      ...sharedComponents.Badge,
      colorText: '#fafafa',
    },
    Segmented: {
      ...sharedComponents.Segmented,
      trackBg: 'rgba(255, 255, 255, 0.06)',
    },
    Avatar: {
      borderRadius: 10,
    },
    Progress: {
      defaultColor: '#6366f1',
      remainingColor: 'rgba(255, 255, 255, 0.06)',
    },
  },
  'dark',
)

export function getAntdTheme(mode: AppThemeMode): ThemeConfig {
  return mode === 'dark' ? darkTheme : lightTheme
}
