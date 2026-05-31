import { createRouter, createRoute, createRootRoute, Outlet, redirect } from '@tanstack/react-router'
// import { TanStackRouterDevtools } from '@tanstack/router-devtools'
import { lazy, Suspense } from 'react'
import { Spin } from 'antd'
import { WebSocketProvider } from './context/WebSocketContext'
import GlobalNotifications from './components/GlobalNotifications'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const Login = lazy(() => import('./pages/Login'))
const Overview = lazy(() => import('./pages/Overview'))
const Servers = lazy(() => import('./pages/Servers'))
const Threats = lazy(() => import('./pages/Threats'))
const Alerts = lazy(() => import('./pages/Alerts'))
const ServerDetail = lazy(() => import('./pages/ServerDetail'))
const OAuthCallback = lazy(() => import('./pages/OAuthCallback'))
const Profile = lazy(() => import('./pages/Profile'))
const Reports = lazy(() => import('./pages/Reports'))
const Visualizer = lazy(() => import('./pages/Visualizer'))
const BlockedIPs = lazy(() => import('./pages/BlockedIPs'))
const Whitelist = lazy(() => import('./pages/Whitelist'))

const PageLoader = () => (
  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '60vh' }}>
    <Spin size="large" />
  </div>
)

function withSuspense(Component: React.ComponentType) {
  return () => (
    <Suspense fallback={<PageLoader />}>
      <Component />
    </Suspense>
  )
}

// 1. Create a root route
const rootRoute = createRootRoute({
  component: () => (
    <>
      <Outlet />
      {/* <TanStackRouterDevtools /> */}
    </>
  ),
})

// Auth check using AuthContext
const authCheck = () => {
  const token = localStorage.getItem('kerneleye_token')
  if (!token) {
    throw redirect({
      to: '/login',
      search: {
        redirect: window.location.href,
      },
    })
  }
}

// 2. Create the route tree
const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: withSuspense(Login),
})

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/dashboard' })
  },
})

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'dashboard',
  component: () => (
    <Suspense fallback={<PageLoader />}>
      <WebSocketProvider>
        <GlobalNotifications />
        <Dashboard />
      </WebSocketProvider>
    </Suspense>
  ),
  beforeLoad: authCheck,
})

const overviewRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/',
  component: withSuspense(Overview),
})

const serversRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/servers',
  component: withSuspense(Servers),
})

const serverDetailRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/servers/$id',
  component: withSuspense(ServerDetail),
})

const threatsRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/threats',
  component: withSuspense(Threats),
})

const alertsRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/alerts',
  component: withSuspense(Alerts),
})

const blockedIPsRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/blocked-ips',
  component: withSuspense(BlockedIPs),
})

const whitelistRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/whitelist',
  component: withSuspense(Whitelist),
})

const oauthCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/oauth/callback',
  component: withSuspense(OAuthCallback),
})

const profileRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: 'profile',
  component: withSuspense(Profile),
})

const reportsRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: 'reports',
  component: withSuspense(Reports),
})

const visualizerRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: 'visualizer',
  component: withSuspense(Visualizer),
})

// 3. Register the route tree
const routeTree = rootRoute.addChildren([
  loginRoute,
  oauthCallbackRoute,
  dashboardRoute.addChildren([
    overviewRoute,
    serversRoute,
    serverDetailRoute,
    threatsRoute,
    alertsRoute,
    blockedIPsRoute,
    whitelistRoute,
    profileRoute,
    reportsRoute,
    visualizerRoute,
  ]),
  indexRoute
])

// 4. Create the router
export const router = createRouter({ routeTree })

// 5. Register the router instance for type safety
declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
