import { createRouter, createRoute, createRootRoute, Outlet, redirect } from '@tanstack/react-router'
// import { TanStackRouterDevtools } from '@tanstack/router-devtools'
import Dashboard from './pages/Dashboard'
import Login from './pages/Login'
import Register from './pages/Register'
import Overview from './pages/Overview'
import Servers from './pages/Servers'
import Threats from './pages/Threats'
import Alerts from './pages/Alerts'
import ServerDetail from './pages/ServerDetail'
import Subscription from './pages/Subscription'
import OAuthCallback from './pages/OAuthCallback'
import ForgotPassword from './pages/ForgotPassword'
import Profile from './pages/Profile'
import Reports from './pages/Reports'
import Visualizer from './pages/Visualizer'
import CheckoutSuccess from './pages/CheckoutSuccess'
import { WebSocketProvider } from './context/WebSocketContext'

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
  component: Login,
})

const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/register',
  component: Register,
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
    <WebSocketProvider>
      <Dashboard />
    </WebSocketProvider>
  ),
  beforeLoad: authCheck,
})

const overviewRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/',
  component: Overview,
})

const serversRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/servers',
  component: Servers,
})

const serverDetailRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/servers/$id',
  component: ServerDetail,
})

const threatsRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/threats',
  component: Threats,
})

const alertsRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: '/alerts',
  component: Alerts,
})

const subscriptionRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: 'subscription',
  component: Subscription,
})

const checkoutSuccessRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: 'subscription/success',
  component: CheckoutSuccess,
})

const oauthCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/oauth/callback',
  component: OAuthCallback,
})

const forgotPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/forgot-password',
  component: ForgotPassword,
})

const profileRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: 'profile',
  component: Profile,
})

const reportsRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: 'reports',
  component: Reports,
})

const visualizerRoute = createRoute({
  getParentRoute: () => dashboardRoute,
  path: 'visualizer',
  component: Visualizer,
})

// 3. Register the route tree
const routeTree = rootRoute.addChildren([
  loginRoute,
  registerRoute,
  forgotPasswordRoute,
  oauthCallbackRoute,
  dashboardRoute.addChildren([
    overviewRoute,
    serversRoute,
    serverDetailRoute,
    threatsRoute,
    alertsRoute,
    subscriptionRoute,
    checkoutSuccessRoute,
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
