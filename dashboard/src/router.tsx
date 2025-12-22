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
import { WebSocketProvider } from './context/WebSocketContext'

// Auth check helper
const authCheck = (location: any) => {
  const token = localStorage.getItem('kerneleye_token')
  if (!token) {
    throw redirect({
      to: '/login',
      search: {
        // Use the current location so we can redirect back after login (if we implement that)
        redirect: location.href,
      },
    })
  }
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
  component: () => (
    <WebSocketProvider>
      <Dashboard />
    </WebSocketProvider>
  ), 
  beforeLoad: ({ location }) => authCheck(location),
})

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'dashboard',
  component: () => (
    <WebSocketProvider>
      <Dashboard />
    </WebSocketProvider>
  ),
  beforeLoad: ({ location }) => authCheck(location),
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

// 3. Register the route tree
const routeTree = rootRoute.addChildren([
  loginRoute,
  registerRoute,
  dashboardRoute.addChildren([
    overviewRoute,
    serversRoute,
    serverDetailRoute,
    threatsRoute,
    alertsRoute,
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
