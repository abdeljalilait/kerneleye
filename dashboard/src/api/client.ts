import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

// Extend Axios config to include custom _retry flag
interface CustomAxiosRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
}

// Get API URL from build-time environment variable
const getApiUrl = (): string => {
  return import.meta.env.VITE_API_URL || '/api/v1';
};

const API_BASE_URL = getApiUrl();

// Public API client - no auth headers (for login, register, OAuth providers)
export const publicApi = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Authenticated API client - adds auth headers to all requests
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to authenticated requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('kerneleye_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// API methods
export const authAPI = {
  // Public endpoints (no auth required)
  login: (email: string, password: string) => publicApi.post('/auth/login', { email, password }),
  register: (email: string, password: string) => publicApi.post('/auth/register', { email, password }),
  getProviders: () => publicApi.get('/auth/providers'),
  
  // Protected endpoints (requires auth)
  getMe: () => api.get('/auth/me'),
  
  // TODO: Implement when backend has refresh token endpoint
  // refreshToken: (refreshToken: string) => axios.post(`${API_BASE_URL}/auth/refresh`, { refreshToken }),
};

export const serversAPI = {
  list: () => api.get('/servers'),
  get: (id: string) => api.get(`/servers/${id}`),
  generateApiKey: () => api.get('/servers/generate-api-key'),
  create: (data: { server_name: string; config: any }) => api.post('/servers', data),
  updateStatus: (id: string, status: string) => api.patch(`/servers/${id}/status`, { status }),
  getTraffic: (id: string, limit = 50) => api.get(`/servers/${id}/traffic?limit=${limit}`),
  getStats: (id: string) => api.get(`/servers/${id}/stats`),
  getConfig: (id: string) => api.get(`/servers/${id}/config`),
  updateConfig: (id: string, config: any) => api.patch(`/servers/${id}/config`, config),
  delete: (id: string) => api.delete(`/servers/${id}`),
};

export const agentConfigAPI = {
  getDeploymentModes: () => api.get('/deployment-modes'),
  getFeatures: () => api.get('/agent-features'),
};

export const threatsAPI = {
  list: () => api.get('/threats'),
};

export const alertsAPI = {
  list: () => api.get('/alerts'),
};

export const statsAPI = {
  overview: () => api.get('/stats/overview'),
};

export const subscriptionAPI = {
  getPlans: () => api.get('/subscription/plans'),
  getStatus: () => api.get('/subscription/status'),
  createCheckout: (planName: string, embedOrigin?: string) => api.post('/subscription/checkout', { 
    plan_name: planName,
    embed_origin: embedOrigin,
  }),
  createCustomerPortal: () => api.post('/subscription/portal', {}),
};

export const analyticsAPI = {
  // Reports
  getDailyAttacks: (startDate?: string, endDate?: string) => 
    api.get(`/analytics/daily-attacks?start_date=${startDate || ''}&end_date=${endDate || ''}`),
  getAttackTypes: (startDate?: string, endDate?: string) => 
    api.get(`/analytics/attack-types?start_date=${startDate || ''}&end_date=${endDate || ''}`),
  getTopCountries: (startDate?: string, endDate?: string, limit?: number) => 
    api.get(`/analytics/top-countries?start_date=${startDate || ''}&end_date=${endDate || ''}&limit=${limit || 10}`),
  getHourlyDistribution: (startDate?: string, endDate?: string) => 
    api.get(`/analytics/hourly-distribution?start_date=${startDate || ''}&end_date=${endDate || ''}`),
  getThreatTrends: (startDate?: string, endDate?: string) => 
    api.get(`/analytics/threat-trends?start_date=${startDate || ''}&end_date=${endDate || ''}`),
  
  // Visualizer
  getTopSourceIPs: (startDate?: string, endDate?: string, limit?: number) => 
    api.get(`/analytics/top-source-ips?start_date=${startDate || ''}&end_date=${endDate || ''}&limit=${limit || 20}`),
  getTopASNs: (startDate?: string, endDate?: string, limit?: number) => 
    api.get(`/analytics/top-asns?start_date=${startDate || ''}&end_date=${endDate || ''}&limit=${limit || 10}`),
  getSourceIPTimeline: (ip: string) => 
    api.get(`/analytics/ip-timeline?ip=${encodeURIComponent(ip)}`),
};

// ============ TOKEN REFRESH LOGIC ============

// TODO: SECURITY - Current implementation has a flaw:
// When a 401 occurs, we call authAPI.getMe() which uses the SAME expired token.
// This will fail immediately with another 401.
// 
// PROPER SOLUTION:
// 1. Backend must implement a /auth/refresh endpoint that accepts a refresh token
//    (stored in HttpOnly cookie or separate localStorage key)
// 2. This endpoint returns a new access token
// 3. The refresh token should be rotated on each use for security
//
// ALTERNATIVE (Current workaround):
// - Check if session is still valid (getMe succeeds)
// - If not, redirect to login
// - This is NOT true token refresh, just session validation

let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value: string | null) => void;
  reject: (reason?: AxiosError) => void;
}> = [];

const processQueue = (error: AxiosError | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Dispatch auth error event for SPA router to handle
const dispatchAuthError = () => {
  window.dispatchEvent(new CustomEvent('auth:required', {
    detail: { redirectTo: '/login' }
  }));
};

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as CustomAxiosRequestConfig;

    // Handle 401 errors
    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      if (isRefreshing) {
        // Queue the request while refreshing
        return new Promise<string | null>((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          if (token) {
            originalRequest.headers.Authorization = `Bearer ${token}`;
          }
          return api(originalRequest);
        }).catch((err) => {
          return Promise.reject(err);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // WORKAROUND: Check if session is still valid
        // This is NOT proper token refresh - it just validates the current token
        // If the backend session is still active (e.g., token expired but session not),
        // this might succeed. Otherwise, it will fail and we redirect to login.
        // 
        // PROPER IMPLEMENTATION (when backend supports refresh tokens):
        // const { data } = await authAPI.refreshToken(refreshToken);
        // const newToken = data.token;
        // localStorage.setItem('kerneleye_token', newToken);
        
        const { data } = await authAPI.getMe();
        
        if (data) {
          // Session is still valid, extend expiry
          // NOTE: This doesn't actually refresh the token - just validates session
          const newExpiry = new Date().getTime() + 24 * 60 * 60 * 1000;
          localStorage.setItem('kerneleye_session_expiry', newExpiry.toString());
          
          const currentToken = localStorage.getItem('kerneleye_token');
          processQueue(null, currentToken);
          return api(originalRequest);
        }
      } catch (refreshError) {
        // Session validation failed, clear session and notify app
        processQueue(refreshError as AxiosError, null);
        localStorage.removeItem('kerneleye_token');
        localStorage.removeItem('kerneleye_session_expiry');
        
        // Dispatch event for SPA router instead of hard reload
        dispatchAuthError();
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;
