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
  withCredentials: true,
});

// Authenticated API client - adds auth headers to all requests
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
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
  
  // Refresh token - uses HttpOnly cookie, returns new access token
  refreshToken: () => publicApi.post('/auth/refresh'),
};

export const serversAPI = {
  list: () => api.get('/servers'),
  get: (id: string) => api.get(`/servers/${id}`),
  generateApiKey: () => api.get('/servers/generate-api-key'),
  create: (data: { server_name: string; config: any }) => api.post('/servers', data),
  updateStatus: (id: string, status: string) => api.patch(`/servers/${id}/status`, { status }),
  getTraffic: (id: string, params?: { page?: number; page_size?: number; search?: string; threat_level?: string; sort_by?: string; from?: string; to?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', String(params.page));
    if (params?.page_size) queryParams.set('page_size', String(params.page_size));
    if (params?.search) queryParams.set('search', params.search);
    if (params?.threat_level) queryParams.set('threat_level', params.threat_level);
    if (params?.sort_by) queryParams.set('sort_by', params.sort_by);
    if (params?.from) queryParams.set('from', params.from);
    if (params?.to) queryParams.set('to', params.to);
    const query = queryParams.toString();
    return api.get(`/servers/${id}/traffic${query ? `?${query}` : ''}`);
  },
  getPortTraffic: (id: string, params?: { page?: number; page_size?: number; search?: string; threat_level?: string; sort_by?: string; from?: string; to?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', String(params.page));
    if (params?.page_size) queryParams.set('page_size', String(params.page_size));
    if (params?.search) queryParams.set('search', params.search);
    if (params?.threat_level) queryParams.set('threat_level', params.threat_level);
    if (params?.sort_by) queryParams.set('sort_by', params.sort_by);
    if (params?.from) queryParams.set('from', params.from);
    if (params?.to) queryParams.set('to', params.to);
    const query = queryParams.toString();
    return api.get(`/servers/${id}/port-traffic${query ? `?${query}` : ''}`);
  },
  getProtocolTraffic: (id: string, params?: { page?: number; page_size?: number; search?: string; threat_level?: string; sort_by?: string; from?: string; to?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', String(params.page));
    if (params?.page_size) queryParams.set('page_size', String(params.page_size));
    if (params?.search) queryParams.set('search', params.search);
    if (params?.threat_level) queryParams.set('threat_level', params.threat_level);
    if (params?.sort_by) queryParams.set('sort_by', params.sort_by);
    if (params?.from) queryParams.set('from', params.from);
    if (params?.to) queryParams.set('to', params.to);
    const query = queryParams.toString();
    return api.get(`/servers/${id}/protocol-traffic${query ? `?${query}` : ''}`);
  },
  getPortSources: (id: string, port: number, protocol: string, params?: { page?: number; page_size?: number; search?: string; sort_by?: string; sort_order?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', String(params.page));
    if (params?.page_size) queryParams.set('page_size', String(params.page_size));
    if (params?.search) queryParams.set('search', params.search);
    if (params?.sort_by) queryParams.set('sort_by', params.sort_by);
    if (params?.sort_order) queryParams.set('sort_order', params.sort_order);
    const query = queryParams.toString();
    return api.get(`/servers/${id}/port-traffic/${port}/sources?protocol=${protocol}${query ? `&${query}` : ''}`);
  },
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

export const blocksAPI = {
  list: (params?: { page?: number; page_size?: number; server?: string; status?: string }) => 
    api.get('/blocks', { params }),
  stats: () => api.get('/blocks/stats'),
  unblock: (ip: string, reason?: string) => 
    api.post(`/blocks/${encodeURIComponent(ip)}/unblock`, { reason }),
};

export const whitelistAPI = {
  list: () => api.get('/whitelist'),
  add: (ip: string, reason?: string) => 
    api.post('/whitelist', { ip_address: ip, reason }),
  remove: (ip: string) => 
    api.delete(`/whitelist/${encodeURIComponent(ip)}`),
  check: (ip: string) => 
    api.get(`/whitelist/check?ip=${encodeURIComponent(ip)}`),
};

export const alertsAPI = {
  list: () => api.get('/alerts'),
};

export const statsAPI = {
  overview: () => api.get('/stats/overview'),
};

export const analyticsAPI = {
  // Reports
  getDailyAttacks: (startDate?: string, endDate?: string) => 
    api.get(`/analytics/daily-attacks?start_date=${startDate || ''}&end_date=${endDate || ''}`),
  getDailyBlocks: (startDate?: string, endDate?: string) => 
    api.get(`/analytics/daily-blocks?start_date=${startDate || ''}&end_date=${endDate || ''}`),
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
  getSourceIPTimeline: (ip: string, startDate?: string, endDate?: string) => 
    api.get(
      `/analytics/ip-timeline?ip=${encodeURIComponent(ip)}&start_date=${startDate || ''}&end_date=${endDate || ''}`
    ),
  getSourceIPBlockTimes: (ip: string, startDate?: string, endDate?: string) =>
    api.get(
      `/analytics/ip-block-times?ip=${encodeURIComponent(ip)}&start_date=${startDate || ''}&end_date=${endDate || ''}`
    ),
  getTopIPsTimeline: (sortBy: 'hits' | 'score', limit: number, startDate?: string, endDate?: string) =>
    api.get(
      `/analytics/top-ips-timeline?sort_by=${sortBy}&limit=${limit}&start_date=${startDate || ''}&end_date=${endDate || ''}`
    ),
};

// ============ TOKEN REFRESH LOGIC ============

// Token refresh is now handled via HttpOnly cookies:
// 1. On login/OAuth, backend sets a refresh token in an HttpOnly cookie
// 2. On 401, frontend calls /auth/refresh which uses the cookie
// 3. Backend validates, rotates, and returns new access token
// 4. Frontend stores new access token in localStorage

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
        // Use the refresh token endpoint (HttpOnly cookie handles the refresh token)
        const { data } = await authAPI.refreshToken();
        const newToken = data.token;
        
        // Store the new access token
        localStorage.setItem('kerneleye_token', newToken);
        
        // Process queued requests with new token
        processQueue(null, newToken);
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh token invalid/expired, clear session and notify app
        processQueue(refreshError as AxiosError, null);
        localStorage.removeItem('kerneleye_token');
        
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
