import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('kerneleye_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// API methods
export const authAPI = {
  login: (email: string, password: string) => api.post('/auth/login', { email, password }),
  register: (email: string, password: string) => api.post('/auth/register', { email, password }),
  getMe: () => api.get('/auth/me'),
};

export const serversAPI = {
  list: () => api.get('/servers'),
  get: (id: string) => api.get(`/servers/${id}`),
  generateApiKey: () => api.get('/servers/generate-api-key'),
  updateStatus: (id: string, status: string) => api.patch(`/servers/${id}/status`, { status }),
  getTraffic: (id: string, limit = 50) => api.get(`/servers/${id}/traffic?limit=${limit}`),
  getStats: (id: string) => api.get(`/servers/${id}/stats`),
  delete: (id: string) => api.delete(`/servers/${id}`),
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

export default api;

// Add generic error handler to catch 401s (token expiry)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Clear token and redirect to login
      localStorage.removeItem('kerneleye_token');

      // Avoid redirect loops if already on login
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
