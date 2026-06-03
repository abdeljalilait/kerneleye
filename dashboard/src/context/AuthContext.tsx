import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from '@tanstack/react-router';
import api from '../api/client';

interface User {
  id: string;
  email: string;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (token: string) => Promise<void>;
  logout: () => void;
  refreshSession: () => Promise<boolean>;
  getToken: () => string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = 'kerneleye_token';
const SESSION_EXPIRY_KEY = 'kerneleye_session_expiry';
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Clear session data
  const clearSession = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(SESSION_EXPIRY_KEY);
    setUser(null);
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
  }, []);

  // Get current token
  const getToken = useCallback(() => {
    return localStorage.getItem(TOKEN_KEY);
  }, []);

  // Check if session is valid
  const isSessionValid = useCallback(() => {
    const expiry = localStorage.getItem(SESSION_EXPIRY_KEY);
    if (!expiry) return false;
    return new Date().getTime() < parseInt(expiry, 10);
  }, []);

  // Fetch user profile
  const fetchUserProfile = useCallback(async (): Promise<User | null> => {
    try {
      const { data } = await api.get('/auth/me');
      return data;
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
      return null;
    }
  }, []);

  // Setup token refresh timer
  const setupRefreshTimer = useCallback(() => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
    }

    // Refresh 5 minutes before expiry
    const expiry = localStorage.getItem(SESSION_EXPIRY_KEY);
    if (expiry) {
      const expiryTime = parseInt(expiry, 10);
      const refreshTime = expiryTime - 5 * 60 * 1000; // 5 minutes before expiry
      const now = new Date().getTime();
      const delay = Math.max(0, refreshTime - now);

      refreshTimerRef.current = setTimeout(() => {
        refreshSession();
      }, delay);
    }
  }, []);

  // Login with token (from OAuth callback or regular login)
  const login = useCallback(async (token: string) => {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(SESSION_EXPIRY_KEY, (new Date().getTime() + SESSION_DURATION).toString());
    
    const userData = await fetchUserProfile();
    if (userData) {
      setUser(userData);
      setupRefreshTimer();
    } else {
      clearSession();
      throw new Error('Failed to fetch user profile');
    }
  }, [fetchUserProfile, setupRefreshTimer, clearSession]);

  // Logout
  const logout = useCallback(() => {
    clearSession();
    navigate({ to: '/login' });
  }, [clearSession, navigate]);

  // Refresh session
  const refreshSession = useCallback(async (): Promise<boolean> => {
    const token = getToken();
    if (!token) return false;

    try {
      const userData = await fetchUserProfile();
      if (userData) {
        setUser(userData);
        // Extend session expiry
        localStorage.setItem(SESSION_EXPIRY_KEY, (new Date().getTime() + SESSION_DURATION).toString());
        setupRefreshTimer();
        return true;
      }
    } catch (error) {
      console.error('Session refresh failed:', error);
    }

    clearSession();
    return false;
  }, [getToken, fetchUserProfile, setupRefreshTimer, clearSession]);

  // Initialize auth state on mount
  useEffect(() => {
    const initAuth = async () => {
      setIsLoading(true);
      
      const token = getToken();
      if (!token) {
        setIsLoading(false);
        return;
      }

      // Check if session is still valid
      if (!isSessionValid()) {
        clearSession();
        setIsLoading(false);
        return;
      }

      // Try to restore session
      const success = await refreshSession();
      if (!success) {
        clearSession();
      }
      
      setIsLoading(false);
    };

    initAuth();

    return () => {
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
      }
    };
  }, []);

  // Listen for storage changes (multi-tab support)
  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === TOKEN_KEY) {
        if (!e.newValue) {
          // Token was removed in another tab
          setUser(null);
          navigate({ to: '/login' });
        } else if (e.newValue !== e.oldValue) {
          // Token was updated in another tab
          refreshSession();
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [refreshSession, navigate]);

  // Listen for auth:required events from API client (token refresh failures)
  useEffect(() => {
    const handleAuthRequired = (e: CustomEvent<{ redirectTo: string }>) => {
      clearSession();
      // Avoid redirect loops if already on login
      if (!window.location.pathname.includes('/login')) {
        navigate({ to: e.detail.redirectTo as '/login' });
      }
    };

    window.addEventListener('auth:required', handleAuthRequired as EventListener);
    return () => window.removeEventListener('auth:required', handleAuthRequired as EventListener);
  }, [clearSession, navigate]);

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    refreshSession,
    getToken,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// Hook to use auth context
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
