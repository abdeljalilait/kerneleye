import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { serversAPI, threatsAPI, alertsAPI, statsAPI, authAPI, subscriptionAPI } from '../api/client';
import { Server, Threat, Alert, StatsOverview } from '../types';

export const useServers = () => {
  return useQuery({
    queryKey: ['servers'],
    queryFn: async () => {
      const { data } = await serversAPI.list();
      return data as Server[];
    },
  });
};

export const useThreats = () => {
  return useQuery({
    queryKey: ['threats'],
    queryFn: async () => {
      const { data } = await threatsAPI.list();
      return data as Threat[];
    },
  });
};

export const useAlerts = () => {
  return useQuery({
    queryKey: ['alerts'],
    queryFn: async () => {
      const { data } = await alertsAPI.list();
      return data as Alert[];
    },
  });
};

export const useStats = () => {
  return useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      const { data } = await statsAPI.overview();
      return data as StatsOverview;
    },
  });
};

// Server detail hooks
export const useServer = (id: string | undefined) => {
  return useQuery({
    queryKey: ['server', id],
    queryFn: async () => {
      const { data } = await serversAPI.get(id!);
      return data as {
        id: string;
        hostname: string;
        status: string;
        ip_address: string | null;
        agent_version: string | null;
        cpu_usage: number;
        memory_usage: number;
        uptime_seconds: number;
        last_seen: string;
      };
    },
    enabled: !!id,
  });
};

export const useServerStats = (id: string | undefined) => {
  return useQuery({
    queryKey: ['server', id, 'stats'],
    queryFn: async () => {
      const { data } = await serversAPI.getStats(id!);
      return data as {
        total_events: number;
        events_last_24h: number;
        threat_events: number;
        total_bytes_in: number;
        total_bytes_out: number;
      };
    },
    enabled: !!id,
  });
};

export const useServerTraffic = (id: string | undefined, limit: number = 100) => {
  return useQuery({
    queryKey: ['server', id, 'traffic', limit],
    queryFn: async () => {
      const { data } = await serversAPI.getTraffic(id!, limit);
      return data as Array<{
        id: string;
        source_ip: string;
        destination_port: number;
        protocol: string;
        syn_count: number;
        ack_count: number;
        failed_handshakes: number;
        unique_ports: number;
        bytes_in: number;
        bytes_out: number;
        threat_score: number;
        threat_level: string;
        country: string | null;
        city: string | null;
        isp: string | null;
        hit_count: number;
        first_seen: string;
        last_seen: string;
        created_at: string;
      }>;
    },
    enabled: !!id,
  });
};

// ============ MUTATIONS ============

// Auth mutations & queries
export const useProfile = () => {
  return useQuery({
    queryKey: ['profile'],
    queryFn: async () => {
      const { data } = await authAPI.getMe();
      return data as { id: string; email: string; plan: string };
    },
  });
};

export interface OAuthProvider {
  id: string;
  name: string;
  icon: string;
}

export const useOAuthProviders = () => {
  return useQuery({
    queryKey: ['auth', 'providers'],
    queryFn: async () => {
      const { data } = await authAPI.getProviders();
      return data.providers as OAuthProvider[];
    },
    staleTime: 5 * 60 * 1000, // 5 minutes - providers don't change often
  });
};

export const useLogin = () => {
  return useMutation({
    mutationFn: async ({ email, password }: { email: string; password: string }) => {
      const { data } = await authAPI.login(email, password);
      return data as { token: string };
    },
  });
};

export const useRegister = () => {
  return useMutation({
    mutationFn: async ({ email, password }: { email: string; password: string }) => {
      const { data } = await authAPI.register(email, password);
      return data as { token: string };
    },
  });
};

// Server mutations
export const useGenerateApiKey = () => {
  return useMutation({
    mutationFn: async () => {
      const { data } = await serversAPI.generateApiKey();
      return data as { api_key: string };
    },
  });
};

export const useCreateServer = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (_hostname: string) => {
      const { data } = await serversAPI.generateApiKey();
      return data as { api_key: string; install_command: string };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] });
    },
  });
};

export const useUpdateServerStatus = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const { data } = await serversAPI.updateStatus(id, status);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] });
    },
  });
};

export const useDeleteServer = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await serversAPI.delete(id);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['threats'] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
};

// ============ SUBSCRIPTION HOOKS ============

export interface Plan {
  id: string;
  name: string;
  display_name: string;
  description: string;
  price_cents: number;
  currency: string;
  billing_interval: string;
  max_servers: number;
  data_retention_days: number;
  features: Record<string, any>;
  is_default: boolean;
  polar_price_id?: string;
}

export interface SubscriptionStatus {
  plan: string;
  plan_display_name: string;
  status: string;
  max_servers: number;
  current_servers: number;
  data_retention_days: number;
  features: Record<string, any>;
  current_period_start?: string;
  current_period_end?: string;
  cancel_at_period_end: boolean;
  trial_ends_at?: string;
  is_trialing: boolean;
}

export const useSubscriptionPlans = () => {
  return useQuery({
    queryKey: ['subscription', 'plans'],
    queryFn: async () => {
      const { data } = await subscriptionAPI.getPlans();
      return data as Plan[];
    },
  });
};

export const useSubscriptionStatus = () => {
  return useQuery({
    queryKey: ['subscription', 'status'],
    queryFn: async () => {
      const { data } = await subscriptionAPI.getStatus();
      return data as SubscriptionStatus;
    },
  });
};

export const useCreateCheckout = () => {
  return useMutation({
    mutationFn: async (planName: string) => {
      const { data } = await subscriptionAPI.createCheckout(planName);
      return data as { checkout_url: string; session_id?: string; customer_email: string; metadata: any };
    },
  });
};

export const useCreateCustomerPortal = () => {
  return useMutation({
    mutationFn: async () => {
      const { data } = await subscriptionAPI.createCustomerPortal();
      return data as { portal_url: string };
    },
  });
};
