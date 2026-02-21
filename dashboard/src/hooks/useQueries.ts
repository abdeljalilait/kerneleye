import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { serversAPI, threatsAPI, alertsAPI, statsAPI, authAPI, subscriptionAPI, analyticsAPI, agentConfigAPI } from '../api/client';
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

// Agent configuration hooks
export const useDeploymentModes = () => {
  return useQuery({
    queryKey: ['deployment-modes'],
    queryFn: async () => {
      const { data } = await agentConfigAPI.getDeploymentModes();
      return data as Array<{
        key: string;
        name: string;
        description: string;
        requirements: string;
        performance: string;
        compatibility: string;
      }>;
    },
  });
};

export const useAgentFeatures = () => {
  return useQuery({
    queryKey: ['agent-features'],
    queryFn: async () => {
      const { data } = await agentConfigAPI.getFeatures();
      return data as Array<{
        key: string;
        name: string;
        description: string;
        flag: string;
        env_var: string;
        default_value: boolean;
        available_in: string[];
        details: string;
        example: string;
        benefits: string[];
        risks?: string[];
      }>;
    },
  });
};

export const useServerConfig = (id: string | undefined) => {
  return useQuery({
    queryKey: ['server', id, 'config'],
    queryFn: async () => {
      const { data } = await serversAPI.getConfig(id!);
      return data as {
        mode: string;
        features: Record<string, boolean>;
        threshold: number;
        duration: string;
      };
    },
    enabled: !!id,
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

export const useCreateServerWithConfig = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { server_name: string; config: any }) => {
      const { data: response } = await serversAPI.create(data);
      return response as {
        api_key: string;
        server_id: string;
        commands: Record<string, string>;
        environment: Record<string, string>;
      };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] });
    },
  });
};

export const useUpdateServerConfig = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, config }: { id: string; config: any }) => {
      const { data } = await serversAPI.updateConfig(id, config);
      return data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['server', variables.id, 'config'] });
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

export interface CheckoutResponse {
  checkout_url: string;
  session_id?: string;
  customer_email: string;
  metadata: any;
  embedded?: boolean;
}

export const useCreateCheckout = () => {
  return useMutation({
    mutationFn: async ({ planName, embedOrigin }: { planName: string; embedOrigin?: string }) => {
      const { data } = await subscriptionAPI.createCheckout(planName, embedOrigin);
      return data as CheckoutResponse;
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

// ============================================
// ANALYTICS HOOKS (Reports & Visualizer)
// ============================================

// Reports hooks
export const useDailyAttackStats = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'daily-attacks', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getDailyAttacks(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useAttackTypeBreakdown = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'attack-types', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getAttackTypes(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useTopSourceCountries = (startDate?: string, endDate?: string, limit?: number) => {
  return useQuery({
    queryKey: ['analytics', 'top-countries', startDate, endDate, limit],
    queryFn: async () => {
      const { data } = await analyticsAPI.getTopCountries(startDate, endDate, limit);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useHourlyAttackDistribution = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'hourly-distribution', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getHourlyDistribution(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useThreatTrends = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'threat-trends', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getThreatTrends(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

// Visualizer hooks
export const useTopSourceIPs = (startDate?: string, endDate?: string, limit?: number) => {
  return useQuery({
    queryKey: ['analytics', 'top-source-ips', startDate, endDate, limit],
    queryFn: async () => {
      const { data } = await analyticsAPI.getTopSourceIPs(startDate, endDate, limit);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useTopASNs = (startDate?: string, endDate?: string, limit?: number) => {
  return useQuery({
    queryKey: ['analytics', 'top-asns', startDate, endDate, limit],
    queryFn: async () => {
      const { data } = await analyticsAPI.getTopASNs(startDate, endDate, limit);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useSourceIPTimeline = (ip?: string) => {
  return useQuery({
    queryKey: ['analytics', 'ip-timeline', ip],
    queryFn: async () => {
      if (!ip) return [];
      const { data } = await analyticsAPI.getSourceIPTimeline(ip);
      return data.data;
    },
    enabled: !!ip,
  });
};
