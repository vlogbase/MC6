import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { InsertUser, SelectUser } from "@db/schema";
import { useToast } from "@/hooks/use-toast";

type RequestResult = {
  ok: true;
  user?: SelectUser;
  accessToken?: string;
  refreshToken?: string;
} | {
  ok: false;
  message: string;
};

// Token management
const TOKEN_KEY = 'auth_token';
const REFRESH_TOKEN_KEY = 'refresh_token';

function setTokens(accessToken: string, refreshToken: string) {
  localStorage.setItem(TOKEN_KEY, accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
}

function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function getStoredRefreshToken() {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

async function refreshTokens(): Promise<boolean> {
  const refreshToken = getStoredRefreshToken();
  if (!refreshToken) return false;

  try {
    const response = await fetch('/api/refresh-token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) {
      clearTokens();
      return false;
    }

    const data = await response.json();
    setTokens(data.accessToken, data.refreshToken);
    return true;
  } catch (error) {
    clearTokens();
    return false;
  }
}

async function fetchWithToken(url: string, options: RequestInit = {}): Promise<Response> {
  const token = getStoredToken();
  if (token) {
    options.headers = {
      ...options.headers,
      'Authorization': `Bearer ${token}`
    };
  }

  const response = await fetch(url, { ...options, credentials: 'include' });

  if (response.status === 401 && await refreshTokens()) {
    // Retry with new token
    const newToken = getStoredToken();
    if (newToken) {
      options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${newToken}`
      };
      return fetch(url, { ...options, credentials: 'include' });
    }
  }

  return response;
}

async function fetchUser(): Promise<SelectUser | null> {
  const response = await fetchWithToken('/api/user');

  if (!response.ok) {
    if (response.status === 401) {
      return null;
    }

    if (response.status >= 500) {
      throw new Error(`${response.status}: ${response.statusText}`);
    }

    throw new Error(`${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  return data;
}

async function handleRequest(
  url: string,
  method: string,
  body?: InsertUser
): Promise<RequestResult> {
  try {
    const response = await fetchWithToken(url, {
      method,
      headers: {
        "Content-Type": "application/json"
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = await response.json();

    if (!response.ok) {
      // Extract error message safely
      const errorMessage = typeof data.error === 'string' 
        ? data.error 
        : (data.error?.message || data.message || "An unexpected error occurred");

      console.error("Auth error:", { url, status: response.status, error: errorMessage });
      return { ok: false, message: errorMessage };
    }

    if (data.accessToken && data.refreshToken) {
      setTokens(data.accessToken, data.refreshToken);
    }

    return { 
      ok: true, 
      user: data.user, 
      accessToken: data.accessToken, 
      refreshToken: data.refreshToken 
    };
  } catch (e: any) {
    const errorMessage = e?.message || "Failed to complete request";
    console.error("Auth request error:", errorMessage);
    return { ok: false, message: errorMessage };
  }
}

export function useUser() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: user, error, isLoading } = useQuery<SelectUser | null, Error>({
    queryKey: ['/api/user'],
    queryFn: fetchUser,
    staleTime: Infinity,
    retry: false
  });

  const loginMutation = useMutation<RequestResult, Error, InsertUser>({
    mutationFn: (userData) => handleRequest('/api/login', 'POST', userData),
    onSuccess: (result) => {
      if (result.ok && result.user) {
        queryClient.setQueryData(['/api/user'], result.user);
        toast({
          title: "Success",
          description: "Successfully logged in",
        });
      } else if (!result.ok) {
        toast({
          variant: "destructive",
          title: "Login failed",
          description: result.message,
        });
      }
    },
  });

  const logoutMutation = useMutation<RequestResult, Error>({
    mutationFn: () => handleRequest('/api/logout', 'POST'),
    onSuccess: () => {
      clearTokens();
      queryClient.setQueryData(['/api/user'], null);
      toast({
        title: "Success",
        description: "Successfully logged out",
      });
    },
  });

  const registerMutation = useMutation<RequestResult, Error, InsertUser>({
    mutationFn: (userData) => handleRequest('/api/register', 'POST', userData),
    onSuccess: (result) => {
      if (result.ok && result.user) {
        queryClient.setQueryData(['/api/user'], result.user);
        toast({
          title: "Success",
          description: "Successfully registered",
        });
      } else if (!result.ok) {
        toast({
          variant: "destructive",
          title: "Registration failed",
          description: result.message,
        });
      }
    },
  });

  return {
    user,
    isLoading,
    error,
    login: loginMutation.mutateAsync,
    logout: logoutMutation.mutateAsync,
    register: registerMutation.mutateAsync,
  };
}