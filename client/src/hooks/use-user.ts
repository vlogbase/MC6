import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { InsertUser, SelectUser } from "@db/schema";
import { useToast } from "@/hooks/use-toast";

type RequestResult = {
  ok: true;
  user?: SelectUser;
} | {
  ok: false;
  message: string;
};

async function fetchUser(): Promise<SelectUser | null> {
  const response = await fetch('/api/user', {
    credentials: 'include'
  });

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
  return data;  // API returns the user data directly
}

async function handleRequest(
  url: string,
  method: string,
  body?: InsertUser
): Promise<RequestResult> {
  try {
    const response = await fetch(url, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      credentials: "include",
    });

    if (!response.ok) {
      if (response.status >= 500) {
        return { ok: false, message: response.statusText };
      }

      const message = await response.text();
      return { ok: false, message };
    }

    const data = await response.json();
    return { ok: true, user: data.user };
  } catch (e: any) {
    return { ok: false, message: e.toString() };
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
      }
    },
  });

  const logoutMutation = useMutation<RequestResult, Error>({
    mutationFn: () => handleRequest('/api/logout', 'POST'),
    onSuccess: () => {
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