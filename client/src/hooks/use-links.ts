import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { InsertLink, SelectLink } from "@db/schema";

export function useLinks() {
  const queryClient = useQueryClient();

  const { data: links, isLoading } = useQuery<SelectLink[]>({
    queryKey: ['/api/links'],
  });

  const createLinkMutation = useMutation<SelectLink, Error, InsertLink>({
    mutationFn: async (linkData) => {
      const response = await fetch('/api/links', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(linkData),
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }

      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/links'] });
    },
  });

  return {
    links,
    isLoading,
    createLink: createLinkMutation.mutateAsync,
  };
}
