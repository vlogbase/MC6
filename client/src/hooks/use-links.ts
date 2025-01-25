import { useQuery } from '@tanstack/react-query';
import type { SelectLink } from "@db/schema";

export function useLinks() {
  const { data: links, isLoading } = useQuery<SelectLink[]>({
    queryKey: ['/api/links'],
    enabled: false // Disable this query since we don't need it right now
  });

  return {
    links: [],
    isLoading: false,
    createLink: async () => { throw new Error('Not implemented'); },
  };
}