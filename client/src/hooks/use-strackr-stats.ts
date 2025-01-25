import { useQuery } from "@tanstack/react-query";
import { format, subDays } from "date-fns";
import { useUser } from "./use-user";

type StrackrStats = {
  transactions: any[];
  revenues: any[];
  clicks: any[];
  isLoading: boolean;
  error: Error | null;
};

export function useStrackrStats(days = 30): StrackrStats {
  const { user } = useUser();
  const timeEnd = format(new Date(), 'yyyy-MM-dd');
  const timeStart = format(subDays(new Date(), days), 'yyyy-MM-dd');

  const headers = user?.apiKey 
    ? { "X-API-KEY": user.apiKey }
    : undefined;

  const { data: transactions, isLoading: transLoading, error: transError } = useQuery({
    queryKey: [`/api/stats/transactions?timeStart=${timeStart}&timeEnd=${timeEnd}`],
    enabled: !!user?.apiKey,
    queryFn: async ({ queryKey }) => {
      const response = await fetch(queryKey[0] as string, { headers });
      if (!response.ok) {
        throw new Error(`${response.status}: ${await response.text()}`);
      }
      return response.json();
    }
  });

  const { data: revenues, isLoading: revLoading, error: revError } = useQuery({
    queryKey: [`/api/stats/revenues?timeStart=${timeStart}&timeEnd=${timeEnd}`],
    enabled: !!user?.apiKey,
    queryFn: async ({ queryKey }) => {
      const response = await fetch(queryKey[0] as string, { headers });
      if (!response.ok) {
        throw new Error(`${response.status}: ${await response.text()}`);
      }
      return response.json();
    }
  });

  const { data: clicks, isLoading: clicksLoading, error: clicksError } = useQuery({
    queryKey: [`/api/stats/clicks?timeStart=${timeStart}&timeEnd=${timeEnd}`],
    enabled: !!user?.apiKey,
    queryFn: async ({ queryKey }) => {
      const response = await fetch(queryKey[0] as string, { headers });
      if (!response.ok) {
        throw new Error(`${response.status}: ${await response.text()}`);
      }
      return response.json();
    }
  });

  return {
    transactions: transactions?.results || [],
    revenues: revenues?.results || [],
    clicks: clicks?.results || [],
    isLoading: transLoading || revLoading || clicksLoading,
    error: transError || revError || clicksError || null
  };
}