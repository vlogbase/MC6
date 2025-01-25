import { useQuery } from "@tanstack/react-query";
import { format, subDays } from "date-fns";

type StrackrStats = {
  transactions: any[];
  revenues: any[];
  clicks: any[];
  isLoading: boolean;
  error: Error | null;
};

export function useStrackrStats(days = 30): StrackrStats {
  const timeEnd = format(new Date(), 'yyyy-MM-dd');
  const timeStart = format(subDays(new Date(), days), 'yyyy-MM-dd');

  // Return empty data since we don't need stats right now
  return {
    transactions: [],
    revenues: [],
    clicks: [],
    isLoading: false,
    error: null
  };
}