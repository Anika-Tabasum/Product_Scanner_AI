import { useQuery, useQueryClient } from "@tanstack/react-query";

export function useCredits() {
  const queryClient = useQueryClient();

  const { data: credits, refetch: refetchCredits } = useQuery({
    queryKey: ["credits"],
    queryFn: async () => {
      const response = await fetch("/api/credits");
      if (!response.ok) {
        throw new Error("Failed to fetch credits");
      }
      const data = await response.json();
      return data.balance;
    },
    // Refresh every minute
    refetchInterval: 60000,
  });

  const { data: history, refetch: refetchHistory } = useQuery({
    queryKey: ["/api/credits/history"],
    queryFn: async () => {
      const response = await fetch("/api/credits/history");
      if (!response.ok) {
        throw new Error("Failed to fetch credit history");
      }
      return response.json();
    },
  });

  const refetchAll = async () => {
    await Promise.all([
      refetchCredits(),
      refetchHistory()
    ]);
  };

  return {
    credits: credits ?? 0,
    history: history ?? [],
    refetchCredits: refetchAll,
  };
}
