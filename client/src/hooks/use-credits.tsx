import { useQuery } from "@tanstack/react-query";

export function useCredits() {
  const { data: credits, refetch } = useQuery({
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

  return {
    credits: credits ?? 0,
    refetchCredits: refetch,
  };
}
