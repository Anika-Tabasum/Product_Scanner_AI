import { useCredits } from "@/hooks/use-credits";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Coins, CreditCard, History, ArrowUp, ArrowDown } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { format } from "date-fns";
import { Link } from "wouter";

export default function CreditsPage() {
  const { credits } = useCredits();
  const { user } = useAuth();

  const { data: history } = useQuery({
    queryKey: ["/api/credits/history"],
    queryFn: async () => {
      const response = await fetch("/api/credits/history");
      if (!response.ok) {
        throw new Error("Failed to fetch credit history");
      }
      return response.json();
    },
  });

  return (
    <div className="container mx-auto py-8 px-4">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold mb-8">Credits Dashboard</h1>
        
        <div className="grid gap-6">
          {/* Current Balance Card */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Coins className="h-6 w-6" />
                Current Balance
              </CardTitle>
              <CardDescription>Your available credits for product identification</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold">{credits} Credits</div>
            </CardContent>
          </Card>

          {/* Credit Packages */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CreditCard className="h-6 w-6" />
                Purchase Credits
              </CardTitle>
              <CardDescription>Choose a credit package to continue identifying products</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <Button className="h-auto py-4 flex flex-col gap-2" variant="outline">
                  <div className="text-2xl font-bold">50 Credits</div>
                  <div className="text-muted-foreground">$4.99</div>
                </Button>
                <Button className="h-auto py-4 flex flex-col gap-2" variant="outline">
                  <div className="text-2xl font-bold">100 Credits</div>
                  <div className="text-muted-foreground">$8.99</div>
                </Button>
                <Button className="h-auto py-4 flex flex-col gap-2" variant="outline">
                  <div className="text-2xl font-bold">200 Credits</div>
                  <div className="text-muted-foreground">$15.99</div>
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Credit Usage History */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <History className="h-6 w-6" />
                Credit Usage History
              </CardTitle>
              <CardDescription>Track your credit usage over time</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {history?.length === 0 ? (
                  <div className="text-sm text-muted-foreground text-center py-4">
                    No credit usage history yet
                  </div>
                ) : (
                  history?.map((item: any) => (
                    <div key={item.id} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center gap-3">
                        {item.amount > 0 ? (
                          <div className="p-2 bg-green-100 rounded-full">
                            <ArrowUp className="h-4 w-4 text-green-600" />
                          </div>
                        ) : (
                          <div className="p-2 bg-red-100 rounded-full">
                            <ArrowDown className="h-4 w-4 text-red-600" />
                          </div>
                        )}
                        <div>
                          <div className="font-medium">
                            {item.amount > 0 ? "Credits Added" : "Credits Used"}
                          </div>
                          <div className="text-sm text-muted-foreground">
                            {format(new Date(item.createdAt), "MMM d, yyyy 'at' h:mm a")}
                          </div>
                        </div>
                      </div>
                      <div className={`font-bold ${item.amount > 0 ? "text-green-600" : "text-red-600"}`}>
                        {item.amount > 0 ? "+" : ""}{item.amount} credits
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
