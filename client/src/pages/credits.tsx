import { useCredits } from "@/hooks/use-credits";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Coins, CreditCard, History } from "lucide-react";
import { Link } from "wouter";

export default function CreditsPage() {
  const { credits } = useCredits();
  const { user } = useAuth();

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
              <div className="text-sm text-muted-foreground">
                Coming soon - detailed history of your credit usage
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
