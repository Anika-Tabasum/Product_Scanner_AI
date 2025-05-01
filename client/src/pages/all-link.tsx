import { useEffect, useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { insertUserSchema } from "@shared/schema";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

// List of all route links (add more as needed)
const ALL_LINKS = [
  { path: "/", label: "Home" },
  { path: "/profile", label: "Profile" },
  { path: "/plugin-demo", label: "Plugin Demo" },
  { path: "/ggs-visualization", label: "GGS Visualization" },
  { path: "/admin", label: "Admin Dashboard" },
  { path: "/all-link", label: "All Links" },
];

export default function AllLinkPage() {
  const { user, loginMutation, isLoading } = useAuth();
  const { toast } = useToast();
  const [showLogin, setShowLogin] = useState(false);

  // Login form
  const loginForm = useForm({
    resolver: zodResolver(insertUserSchema.pick({ username: true, password: true })),
    defaultValues: { username: "", password: "" },
  });

  useEffect(() => {
    // If not admin, show login form
    if (user && user.role !== "admin") {
      setShowLogin(true);
    } else {
      setShowLogin(false);
    }
  }, [user]);

  const onLogin = async (values: { username: string; password: string }) => {
    try {
      await loginMutation.mutateAsync(values);
      toast({ title: "Login successful!" });
      setShowLogin(false);
    } catch (error: any) {
      toast({
        title: "Login failed",
        description: error?.message || "Invalid credentials",
        variant: "destructive",
      });
    }
  };

  if (isLoading) {
    return <div className="flex items-center justify-center min-h-screen">Loading...</div>;
  }

  if (!user || showLogin) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Admin Privilege Needed</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="mb-4 text-sm text-muted-foreground">You must be an admin to view all links.</p>
            <form onSubmit={loginForm.handleSubmit(onLogin)} className="space-y-4">
              <Input {...loginForm.register("username")} placeholder="Username" />
              <Input {...loginForm.register("password")} type="password" placeholder="Password" />
              <Button type="submit" className="w-full" disabled={loginMutation.isPending}>
                {loginMutation.isPending ? "Signing in..." : "Sign in as Admin"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  // If admin, show all links
  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <Card className="w-full max-w-lg">
        <CardHeader>
          <CardTitle>All Available Pages</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2">
            {ALL_LINKS.map((link) => (
              <li key={link.path}>
                <a href={link.path} className="text-blue-600 hover:underline">
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
