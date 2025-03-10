import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { AuthProvider } from "@/hooks/use-auth";
import { ProtectedRoute } from "@/components/protected-route";
import { MainNav } from "@/components/main-nav";
import Home from "@/pages/home";
import PluginDemo from "@/pages/plugin-demo";
import AuthPage from "@/pages/auth";
<<<<<<< HEAD
=======
import ProfilePage from "@/pages/profile";
import AdminDashboard from "@/pages/admin";
import PasswordResetPage from "@/pages/password-reset";
>>>>>>> e6c0e49 (admin fix)
import NotFound from "@/pages/not-found";

function Router() {
  return (
    <div className="min-h-screen flex flex-col">
      <MainNav />
      <main className="flex-1">
        <Switch>
          <ProtectedRoute path="/" component={Home} />
          <ProtectedRoute path="/plugin-demo" component={PluginDemo} />
<<<<<<< HEAD
          <Route path="/auth" component={AuthPage} />
=======
          <ProtectedRoute path="/profile" component={ProfilePage} />
          <ProtectedRoute path="/admin" component={AdminDashboard} />
          <Route path="/auth" component={AuthPage} />
          <Route path="/password-reset" component={PasswordResetPage} />
>>>>>>> e6c0e49 (admin fix)
          <Route component={NotFound} />
        </Switch>
      </main>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Router />
        <Toaster />
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;