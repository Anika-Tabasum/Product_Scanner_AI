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
import ProfilePage from "@/pages/profile";
import AdminDashboard from "@/pages/admin";
import PasswordResetPage from "@/pages/password-reset";
import GGSVisualization from "@/pages/ggs-visualization";
import AllLinkPage from "@/pages/all-link";
import MarksPage from "@/pages/marks";
import VerifyPage from "@/pages/verify";
import NotFound from "@/pages/not-found";
import CreditsPage from "@/pages/credits";
import PaymentPage from "@/pages/payment";

function Router() {
  return (
    <div className="min-h-screen flex flex-col">
      <MainNav />
      <main className="flex-1">
        <Switch>
          {/* Routes that allow guest access */}
          <ProtectedRoute path="/" component={Home} allowGuest={true} />
          <ProtectedRoute path="/plugin-demo" component={PluginDemo} allowGuest={true} />
          <ProtectedRoute path="/profile" component={ProfilePage} allowGuest={true} />
          <ProtectedRoute path="/ggs-visualization" component={GGSVisualization} allowGuest={true} />
          
          {/* Routes that require full authentication */}
          <ProtectedRoute path="/admin" component={AdminDashboard} />
          <ProtectedRoute path="/all-link" component={AllLinkPage} />
          <ProtectedRoute path="/credits" component={CreditsPage} />
          <ProtectedRoute path="/payment" component={PaymentPage} />
          
          {/* Public routes */}
          <Route path="/marks" component={MarksPage} />
          <Route path="/verify" component={VerifyPage} />
          <Route path="/auth" component={AuthPage} />
          <Route path="/password-reset" component={PasswordResetPage} />
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