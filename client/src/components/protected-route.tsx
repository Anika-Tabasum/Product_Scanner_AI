import { useAuth } from "@/hooks/use-auth";
import { Loader2 } from "lucide-react";
import { Route, useLocation } from "wouter";

export function ProtectedRoute({
  path,
  component: Component,
  allowGuest = false,
}: {
  path: string;
  component: () => React.JSX.Element;
  allowGuest?: boolean;
}) {
  const { user, isLoading, isGuest } = useAuth();
  const [_, setLocation] = useLocation();

  if (isLoading) {
    return (
      <Route path={path}>
        <div className="flex items-center justify-center min-h-screen">
          <Loader2 className="h-8 w-8 animate-spin text-border" />
        </div>
      </Route>
    );
  }

  // Allow guest access to certain routes if specified
  if (allowGuest && (user || isGuest)) {
    return <Route path={path} component={Component} />;
  }
  
  // For non-guest routes, require authenticated user
  if (!user || isGuest) {
    // Use setTimeout to avoid state updates during render
    setTimeout(() => setLocation('/auth'), 0);
    return null;
  }

  return <Route path={path} component={Component} />;
}
