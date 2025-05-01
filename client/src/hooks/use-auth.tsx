import { createContext, ReactNode, useContext } from "react";
import {
  useQuery,
  useMutation,
  UseMutationResult,
} from "@tanstack/react-query";
import { insertUserSchema, User as SelectUser, InsertUser } from "@shared/schema";
import { getQueryFn, apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

// Define guest user type
type GuestUser = {
  guest: true;
  createdAt: string;
};

// Define our user type to be either an authenticated user or a guest
type UserState = SelectUser | GuestUser | null;

// Update the context type to include guest functionality
type AuthContextType = {
  user: UserState;
  isGuest: boolean;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: Error | null;
  loginMutation: UseMutationResult<SelectUser, Error, LoginData>;
  logoutMutation: UseMutationResult<void, Error, void>;
  registerMutation: UseMutationResult<SelectUser, Error, InsertUser>;
  guestLoginMutation: UseMutationResult<GuestUser, Error, void>;
};

type LoginData = Pick<InsertUser, "username" | "password">;

export const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { toast } = useToast();
  const {
    data: user,
    error,
    isLoading,
  } = useQuery<UserState | null>({
    queryKey: ["/api/user"],
    queryFn: getQueryFn({ on401: "returnNull" }),
    staleTime: 1000 * 60 * 5, // 5 minutes
  });

  // Check if the user is a guest or authenticated user
  const isGuest = !!user && 'guest' in user;
  const isAuthenticated = !!user && !isGuest;

  // Regular authentication mutations
  const loginMutation = useMutation({
    mutationFn: async (credentials: LoginData) => {
      const res = await apiRequest("POST", "/api/login", credentials);
      return await res.json();
    },
    onSuccess: (user: SelectUser) => {
      queryClient.setQueryData(["/api/user"], user);
      toast({
        title: "Login successful",
        description: `Welcome back, ${user.username}!`,
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Login failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const registerMutation = useMutation({
    mutationFn: async (credentials: InsertUser) => {
      const res = await apiRequest("POST", "/api/register", credentials);
      return await res.json();
    },
    onSuccess: (response) => {
      // Don't set the user data - they need to verify first
      toast({
        title: "Registration successful",
        description: "Please check your email to verify your account before logging in.",
      });
      // Redirect to login tab
      const authTabs = document.querySelector('[data-state="inactive"][data-value="login"]') as HTMLElement;
      if (authTabs) {
        authTabs.click();
      }
    },
    onError: (error: Error) => {
      toast({
        title: "Registration failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Guest login mutation
  const guestLoginMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/guest");
      return await res.json();
    },
    onSuccess: (guestData: GuestUser) => {
      queryClient.setQueryData(["/api/user"], guestData);
      toast({
        title: "Guest access granted",
        description: "You're now browsing as a guest. Create an account to save your data.",
      });
      
      // Explicitly redirect to home page
      window.location.href = '/';
    },
    onError: (error: Error) => {
      toast({
        title: "Guest access failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Handles both regular user and guest logout
  const logoutMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/logout");
    },
    onSuccess: () => {
      queryClient.setQueryData(["/api/user"], null);
      toast({
        title: "Logged out",
        description: "You have been logged out successfully.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Logout failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  return (
    <AuthContext.Provider
      value={{
        user: user ?? null,
        isGuest,
        isAuthenticated,
        isLoading,
        error,
        loginMutation,
        logoutMutation,
        registerMutation,
        guestLoginMutation,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
