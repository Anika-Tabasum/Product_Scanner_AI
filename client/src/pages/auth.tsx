import { useEffect } from 'react';
import { useLocation } from 'wouter';
import { useAuth } from '@/hooks/use-auth';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { insertUserSchema } from '@shared/schema';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { SiGithub } from 'react-icons/si';
import { useToast } from '@/hooks/use-toast';

export default function AuthPage() {
  const [location, setLocation] = useLocation();
  const { user, isGuest, loginMutation, registerMutation, guestLoginMutation } = useAuth();
  const { toast } = useToast();
  
  // Check for URL params
  const searchParams = new URLSearchParams(location.split('?')[1]);
  const isVerified = searchParams.get('verified') === 'true';
  
  // Check URL parameters
  useEffect(() => {
    // Show toast for successful verification
    if (isVerified) {
      toast({
        title: "Email verified successfully!",
        description: "Your account has been verified. You can now log in.",
        variant: "default",
      });
    }
    
    // Show toast if redirected for unverified access attempt
    const needsVerification = searchParams.get('needsVerification') === 'true';
    if (needsVerification) {
      toast({
        title: "Email verification required",
        description: "Please verify your email before accessing the application. Check your inbox for the verification link.",
        variant: "destructive",
      });
    }
  }, [isVerified, toast, searchParams]);

  // Redirect if already logged in (including guest users)
  useEffect(() => {
    if (user) {
      setLocation('/');
    }
  }, [user, setLocation]);
  
  // Handle guest login
  const handleGuestLogin = () => {
    guestLoginMutation.mutate();
  };

  const loginForm = useForm({
    defaultValues: {
      username: '',
      password: '',
    },
  });

  const registerForm = useForm({
    resolver: zodResolver(insertUserSchema),
    defaultValues: {
      username: '',
      email: '',
      password: '',
    },
  });

  const onLogin = loginForm.handleSubmit((data) => {
    loginMutation.mutate(data);
  });

  const onRegister = registerForm.handleSubmit((data) => {
    registerMutation.mutate(data, {
      onSuccess: () => {
        toast({
          title: "Registration successful",
          description: "Please log in with your new account",
        });
        loginForm.reset();
        // Use a more reliable way to switch tabs
        const loginTab = document.querySelector('[data-state="inactive"][value="login"]') as HTMLElement;
        if (loginTab) {
          loginTab.click();
        }
      },
    });
  });

  return (
    <div className="min-h-screen flex">
      {/* Left side - Auth forms */}
      <div className="flex-1 flex items-center justify-center p-8">
        <Card className="w-full max-w-md mx-auto">
          <CardHeader>
            <CardTitle>Welcome</CardTitle>
            <CardDescription>Sign in to access your account</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="login">
              <TabsList className="grid w-full grid-cols-2 mb-8">
                <TabsTrigger value="login">Login</TabsTrigger>
                <TabsTrigger value="register">Register</TabsTrigger>
              </TabsList>

              <TabsContent value="login">
                <Form {...loginForm}>
                  <form onSubmit={onLogin} className="space-y-4">
                    <FormField
                      control={loginForm.control}
                      name="username"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Username</FormLabel>
                          <FormControl>
                            <Input {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={loginForm.control}
                      name="password"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Password</FormLabel>
                          <FormControl>
                            <Input type="password" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <div className="text-right">
                      <a 
                        href="/password-reset" 
                        className="text-sm text-blue-600 hover:underline"
                      >
                        Forgot password?
                      </a>
                    </div>
                    <Button type="submit" className="w-full" disabled={loginMutation.isPending}>
                      {loginMutation.isPending ? 'Signing in...' : 'Sign in'}
                    </Button>
                  </form>
                </Form>
              </TabsContent>

              <TabsContent value="register">
                <Form {...registerForm}>
                  <form onSubmit={onRegister} className="space-y-4">
                    <FormField
                      control={registerForm.control}
                      name="username"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Username</FormLabel>
                          <FormControl>
                            <Input {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={registerForm.control}
                      name="email"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Email</FormLabel>
                          <FormControl>
                            <Input type="email" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={registerForm.control}
                      name="password"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Password</FormLabel>
                          <FormControl>
                            <Input type="password" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <Button type="submit" className="w-full" disabled={registerMutation.isPending}>
                      {registerMutation.isPending ? 'Creating account...' : 'Create account'}
                    </Button>
                  </form>
                </Form>
              </TabsContent>
            </Tabs>

            <div className="mt-6">
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <Separator />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-background px-2 text-muted-foreground">
                    Or continue with
                  </span>
                </div>
              </div>

              <div className="mt-4 space-y-2">
                <Button variant="outline" className="w-full" onClick={() => window.location.href = '/api/auth/github'}>
                  <SiGithub className="mr-2 h-4 w-4" />
                  GitHub
                </Button>
                
                <Button 
                  variant="ghost" 
                  className="w-full"
                  onClick={handleGuestLogin}
                  disabled={guestLoginMutation.isPending}
                >
                  {guestLoginMutation.isPending ? 'Loading...' : 'Continue as Guest'}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Right side - Hero section */}
      <div className="hidden lg:flex flex-1 bg-muted items-center justify-center p-8">
        <div className="max-w-lg text-center">
          <h1 className="text-4xl font-bold mb-4">
            AI-Powered Product Identification
          </h1>
          <p className="text-lg text-muted-foreground">
            Automatically identify and catalog products using state-of-the-art AI technology.
            Upload images or use your camera to get instant product details.
          </p>
        </div>
      </div>
    </div>
  );
}