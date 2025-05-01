
import { useState } from 'react';
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { useLocation } from 'wouter';
import { Loader2, Mail, CheckCircle, Key } from "lucide-react";

// Schema for the request form
const requestResetSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
});

// Schema for the reset password form
const resetPasswordSchema = z.object({
  password: z.string().min(6, "Password must be at least 6 characters"),
  confirmPassword: z.string(),
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export default function PasswordResetPage() {
  const [_, setLocation] = useLocation();
  const { toast } = useToast();
  const [stage, setStage] = useState<'request' | 'sent' | 'reset'>('request');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [token, setToken] = useState('');
  
  // Get the token from URL if present
  const url = new URL(window.location.href);
  const urlToken = url.searchParams.get('token');
  
  if (urlToken && stage === 'request') {
    setToken(urlToken);
    setStage('reset');
  }

  // Form for requesting password reset
  const requestForm = useForm({
    resolver: zodResolver(requestResetSchema),
    defaultValues: {
      email: '',
    },
  });

  // Form for resetting password
  const resetForm = useForm({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: {
      password: '',
      confirmPassword: '',
    },
  });

  // Handle request password reset
  const onRequestReset = requestForm.handleSubmit(async (data) => {
    setIsSubmitting(true);
    try {
      await apiRequest('POST', '/api/reset-password/request', data);
      setStage('sent');
      toast({
        title: "Reset link sent",
        description: "Check your email for password reset instructions",
      });
    } catch (error) {
      console.error(error);
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to send reset link",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  });

  // Handle password reset
  const onResetPassword = resetForm.handleSubmit(async (data) => {
    setIsSubmitting(true);
    try {
      await apiRequest('POST', '/api/reset-password/reset', {
        token,
        password: data.password,
      });
      toast({
        title: "Password reset successful",
        description: "Your password has been updated. You can now log in.",
      });
      // Redirect to login page
      setTimeout(() => {
        setLocation('/auth?tab=login');
      }, 2000);
    } catch (error) {
      console.error(error);
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to reset password",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  });

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {stage === 'request' && (
          <Card>
            <CardHeader>
              <CardTitle>Reset Password</CardTitle>
              <CardDescription>Enter your email to receive a password reset link</CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...requestForm}>
                <form onSubmit={onRequestReset} className="space-y-4">
                  <FormField
                    control={requestForm.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Email</FormLabel>
                        <FormControl>
                          <Input type="email" placeholder="Enter your email" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={isSubmitting}>
                    {isSubmitting ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Sending...
                      </>
                    ) : (
                      <>
                        <Mail className="mr-2 h-4 w-4" />
                        Send Reset Link
                      </>
                    )}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full mt-2"
                    onClick={() => setLocation('/auth')}
                  >
                    Back to Login
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>
        )}

        {stage === 'sent' && (
          <Card>
            <CardHeader>
              <CardTitle>Check Your Email</CardTitle>
              <CardDescription>We've sent a password reset link to your email</CardDescription>
            </CardHeader>
            <CardContent className="text-center">
              <CheckCircle className="h-16 w-16 text-green-500 mx-auto my-4" />
              <p className="mb-4">Please check your inbox and click on the reset link.</p>
              <Button
                type="button"
                variant="outline"
                className="w-full mt-4"
                onClick={() => setStage('request')}
              >
                Back to Reset Request
              </Button>
            </CardContent>
          </Card>
        )}

        {stage === 'reset' && (
          <Card>
            <CardHeader>
              <CardTitle>Create New Password</CardTitle>
              <CardDescription>Enter your new password</CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...resetForm}>
                <form onSubmit={onResetPassword} className="space-y-4">
                  <FormField
                    control={resetForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>New Password</FormLabel>
                        <FormControl>
                          <Input type="password" placeholder="Enter new password" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={resetForm.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Confirm Password</FormLabel>
                        <FormControl>
                          <Input
                            type="password"
                            placeholder="Confirm new password"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={isSubmitting}>
                    {isSubmitting ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Updating...
                      </>
                    ) : (
                      <>
                        <Key className="mr-2 h-4 w-4" />
                        Reset Password
                      </>
                    )}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
