import { useAuth } from "@/hooks/use-auth";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Loader2, UserCircle, Camera, AlertTriangle } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

// Guest view component
function GuestView() {
  return (
    <div className="max-w-md mx-auto text-center space-y-6 py-8">
      <UserCircle className="h-20 w-20 mx-auto text-muted-foreground" />
      <h2 className="text-2xl font-bold">Guest Access</h2>
      <p className="text-muted-foreground">
        You're browsing as a guest. Create an account to save your identified products and access more features.
      </p>
      <div className="flex gap-4 justify-center">
        <Button variant="outline" onClick={() => window.location.href = '/auth?tab=login'}>
          Sign In
        </Button>
        <Button onClick={() => window.location.href = '/auth?tab=register'}>
          Create Account
        </Button>
      </div>
    </div>
  );
}

// User profile component
function UserProfile({ user }: { user: any }) {
  const { toast } = useToast();
  const { data: products } = useQuery<any[]>({
    queryKey: ['/api/products']
  });

  const changePasswordForm = useForm({
    defaultValues: {
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    },
  });

  const deleteAccountForm = useForm({
    defaultValues: {
      password: '',
    },
  });

  const onSubmitPasswordChange = changePasswordForm.handleSubmit(async (data) => {
    if (data.newPassword !== data.confirmPassword) {
      toast({
        title: "Passwords don't match",
        description: "New password and confirmation must match",
        variant: "destructive",
      });
      return;
    }

    try {
      await apiRequest('POST', '/api/profile/change-password', {
        currentPassword: data.currentPassword,
        newPassword: data.newPassword,
      });

      toast({
        title: "Password updated",
        description: "Your password has been changed successfully",
      });

      changePasswordForm.reset();
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to change password",
        variant: "destructive",
      });
    }
  });

  const handleProfilePictureUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('profilePicture', file);

    try {
      const response = await fetch('/api/profile/picture', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) throw new Error('Failed to upload profile picture');

      const data = await response.json();
      toast({
        title: "Success",
        description: "Profile picture updated successfully",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to upload profile picture",
        variant: "destructive",
      });
    }
  };

  const handleDeleteAccount = deleteAccountForm.handleSubmit(async (data) => {
    if (!confirm("Are you sure you want to delete your account? This action cannot be undone.")) {
      return;
    }

    try {
      await apiRequest('DELETE', '/api/profile', { password: data.password });
      window.location.href = '/auth'; // Redirect to auth page after deletion
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to delete account",
        variant: "destructive",
      });
    }
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col items-center gap-4">
        <div className="relative">
          <Avatar className="h-24 w-24">
            <AvatarImage src={user.profilePicture || ''} />
            <AvatarFallback className="text-2xl">{user.username.charAt(0).toUpperCase()}</AvatarFallback>
          </Avatar>
          <div className="absolute -bottom-3 left-1/2 -translate-x-1/2">
            <Button 
              variant="secondary" 
              size="sm"
              className="rounded-full"
              onClick={() => document.getElementById('profile-picture-input')?.click()}
            >
              <Camera className="h-4 w-4 mr-1" />
              Change
            </Button>
            <Input
              id="profile-picture-input"
              type="file"
              accept="image/*"
              className="hidden"
              onChange={handleProfilePictureUpload}
            />
          </div>
        </div>
        <div className="text-center">
          <h2 className="text-2xl font-bold">{user.username}</h2>
          <p className="text-muted-foreground">{user.email}</p>
          <div className="mt-1 inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold">
            {user.role}
          </div>
        </div>
      </div>

      <Tabs defaultValue="account" className="mt-8">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="account">Account Info</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="account" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Account Information</CardTitle>
              <CardDescription>View your account details</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground">Username</h3>
                  <p>{user.username}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground">Email</h3>
                  <p>{user.email}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground">Account Created</h3>
                  <p>{new Date(user.createdAt).toLocaleDateString()}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground">Products Identified</h3>
                  <p>{products?.length || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security">
          <Card>
            <CardHeader>
              <CardTitle>Change Password</CardTitle>
              <CardDescription>Update your password</CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...changePasswordForm}>
                <form onSubmit={onSubmitPasswordChange} className="space-y-4">
                  <FormField
                    control={changePasswordForm.control}
                    name="currentPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Current Password</FormLabel>
                        <FormControl>
                          <Input type="password" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={changePasswordForm.control}
                    name="newPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>New Password</FormLabel>
                        <FormControl>
                          <Input type="password" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={changePasswordForm.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Confirm New Password</FormLabel>
                        <FormControl>
                          <Input type="password" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <Button type="submit" className="w-full">
                    Update Password
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="danger">
          <Card className="border-destructive">
            <CardHeader>
              <CardTitle className="text-destructive">Delete Account</CardTitle>
              <CardDescription>
                This action cannot be undone. This will permanently delete your account and remove your data from our servers.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...deleteAccountForm}>
                <form onSubmit={handleDeleteAccount} className="space-y-4">
                  <FormField
                    control={deleteAccountForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Confirm your password</FormLabel>
                        <FormControl>
                          <Input type="password" {...field} placeholder="Enter your password to confirm" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <Button type="submit" variant="destructive" className="w-full">
                    <AlertTriangle className="w-4 h-4 mr-2" />
                    Delete Account
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default function ProfilePage() {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="container py-8 flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="container py-8">
        <GuestView />
      </div>
    );
  }

  return (
    <div className="container py-8">
      <UserProfile user={user} />
    </div>
  );
}