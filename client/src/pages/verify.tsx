import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useLocation } from "wouter";

const verifySchema = z.object({
  token: z.string().min(6, "Verification code required"),
});

export default function VerifyPage() {
  const { toast } = useToast();
  const [location, setLocation] = useLocation();
  const [isVerifying, setIsVerifying] = useState(false);
  const [success, setSuccess] = useState(false);

  // Pre-fill token from URL if present
  const urlToken = (() => {
    try {
      const params = new URLSearchParams(window.location.search);
      return params.get("token") || "";
    } catch {
      return "";
    }
  })();

  const form = useForm({
    resolver: zodResolver(verifySchema),
    defaultValues: { token: urlToken },
  });

  const onSubmit = async (values: { token: string }) => {
    setIsVerifying(true);
    try {
      const resp = await fetch(`/api/verify-email?token=${encodeURIComponent(values.token)}`);
      const data = await resp.json();
      if (resp.ok && data.success) {
        toast({ title: "Email verified!", description: data.message });
        setSuccess(true);
        setTimeout(() => setLocation("/auth?verified=true"), 1500);
      } else {
        toast({ title: "Verification failed", description: data.message || "Invalid code", variant: "destructive" });
      }
    } catch (err) {
      toast({ title: "Error", description: "Verification failed", variant: "destructive" });
    }
    setIsVerifying(false);
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Email Verification</CardTitle>
        </CardHeader>
        <CardContent>
          {success ? (
            <p className="text-green-600">Verification successful! Redirecting to login...</p>
          ) : (
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <Input {...form.register("token")} placeholder="Enter verification code or paste link token" />
              <Button type="submit" className="w-full" disabled={isVerifying}>
                {isVerifying ? "Verifying..." : "Verify"}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
