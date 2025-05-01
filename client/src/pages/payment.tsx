import { useState } from "react";
import { useLocation } from "wouter";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { useCredits } from "@/hooks/use-credits";
import { CreditCard, Smartphone } from "lucide-react";

interface PaymentMethod {
  id: string;
  name: string;
  icon: JSX.Element;
  fields: { name: string; label: string; type: string }[];
}

const paymentMethods: PaymentMethod[] = [
  {
    id: "bkash",
    name: "bKash",
    icon: <Smartphone className="h-6 w-6 text-pink-600" />,
    fields: [
      { name: "phone", label: "bKash Number", type: "tel" },
      { name: "pin", label: "PIN", type: "password" },
    ],
  },
  {
    id: "nagad",
    name: "Nagad",
    icon: <Smartphone className="h-6 w-6 text-orange-600" />,
    fields: [
      { name: "phone", label: "Nagad Number", type: "tel" },
      { name: "pin", label: "PIN", type: "password" },
    ],
  },
  {
    id: "card",
    name: "Credit Card",
    icon: <CreditCard className="h-6 w-6 text-blue-600" />,
    fields: [
      { name: "cardNumber", label: "Card Number", type: "text" },
      { name: "expiry", label: "Expiry Date (MM/YY)", type: "text" },
      { name: "cvv", label: "CVV", type: "text" },
    ],
  },
];

export default function PaymentPage() {
  const [selectedMethod, setSelectedMethod] = useState<string>("bkash");
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [isProcessing, setIsProcessing] = useState(false);
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const { refetchCredits } = useCredits();

  // Get package details from URL params
  const params = new URLSearchParams(window.location.search);
  const packageId = params.get("packageId");
  const amount = params.get("amount");
  const credits = params.get("credits");

  const handleInputChange = (name: string, value: string) => {
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsProcessing(true);

    try {
      // Show processing message
      toast({
        title: "Processing Payment",
        description: "Please wait while we process your payment...",
      });

      const response = await fetch("/api/purchase-credits", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          packageId: parseInt(packageId || "0"),
          paymentMethodId: selectedMethod,
          paymentDetails: formData,
        }),
      });

      if (!response.ok) {
        throw new Error("Payment failed");
      }

      // Refetch credits to update the balance
      await refetchCredits();

      toast({
        title: "Payment Successful",
        description: `Successfully purchased ${credits} credits!`,
      });

      // Redirect back to credits page
      setLocation("/credits");
    } catch (error) {
      toast({
        title: "Payment Failed",
        description: "There was an error processing your payment. Please try again.",
        variant: "destructive",
      });
    }
  };

  const selectedPaymentMethod = paymentMethods.find((m) => m.id === selectedMethod);

  return (
    <div className="container mx-auto py-8 px-4">
      <div className="max-w-2xl mx-auto">
        <Card>
          <CardHeader>
            <CardTitle>Complete Your Purchase</CardTitle>
            <CardDescription>
              You are purchasing {credits} credits for ${amount}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-4">
                <Label>Select Payment Method</Label>
                <RadioGroup
                  value={selectedMethod}
                  onValueChange={setSelectedMethod}
                  className="grid grid-cols-3 gap-4"
                >
                  {paymentMethods.map((method) => (
                    <Label
                      key={method.id}
                      className={`flex flex-col items-center justify-center p-4 rounded-lg border-2 cursor-pointer ${
                        selectedMethod === method.id
                          ? "border-primary bg-primary/5"
                          : "border-muted"
                      }`}
                    >
                      <RadioGroupItem
                        value={method.id}
                        id={method.id}
                        className="sr-only"
                      />
                      {method.icon}
                      <span className="mt-2 text-sm font-medium">
                        {method.name}
                      </span>
                    </Label>
                  ))}
                </RadioGroup>
              </div>

              {selectedPaymentMethod && (
                <div className="space-y-4">
                  {selectedPaymentMethod.fields.map((field) => (
                    <div key={field.name} className="space-y-2">
                      <Label htmlFor={field.name}>{field.label}</Label>
                      <Input
                        id={field.name}
                        type={field.type}
                        value={formData[field.name] || ""}
                        onChange={(e) =>
                          handleInputChange(field.name, e.target.value)
                        }
                        required
                      />
                    </div>
                  ))}
                </div>
              )}

              <div className="pt-4 space-y-4">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Amount:</span>
                  <span className="font-medium">৳{amount}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Credits:</span>
                  <span className="font-medium">{credits} credits</span>
                </div>
                <Button type="submit" className="w-full" disabled={isProcessing}>
                  {isProcessing ? "Processing..." : `Pay ৳${amount}`}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
