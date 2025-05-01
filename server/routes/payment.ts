import { Express, Request, Response } from "express";
import { storage } from "../storage";

export function registerPaymentRoutes(app: Express) {
  app.post("/api/purchase-credits", async (req: Request, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const { packageId, paymentMethodId, paymentDetails } = req.body;

    try {
      // Get package details
      const packages = await storage.getCreditPackages();
      const pkg = packages.find(p => p.id === packageId);

      if (!pkg) {
        return res.status(404).json({ error: "Credit package not found" });
      }

      // In a real app, we would process the payment here
      // For now, we'll simulate a successful payment
      
      // Create a payment record
      const payment = await storage.createPayment({
        userId: req.user.id,
        packageId: parseInt(packageId),
        amount: pkg.price,
        status: "completed",
        paymentMethodId: parseInt(paymentMethodId),
        metadata: paymentDetails,
        transactionId: null,
        senderNumber: null,
        verifiedAt: null,
        verifiedBy: null
      });

      // Add credits to user's account
      await storage.updateUserCredits(req.user.id, pkg.credits);

      res.json({ 
        success: true,
        credits: pkg.credits,
        payment: payment
      });
    } catch (error) {
      console.error("Error processing payment:", error);
      res.status(500).json({ error: "Failed to process payment" });
    }
  });
}
