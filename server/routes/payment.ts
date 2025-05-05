import { Express, Request, Response } from "express";
import { storage } from "../storage";
import { db } from "../db";
import { eq } from "drizzle-orm";
import { paymentMethods } from "@shared/payment-schema";

export function registerPaymentRoutes(app: Express) {
  app.post("/api/purchase-credits", async (req: Request, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const { packageId, paymentMethodId, paymentDetails } = req.body;

    try {
      // Get package details
      const packages = await storage.getCreditPackages();
      const pkg = packages.find(p => p.id === parseInt(packageId));

      if (!pkg) {
        return res.status(404).json({ error: "Credit package not found" });
      }

      // Get payment method
      const [method] = await db
        .select()
        .from(paymentMethods)
        .where(eq(paymentMethods.name, paymentMethodId));

      if (!method) {
        return res.status(404).json({ error: "Payment method not found" });
      }

      if (!method.active) {
        return res.status(400).json({ error: "Payment method is not available" });
      }

      // Create a payment record
      const payment = await storage.createPayment({
        userId: req.user.id,
        packageId: pkg.id,
        amount: pkg.price,
        status: "completed",
        paymentMethodId: method.id,
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
