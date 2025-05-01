import { Express, Request, Response } from "express";
import { storage } from "./storage";
import { creditPackages, payments, userCredits, creditUsage, paymentMethods } from "../shared/payment-schema";
import { eq } from "drizzle-orm";

export async function deductCredits(userId: number, amount: number, type: string, metadata: Record<string, any> = {}) {
  // Start a transaction
  return await storage.transaction(async (tx) => {
    // Get current credit balance
    const [userCredit] = await tx
      .select()
      .from(userCredits)
      .where(eq(userCredits.userId, userId));

    if (!userCredit || userCredit.balance < amount) {
      throw new Error("Insufficient credits");
    }

    // Update credit balance
    await tx
      .update(userCredits)
      .set({ balance: userCredit.balance - amount })
      .where(eq(userCredits.userId, userId));

    // Record credit usage
    await tx.insert(creditUsage).values({
      userId,
      amount,
      type,
      metadata,
    });
  });
}

export function setupPayment(app: Express) {
  // Get available credit packages
  app.get("/api/credit-packages", async (req: Request, res: Response) => {
    try {
      const packages = await storage.getCreditPackages();
      res.json(packages);
    } catch (error) {
      console.error("Error fetching credit packages:", error);
      res.status(500).json({ error: "Failed to fetch credit packages" });
    }
  });

  // Get payment methods
  app.get("/api/payment-methods", async (req: Request, res: Response) => {
    try {
      const methods = await storage.getPaymentMethods();
      res.json(methods);
    } catch (error) {
      console.error("Error fetching payment methods:", error);
      res.status(500).json({ error: "Failed to fetch payment methods" });
    }
  });

  // Get user's credit balance
  app.get("/api/credits", async (req: Request, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    try {
      const credits = await storage.getUserCredits(req.user.id);
      res.json({ balance: credits?.balance || 0 });
    } catch (error) {
      console.error("Error fetching credit balance:", error);
      res.status(500).json({ error: "Failed to fetch credit balance" });
    }
  });

  // Initiate payment for credits
  app.post("/api/purchase-credits", async (req: Request, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const { packageId, paymentMethodId } = req.body;

    try {
      // Get package details
      const packages = await storage.getCreditPackages();
      const pkg = packages.find(p => p.id === packageId);

      if (!pkg) {
        return res.status(404).json({ error: "Credit package not found" });
      }

      // Get payment method
      const methods = await storage.getPaymentMethods();
      const paymentMethod = methods.find(m => m.id === paymentMethodId);

      if (!paymentMethod) {
        return res.status(404).json({ error: "Payment method not found" });
      }

      // Create payment record
      const payment = await storage.createPayment({
        userId: req.user.id,
        packageId,
        paymentMethodId,
        amount: pkg.price,
        status: "pending",
        transactionId: null,
        senderNumber: null,
        verifiedAt: null,
        verifiedBy: null,
        metadata: {
          credits: pkg.credits,
        },
      });

      res.json({
        success: true,
        orderId: payment.id,
        package: pkg,
        paymentMethod,
        instructions: paymentMethod.instructions,
        accountDetails: paymentMethod.accountDetails,
      });
    } catch (error) {
      console.error("Error creating payment:", error);
      res.status(500).json({ error: "Failed to create payment" });
    }
  });

  // Submit payment verification
  app.post("/api/verify-payment/:paymentId", async (req: Request, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const { paymentId } = req.params;
    const { transactionId, senderNumber } = req.body;

    try {
      // Get payment details
      const payment = await storage.getPayment(parseInt(paymentId));

      if (!payment) {
        return res.status(404).json({ error: "Payment not found" });
      }

      if (payment.userId !== req.user.id) {
        return res.status(403).json({ error: "Unauthorized" });
      }

      // Update payment with verification details
      await storage.updatePaymentStatus(paymentId, "pending_verification");

      res.json({
        success: true,
        message: "Payment verification submitted. Please wait for admin verification.",
      });
    } catch (error) {
      console.error("Error submitting payment verification:", error);
      res.status(500).json({ error: "Failed to submit payment verification" });
    }
  });

  // Admin: Verify payment
  app.post("/api/admin/verify-payment/:paymentId", async (req: Request, res: Response) => {
    if (!req.user || !req.user.role || req.user.role !== "admin") {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const { paymentId } = req.params;
    const { status } = req.body;

    if (!["verified", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    try {
      await storage.transaction(async (tx) => {
        // Get payment details
        const [payment] = await tx
          .select()
          .from(payments)
          .where(eq(payments.id, parseInt(paymentId)));

        if (!payment) {
          throw new Error("Payment not found");
        }

        // Update payment status
        await tx
          .update(payments)
          .set({
            status,
            verifiedAt: new Date(),
            verifiedBy: req.user?.id || null,
          })
          .where(eq(payments.id, parseInt(paymentId)));

        // If verified, add credits to user's balance
        if (status === "verified") {
          const [pkg] = await tx
            .select()
            .from(creditPackages)
            .where(eq(creditPackages.id, payment.packageId));

          if (!pkg) {
            throw new Error("Credit package not found");
          }

          await storage.updateUserCredits(payment.userId, pkg.credits);
        }
      });

      res.json({
        success: true,
        message: `Payment ${status}`,
      });
    } catch (error) {
      console.error("Error verifying payment:", error);
      res.status(500).json({ error: "Failed to verify payment" });
    }
  });
}
