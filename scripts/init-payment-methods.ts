import { db } from "../server/db";
import { paymentMethods } from "@shared/payment-schema";

async function initializePaymentMethods() {
  try {
    // First, deactivate all existing payment methods
    await db
      .update(paymentMethods)
      .set({ active: false });

    // Insert new payment methods
    await db.insert(paymentMethods).values([
      {
        name: "bkash",
        instructions: "Send money to our bKash number and provide the Transaction ID",
        accountDetails: {
          number: "01XXXXXXXXX",
          type: "Merchant",
        },
        active: true,
      },
      {
        name: "nagad",
        instructions: "Send money to our Nagad number and provide the Transaction ID",
        accountDetails: {
          number: "01XXXXXXXXX",
          type: "Merchant",
        },
        active: true,
      },
      {
        name: "card",
        instructions: "Pay securely with your credit or debit card",
        accountDetails: {
          supportedCards: ["Visa", "Mastercard", "American Express"],
        },
        active: true,
      },
    ]);

    console.log("Payment methods initialized successfully");
    process.exit(0);
  } catch (error) {
    console.error("Error initializing payment methods:", error);
    process.exit(1);
  }
}

initializePaymentMethods();
