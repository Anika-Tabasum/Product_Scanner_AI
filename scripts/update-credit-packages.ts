import { db } from "../server/db";
import { creditPackages } from "@shared/payment-schema";

async function updateCreditPackages() {
  try {
    // First, deactivate all existing packages
    await db
      .update(creditPackages)
      .set({ active: false });

    // Insert new packages
    await db.insert(creditPackages).values([
      {
        name: "Basic",
        credits: 500,
        price: 50,
        description: "500 credits for ৳50",
        active: true,
      },
      {
        name: "Standard",
        credits: 1200,
        price: 100,
        description: "1200 credits for ৳100",
        active: true,
      },
      {
        name: "Premium",
        credits: 3000,
        price: 200,
        description: "3000 credits for ৳200",
        active: true,
      },
    ]);

    console.log("Credit packages updated successfully");
    process.exit(0);
  } catch (error) {
    console.error("Error updating credit packages:", error);
    process.exit(1);
  }
}

updateCreditPackages();
