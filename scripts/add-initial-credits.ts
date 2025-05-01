import { db } from "../server/db";
import { users } from "../shared/schema";
import { userCredits } from "../shared/payment-schema";
import { eq } from "drizzle-orm";

async function addInitialCredits() {
  try {
    // Find shahal's user ID
    const [shahalUser] = await db
      .select()
      .from(users)
      .where(eq(users.username, "shahal"));

    if (!shahalUser) {
      console.error("User 'shahal' not found");
      process.exit(1);
    }

    // Check if user already has credits
    const [existingCredits] = await db
      .select()
      .from(userCredits)
      .where(eq(userCredits.userId, shahalUser.id));

    if (existingCredits) {
      // Update existing credits
      await db
        .update(userCredits)
        .set({ balance: existingCredits.balance + 50 })
        .where(eq(userCredits.userId, shahalUser.id));
      
      console.log(`Updated credits for user 'shahal'. New balance: ${existingCredits.balance + 50}`);
    } else {
      // Add new credits entry
      await db.insert(userCredits).values({
        userId: shahalUser.id,
        balance: 50,
      });
      
      console.log(`Added 50 initial credits for user 'shahal'`);
    }

    process.exit(0);
  } catch (error) {
    console.error("Error adding credits:", error);
    process.exit(1);
  }
}

addInitialCredits();
