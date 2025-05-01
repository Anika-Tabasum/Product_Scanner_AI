import { Express } from "express";
import { storage } from "../storage";
import { generateResetToken, sendPasswordResetEmail } from "../lib/email";
import { hashPassword } from "../auth";

export function registerResetPasswordRoutes(app: Express) {
  // Request password reset
  app.post("/api/reset-password/request", async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email is required" });
      }

      // Check if user exists
      try {
        const user = await storage.getUserByEmail(email);

        if (!user) {
          return res.status(404).json({ message: "User with this email not found" });
        }

        // Generate a reset token
        const resetToken = generateResetToken();

        // Save the token to the user record
        await storage.setPasswordResetToken(user.id, resetToken);

        try {
          // Send the reset email
          const emailPreviewUrl = await sendPasswordResetEmail(email, resetToken, user.username);

          console.log("Password reset email sent to:", email);
          console.log("Password reset email preview (if using Ethereal):", emailPreviewUrl);

          // In production, you would not return the email preview URL
          res.status(200).json({ 
            message: "Password reset link sent to your email",
            ...(process.env.NODE_ENV === "development" ? { emailPreviewUrl } : {})
          });
        } catch (emailError) {
          console.error("Failed to send password reset email:", emailError);
          // We saved the token, so we can still proceed even if email fails
          res.status(200).json({ 
            message: "Password reset initiated, but email delivery failed. Please contact support.",
            error: emailError.message,
            resetToken: process.env.NODE_ENV === "development" ? resetToken : undefined
          });
        }
      } catch (error) {
        console.error("Error finding user:", error);
        res.status(500).json({ message: "Error processing password reset request" });
      }
    } catch (error) {
      console.error("Password reset request error:", error);
      res.status(500).json({ message: "Error processing password reset request" });
    }
  });

  // Reset password with token
  app.post("/api/reset-password/reset", async (req, res) => {
    try {
      const { token, password } = req.body;

      if (!token || !password) {
        return res.status(400).json({ message: "Token and password are required" });
      }

      // Find user with this reset token
      const user = await storage.getUserByResetToken(token);

      if (!user) {
        return res.status(404).json({ message: "Invalid or expired reset token" });
      }

      // Hash the new password
      const hashedPassword = await hashPassword(password);

      // Update user's password and clear reset token
      await storage.resetPassword(user.id, hashedPassword);

      res.status(200).json({ message: "Password reset successful" });
    } catch (error) {
      console.error("Password reset error:", error);
      res.status(500).json({ message: "Error resetting password" });
    }
  });
}