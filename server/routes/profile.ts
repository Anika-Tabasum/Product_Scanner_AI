import { Express } from "express";
import { storage } from "../storage";
import { comparePasswords, hashPassword } from "../auth";
import multer from "multer";
import { randomBytes } from "crypto";
import path from "path";
import fs from "fs";

// Configure multer for file uploads
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage2 = multer.diskStorage({
  destination: function (req: Express.Request, file: Express.Multer.File, cb: Function) {
    cb(null, uploadDir);
  },
  filename: function (req: Express.Request, file: Express.Multer.File, cb: Function) {
    const uniqueSuffix = `${Date.now()}-${randomBytes(8).toString("hex")}`;
    cb(null, `${uniqueSuffix}${path.extname(file.originalname)}`);
  },
});

const upload = multer({
  storage: storage2,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req: Express.Request, file: Express.Multer.File, cb: Function) => {
    // Accept only images
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed"));
    }
  },
});

export function registerProfileRoutes(app: Express) {
  // Get user profile
  app.get("/api/profile", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    const user = await storage.getUser(req.user!.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Return user data without password
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  });

  // Update user profile
  app.put("/api/profile", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    try {
      const { username, email } = req.body;
      const userId = req.user!.id;

      // Check if username is already taken by another user
      if (username) {
        const existingUser = await storage.getUserByUsername(username);
        if (existingUser && existingUser.id !== userId) {
          return res.status(400).json({ message: "Username already in use" });
        }
      }

      // Check if email is already taken by another user
      if (email) {
        const existingUser = await storage.getUserByEmail(email);
        if (existingUser && existingUser.id !== userId) {
          return res.status(400).json({ message: "Email already in use" });
        }
      }

      // Update profile
      const updatedUser = await storage.updateUserProfile(userId, {
        username: username || req.user!.username,
        email: email || req.user!.email,
      });

      // Return updated user without password
      const { password, ...userWithoutPassword } = updatedUser;
      res.json(userWithoutPassword);
    } catch (error) {
      console.error("Error updating profile:", error);
      res.status(500).json({ message: "Failed to update profile" });
    }
  });

  // Upload profile picture
  app.post(
    "/api/profile/picture",
    upload.single("profilePicture"),
    async (req, res) => {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Not authenticated" });
      }

      try {
        if (!req.file) {
          return res.status(400).json({ message: "No file uploaded" });
        }

        // Get the file path relative to the server
        const relativePath = path.relative(process.cwd(), req.file.path);

        // Update user profile with picture path
        const updatedUser = await storage.updateUserProfile(req.user!.id, {
          profilePicture: `/uploads/${path.basename(req.file.path)}`,
        });

        // Return the path
        res.json({
          profilePicture: updatedUser.profilePicture,
        });
      } catch (error) {
        console.error("Error uploading profile picture:", error);
        res.status(500).json({ message: "Failed to upload profile picture" });
      }
    },
  );

  // Change password
  app.post("/api/profile/change-password", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    try {
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        return res
          .status(400)
          .json({ message: "Current and new password required" });
      }

      // Verify current password
      const user = await storage.getUser(req.user!.id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const isPasswordValid = await comparePasswords(
        currentPassword,
        user.password,
      );
      if (!isPasswordValid) {
        return res
          .status(400)
          .json({ message: "Current password is incorrect" });
      }

      // Hash and update new password
      const hashedPassword = await hashPassword(newPassword);
      await storage.changePassword(req.user!.id, hashedPassword);

      res.json({ message: "Password changed successfully" });
    } catch (error) {
      console.error("Error changing password:", error);
      res.status(500).json({ message: "Failed to change password" });
    }
  });

  // Get user profile data
  app.get("/api/profile", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    try {
      // Get user data
      const user = await storage.getUser(req.user!.id);

      // Get user's products count
      const productsCount = await storage.getUserProductsCount(req.user!.id);

      // Return user profile data
      res.json({
        ...user,
        productsCount
      });
    } catch (error) {
      console.error("Error fetching profile:", error);
      res.status(500).json({ message: "Failed to fetch profile data" });
    }
  });

  // Delete account
  app.delete("/api/profile", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    try {
      const { password } = req.body;

      if (!password) {
        return res.status(400).json({ message: "Password is required to delete account" });
      }

      // Verify password
      const user = await storage.getUser(req.user!.id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const isPasswordValid = await comparePasswords(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ message: "Incorrect password" });
      }

      // Delete user and their products
      await storage.deleteUser(req.user!.id);

      // Log out user
      req.logout((err) => {
        if (err) {
          console.error("Error logging out:", err);
          return res.status(500).json({ message: "Error during logout" });
        }
        res.json({ message: "Account deleted successfully" });
      });
    } catch (error) {
      console.error("Error deleting account:", error);
      res.status(500).json({ message: "Failed to delete account" });
    }
  });
}