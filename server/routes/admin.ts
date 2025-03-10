import express, { type Express } from "express";
import { storage } from "../storage";
import { z } from "zod";

// Analytics data schema
const analyticsDataSchema = z.object({
  totalUsers: z.number(),
  totalProducts: z.number(),
  usersByRole: z.record(z.number()),
  productsByCategory: z.record(z.number()),
  recentUsers: z.array(z.object({
    id: z.number(),
    username: z.string(),
    email: z.string(),
    role: z.string(),
    createdAt: z.string().nullable(),
  })),
});

type AnalyticsData = z.infer<typeof analyticsDataSchema>;

// Admin middleware - ensure only admins can access these routes
function ensureAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Authentication required" });
  }

  // Check if the user has admin role
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ message: "Admin access required" });
  }

  next();
}

// Get analytics data for admin dashboard
async function getAnalyticsData(): Promise<AnalyticsData> {
  try {
    // Get total users count
    const totalUsers = await storage.getUserCount();

    // Get total products count
    const totalProducts = await storage.getProductCount();

    // Get users by role
    const usersByRole = await storage.getUsersByRole();

    // Get products by category
    const productsByCategory = await storage.getProductsByCategory();

    // Get recent users (last 5)
    const recentUsers = await storage.getRecentUsers(5);

    return {
      totalUsers,
      totalProducts,
      usersByRole,
      productsByCategory,
      recentUsers,
    };
  } catch (error) {
    console.error("Error getting analytics data:", error);
    throw error;
  }
}

// Get all users (admin only)
async function getAllUsers() {
  try {
    const users = await storage.getAllUsers();
    return users;
  } catch (error) {
    console.error("Error getting all users:", error);
    throw error;
  }
}

// Update user role (admin only)
async function updateUserRole(userId: number, role: string) {
  try {
    const user = await storage.updateUserRole(userId, role);
    return user;
  } catch (error) {
    console.error(`Error updating user ${userId} role to ${role}:`, error);
    throw error;
  }
}

// Register admin routes
export function registerAdminRoutes(app: Express) {
  // Admin dashboard data
  app.get("/api/admin/stats", ensureAdmin, async (req, res) => {
    try {
      const analyticsData = await getAnalyticsData();
      res.json(analyticsData);
    } catch (error) {
      console.error("Error in admin analytics endpoint:", error);
      res.status(500).json({ message: "Failed to fetch analytics data" });
    }
  });

  // Get all users
  app.get("/api/admin/users", ensureAdmin, async (req, res) => {
    try {
      const users = await getAllUsers();
      res.json(users);
    } catch (error) {
      console.error("Error in admin get all users endpoint:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  // Update user role
  app.put("/api/admin/users/:userId/role", ensureAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      const { role } = req.body;

      if (!role || !['user', 'admin', 'guest'].includes(role)) {
        return res.status(400).json({ message: "Invalid role" });
      }

      const user = await updateUserRole(userId, role);
      res.json(user);
    } catch (error) {
      console.error("Error in admin update user role endpoint:", error);
      res.status(500).json({ message: "Failed to update user role" });
    }
  });

  // Get products by user ID (admin only)
  app.get("/api/admin/users/:userId/products", ensureAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      const products = await storage.getProducts(userId);
      res.json(products);
    } catch (error) {
      console.error("Error in admin get user products endpoint:", error);
      res.status(500).json({ message: "Failed to fetch user products" });
    }
  });

  // Delete product (admin only)
  app.delete("/api/admin/products/:productId", ensureAdmin, async (req, res) => {
    try {
      const productId = parseInt(req.params.productId);
      await storage.deleteProduct(productId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error in admin delete product endpoint:", error);
      res.status(500).json({ message: "Failed to delete product" });
    }
  });
}