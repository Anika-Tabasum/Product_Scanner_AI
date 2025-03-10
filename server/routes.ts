<<<<<<< HEAD
import type { Express } from "express";
=======
import express, { type Express } from "express";
>>>>>>> e6c0e49 (admin fix)
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { extractTextFromImage } from "./lib/ocr";
import { identifyProduct } from "./lib/openai";
import { insertProductSchema } from "@shared/schema";
<<<<<<< HEAD

export async function registerRoutes(app: Express): Promise<Server> {
  app.post("/api/products/identify", async (req, res) => {
    try {
=======
import { registerProfileRoutes } from "./routes/profile";
import { registerAdminRoutes } from "./routes/admin";
import { registerResetPasswordRoutes } from "./routes/reset-password";
import path from "path";

export async function registerRoutes(app: Express): Promise<Server> {
  // Serve uploaded files
  app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));
  
  // Register other route modules
  registerProfileRoutes(app);
  registerAdminRoutes(app);
  registerResetPasswordRoutes(app);
  app.post("/api/products/identify", async (req, res) => {
    try {
      // Check if user is authenticated
      if (!req.isAuthenticated || !req.isAuthenticated()) {
        return res.status(401).json({ message: "Authentication required" });
      }

>>>>>>> e6c0e49 (admin fix)
      const { image } = req.body;

      if (!image) {
        return res.status(400).json({ message: "Image is required" });
      }

      console.log('Starting OCR process...');
      const extractedText = await extractTextFromImage(image);
      console.log('Extracted text:', extractedText);

      console.log('Starting OpenAI identification...');
      const productDetails = await identifyProduct(image, extractedText);
      console.log('Product details:', productDetails);

<<<<<<< HEAD
=======
      // Use the logged-in user's ID instead of an auto-incremented value
      const userId = req.user?.id;
      console.log(`Creating product for user ID: ${userId}`);

      // Make sure userId is defined before creating the product
      if (!userId) {
        return res.status(401).json({ message: "User ID not available. Please log in again." });
      }

>>>>>>> e6c0e49 (admin fix)
      const product = await storage.createProduct({
        ...productDetails,
        identifiedText: extractedText,
        imageUrl: image,
        metadata: {}
<<<<<<< HEAD
      });
=======
      }, userId);

      console.log(`Product created successfully for user ID: ${userId}`);
>>>>>>> e6c0e49 (admin fix)

      res.json(product);
    } catch (error) {
      console.error('Detailed error:', error);
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      res.status(500).json({ message: `Failed to process image: ${errorMessage}` });
    }
  });

  app.get("/api/products", async (req, res) => {
    try {
<<<<<<< HEAD
      const products = await storage.getProducts();
      res.json(products);
=======
      // Only get products for the authenticated user
      if (req.isAuthenticated && req.isAuthenticated()) {
        const userId = req.user?.id;
        console.log(`Fetching products for user ID: ${userId}`);
        const products = await storage.getProducts(userId);
        res.json(products);
      } else {
        // If not authenticated, return empty array
        res.json([]);
      }
>>>>>>> e6c0e49 (admin fix)
    } catch (error) {
      console.error('Error fetching products:', error);
      res.status(500).json({ message: "Failed to fetch products" });
    }
  });

  app.get("/api/products/search", async (req, res) => {
    try {
      const { q } = req.query;
      if (!q || typeof q !== "string") {
        return res.status(400).json({ message: "Search query required" });
      }
      const products = await storage.searchProducts(q);
      res.json(products);
    } catch (error) {
      console.error('Error searching products:', error);
      res.status(500).json({ message: "Failed to search products" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}