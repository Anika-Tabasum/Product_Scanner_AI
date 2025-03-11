import express, { type Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { extractTextFromImage } from "./lib/ocr";
import { identifyProduct } from "./lib/openai";
import { insertProductSchema, insertGGSDataSchema } from "@shared/schema";
import { registerProfileRoutes } from "./routes/profile";
import { registerAdminRoutes } from "./routes/admin";
import { registerResetPasswordRoutes } from "./routes/reset-password";
import path from "path";
import fs from "fs";
import { parse } from "csv-parse";

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

      // Use the logged-in user's ID instead of an auto-incremented value
      const userId = req.user?.id;
      console.log(`Creating product for user ID: ${userId}`);

      // Make sure userId is defined before creating the product
      if (!userId) {
        return res.status(401).json({ message: "User ID not available. Please log in again." });
      }

      const product = await storage.createProduct({
        ...productDetails,
        identifiedText: extractedText,
        imageUrl: image,
        metadata: {}
      }, userId);

      console.log(`Product created successfully for user ID: ${userId}`);

      res.json(product);
    } catch (error) {
      console.error('Detailed error:', error);
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      res.status(500).json({ message: `Failed to process image: ${errorMessage}` });
    }
  });

  app.get("/api/products", async (req, res) => {
    try {
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
    } catch (error) {
      console.error('Error fetching products:', error);
      res.status(500).json({ message: "Failed to fetch products" });
    }
  });

  // GGS Data Routes
  app.get("/api/statuses", async (req, res) => {
    try {
      console.log('Fetching GGS data...');
      const [genderStats, eventsByGender] = await Promise.all([
        storage.getGGSDataByGender(),
        storage.getGGSEventsByGender()
      ]);

      console.log('GGS data fetched:', { genderStats, eventsByGender });
      res.json({
        genderStats,
        eventsByGender
      });
    } catch (error) {
      console.error('Error fetching GGS data:', error);
      res.status(500).json({ message: "Failed to fetch GGS data" });
    }
  });

  // Import CSV data route
  app.post("/api/ggs/import", async (req, res) => {
    try {
      console.log('Starting CSV import process...');
      const csvPath = path.join(process.cwd(), "attached_assets", "GGS_new.csv");
      const fileContent = await fs.promises.readFile(csvPath, 'utf-8');
      console.log('CSV file read successfully');

      parse(fileContent, {
        columns: true,
        skip_empty_lines: true,
        trim: true
      }, async (err: Error | null, records: Record<string, any>[]) => {
        if (err) {
          console.error('CSV parsing error:', err);
          throw err;
        }

        console.log(`Processing ${records.length} records...`);

        for (const record of records) {
          const eventData: Record<string, string> = {};
          // Extract a15.1 to a34.12 columns into eventData
          for (let i = 15; i <= 34; i++) {
            for (let j = 1; j <= 12; j++) {
              const key = `a${i}.${j}`;
              if (record[key]) {
                eventData[key] = record[key];
              }
            }
          }

          try {
            await storage.createGGSData({
              originalId: parseInt(record.ID || '0'),
              sex: parseInt(record.sex || '0'),
              generations: parseInt(record.generations || '0'),
              eduLevel: parseInt(record.edu_level || '0'),
              age: parseInt(record.age || '0'),
              eventData
            });
          } catch (e) {
            console.error('Error processing record:', record, e);
          }
        }

        console.log('CSV import completed');
        res.json({ message: "CSV data imported successfully" });
      });
    } catch (error) {
      console.error('Error importing CSV:', error);
      res.status(500).json({ message: "Failed to import CSV data" });
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