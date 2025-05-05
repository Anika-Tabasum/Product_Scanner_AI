import express, { type Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { extractTextFromImage } from "./lib/ocr";
import { identifyProduct } from "./lib/openai";
import { insertProductSchema, insertGGSDataSchema } from "@shared/schema";
import { registerProfileRoutes } from "./routes/profile";
import { registerAdminRoutes } from "./routes/admin";
import { registerResetPasswordRoutes } from "./routes/reset-password";
import { registerPaymentRoutes } from "./routes/payment";
import path from "path";
import fs from "fs";
import { parse, CsvError } from "csv-parse";
import { requireCredits, CREDIT_COSTS } from "./middleware/credits";
import { setupPayment } from "./payment-bd";

export async function registerRoutes(app: Express): Promise<Server> {
  // Health check endpoint for Docker
  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // Project and team information endpoint
  app.get("/info", (_req, res) => {
    const teamMembers = [
      {
        name: "Md Shahadat Hossain Shahal",
        id: "2220914",
        github_id: "shahal-dev",
        github_profile: "https://github.com/shahal-dev",
        personal_notion_page: "https://www.notion.so/LLM-Based-Product-Scanner-1ead07997c7180c2954ceb6ca1cb6bf5",
        personal_group_page_notion: "https://www.notion.so/Group-IV-1980c4a3a7b380d4ab32f8b5de211c52"
      },
      {
        name: "Anika Tabasum",
        id: "2220988",
        github_id: "Anika-Tabasum",
        github_profile: "https://github.com/Anika-Tabasum",
        personal_notion_page: "https://www.notion.so/LLM-Based-Product-Scanner-1ead07997c7180c2954ceb6ca1cb6bf5",
        personal_group_page_notion: "https://www.notion.so/Group-IV-1980c4a3a7b380d4ab32f8b5de211c52"
      },
      {
        name: "Tasdir Ahmmed",
        id: "2222325",
        github_id: "tasdir",
        github_profile: "https://github.com/tasdir",
        personal_notion_page: "https://www.notion.so/LLM-Based-Product-Scanner-1ead07997c7180c2954ceb6ca1cb6bf5",
        personal_group_page_notion: "https://www.notion.so/Group-IV-1980c4a3a7b380d4ab32f8b5de211c52"
      },
      {
        name: "Md Rasel Bhuyan",
        id: "2222230",
        github_id: "Mdrasel1230",
        github_profile: "https://github.com/Mdrasel1230",
        personal_notion_page: "https://www.notion.so/LLM-Based-Product-Scanner-1ead07997c7180c2954ceb6ca1cb6bf5",
        personal_group_page_notion: "https://www.notion.so/Group-IV-1980c4a3a7b380d4ab32f8b5de211c52"
      }
    ];

    const projectInfo = {
      project_name: "Product Scanner AI",
      project_github_link: "https://github.com/Anika-Tabasum/Product_Scanner_AI",
      team_members: teamMembers
    };

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Project Info</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
  <div class="container py-5">
    <div class="text-center mb-4">
      <h1>${projectInfo.project_name}</h1>
      <a href="${projectInfo.project_github_link}" class="btn btn-primary" target="_blank">View Project on GitHub</a>
    </div>
    <div class="card">
      <div class="card-header">Team Members</div>
      <div class="table-responsive">
        <table class="table table-striped table-hover mb-0">
          <thead class="table-dark">
            <tr>
              <th>Name</th>
              <th>ID</th>
              <th>GitHub ID</th>
              <th>GitHub Profile</th>
              <th>Personal Notion</th>
              <th>Group Notion</th>
            </tr>
          </thead>
          <tbody>
            ${teamMembers.map(member => `
              <tr>
                <td>${member.name}</td>
                <td>${member.id}</td>
                <td>${member.github_id}</td>
                <td><a href="${member.github_profile}" target="_blank">${member.github_id}</a></td>
                <td><a href="${member.personal_notion_page}" target="_blank">Personal Notion</a></td>
                <td><a href="${member.personal_group_page_notion}" target="_blank">Group Notion</a></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>`;

    res.header("Content-Type", "text/html; charset=utf-8").send(html);
  });
  
  // Serve uploaded files
  app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

  // Evaluation criteria marks endpoint
  app.get("/marks", (_req, res) => {
    const data = [
      { feature_name: "OCR & AI-Powered Identification", mark: 10, justification: "Image upload is fully functional, integrated with a preprocessing OCR module that extracts text, which is then passed to OpenAI's API for accurate, contextual product identification. This includes fallback handling, edge-case tolerance, and real-time feedback on predictions.", internal_route: "/api/products/identify" },
      { feature_name: "Credits System", mark: 10, justification: "Every AI operation deducts credits from users. Admin dashboard allows credit top-ups and real-time usage monitoring. The implementation includes backend enforcement, real-time UI updates, and future readiness for monetization tiers.", internal_route: "/api/credits, /api/credits/history" },
      { feature_name: "Payment System", mark: 10, justification: "Custom payment flow implementation with transaction history tracking. Users can initiate payments, submit verification, and view transaction history. System includes admin verification workflow and automatic credit balance updates.", internal_route: "/api/payment-methods, /api/verify-payment/:id" }
    ];
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Evaluation Marks</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; }
    h1 { margin-bottom: 30px; text-align: center; color: #333; }
    .table-container { max-width: 1200px; margin: 0 auto; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    th { background-color: #0d6efd; color: white; font-weight: bold; text-align: left; }
    th, td { padding: 12px 15px; border: 1px solid #ddd; }
    tr:nth-child(even) { background-color: #f8f9fa; }
    tr:hover { background-color: #e9ecef; }
    .mark-cell { font-weight: bold; font-size: 1.2em; text-align: center; }
    .feature-cell { font-weight: bold; color: #0d6efd; }
    .checkmark { color: #198754; font-size: 1.5em; margin-right: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Evaluation Table for /marks Route</h1>
    <div id="marks-table" class="table-container"></div>
  </div>
  <script>
    // Data for the table
    const data = ${JSON.stringify(data)};
    
    // Column headers
    const columns = ["Feature Name", "Mark", "Justification for This Marking", "Internal Route"];
    
    // Create table using D3.js
    const table = d3.select("#marks-table")
      .append("table")
      .attr("class", "table table-bordered");
      
    // Create table header
    const thead = table.append("thead");
    thead.append("tr")
      .selectAll("th")
      .data(columns)
      .enter()
      .append("th")
      .text(d => d);
      
    // Create table body
    const tbody = table.append("tbody");
    
    // Create rows
    const rows = tbody.selectAll("tr")
      .data(data)
      .enter()
      .append("tr");
      
    // Add feature name cells
    rows.append("td")
      .attr("class", "feature-cell")
      .text(d => d.feature_name);
      
    // Add mark cells with special styling
    rows.append("td")
      .attr("class", "mark-cell")
      .text(d => d.mark);
      
    // Add justification cells
    rows.append("td")
      .text(d => d.justification);
      
    // Add route cells
    rows.append("td")
      .text(d => d.internal_route);
  </script>
</body>
</html>`;
    res.header("Content-Type", "text/html; charset=utf-8").send(html);
  });

  // Register other route modules
  registerProfileRoutes(app);
  registerAdminRoutes(app);
  registerResetPasswordRoutes(app);
  registerPaymentRoutes(app);
  setupPayment(app);

  app.post("/api/products/identify", requireCredits(CREDIT_COSTS.IDENTIFY_PRODUCT), async (req, res) => {
    try {
      // Check if user is authenticated or has guest session
      const isGuest = req.session.isGuest === true;
      const isAuthenticated = req.isAuthenticated && req.isAuthenticated();
      
      if (!isAuthenticated && !isGuest) {
        return res.status(401).json({ message: "Authentication or guest access required" });
      }

      const { image } = req.body;

      if (!image) {
        return res.status(400).json({ message: "Image is required" });
      }

      console.log('Starting OCR process...');
      const extractedText = await extractTextFromImage(image);
      console.log('Extracted text:', extractedText);

      let productDetails;
      try {
        console.log('Starting OpenAI identification...');
        productDetails = await identifyProduct(image, extractedText);
        console.log('Product details:', productDetails);
      } catch (error) {
        console.error('Error identifying product with OpenAI:', error);
        
        // Simple fallback identification based on OCR text
        // This allows guest users to test the feature even without a working OpenAI key
        console.log('Using fallback identification based on OCR text');
        
        // Extract keywords from OCR text for simple categorization
        const lowerText = extractedText.toLowerCase();
        let category = 'Electronics'; // Default
        let brand = 'Unknown';
        
        // Simple brand detection
        if (lowerText.includes('nvidia') || lowerText.includes('geforce') || lowerText.includes('rtx')) {
          brand = 'NVIDIA';
        } else if (lowerText.includes('amd') || lowerText.includes('radeon')) {
          brand = 'AMD';
        } else if (lowerText.includes('intel')) {
          brand = 'Intel';
        } else if (lowerText.includes('samsung')) {
          brand = 'Samsung';
        } else if (lowerText.includes('apple') || lowerText.includes('iphone')) {
          brand = 'Apple';
        }
        
        // Create product details based on OCR text
        productDetails = {
          name: `Product (${extractedText.slice(0, 30)}${extractedText.length > 30 ? '...' : ''})`,
          description: `This product was identified using OCR technology. The extracted text was: ${extractedText}`,
          brand: brand,
          category: category
        };
      }

      // For guest users, we don't save the product to the database
      // Just return the identified product details
      if (isGuest) {
        console.log('Guest user identified product (not saving to database)');
        return res.json({
          ...productDetails,
          temporary: true,
          message: "Product identified but not saved. Create an account to save your products."
        });
      }

      // For authenticated users, proceed with saving to the database
      const userId = req.user?.id;
      console.log(`Creating product for user ID: ${userId}`);

      // Make sure userId is defined before creating the product
      if (!userId) {
        return res.status(401).json({ message: "User ID not available. Please log in again." });
      }

      try {
        const product = await storage.createProduct({
          ...productDetails,
          identifiedText: extractedText,
          imageUrl: image,
          metadata: {}
        }, userId);

        console.log(`Product created successfully for user ID: ${userId}`);
        
        return res.json(product);
      } catch (error) {
        console.error('Error saving product to database:', error);
        // Still return the identified product even if saving fails
        return res.json({
          ...productDetails,
          temporary: true,
          message: "Product identified but encountered an error while saving. Please try again."
        });
      }
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
      const csvPath = path.join(process.cwd(), "GGS_new.csv");
      console.log('Looking for CSV file at:', csvPath);
      console.log('File exists:', fs.existsSync(csvPath));

      const fileContent = await fs.promises.readFile(csvPath, 'utf-8');
      console.log('CSV file read successfully');

      parse(fileContent, {
        columns: true,
        skip_empty_lines: true,
        trim: true,
        cast: true
      }, async (err: CsvError | undefined, records: Record<string, any>[]) => {
        if (err) {
          console.error('CSV parsing error:', err);
          throw err;
        }

        console.log(`Processing ${records.length} records...`);
        console.log('Sample record:', records[0]);

        try {
          // Clear existing data first
          await storage.clearGGSData();

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

          console.log('CSV import completed successfully');
          res.json({ 
            success: true,
            message: "CSV data imported successfully",
            recordCount: records.length
          });
        } catch (error) {
          console.error('Error during bulk insert:', error);
          res.status(500).json({ 
            success: false,
            message: "Failed to import CSV data",
            error: error.message
          });
        }
      });
    } catch (error: unknown) {
      console.error('Error importing CSV:', error);
      const err = error as Error;
      res.status(500).json({ 
        success: false,
        message: "Failed to import CSV data",
        error: err.message
      });
    }
  });

  app.get("/api/products/search", requireCredits(CREDIT_COSTS.SEARCH_PRODUCT), async (req, res) => {
    try {
      const { q } = req.query;
      if (!q || typeof q !== "string") {
        return res.status(400).json({ message: "Search query required" });
      }
      const products = await storage.searchProducts(q);
      res.json(products);
    } catch (error) {
      console.error('Error searching products:', error);
      const err = error as Error;
      res.status(500).json({ 
        message: "Failed to search products",
        error: err.message
      });
    }
  });
  const httpServer = createServer(app);
  return httpServer;
}