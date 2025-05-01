import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { setupAuth } from "./auth";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

// Load environment variables from .env file (with debug output)
console.log("Current working directory:", process.cwd());
const envPath = path.resolve(process.cwd(), '.env');
console.log("Looking for .env file at:", envPath);
console.log(".env file exists:", fs.existsSync(envPath));

// Try to load environment variables directly from file
if (fs.existsSync(envPath)) {
  const envConfig = dotenv.parse(fs.readFileSync(envPath));
  Object.keys(envConfig).forEach(key => {
    process.env[key] = envConfig[key];
  });
  console.log("Environment variables loaded directly from .env file");
}

// Fallback to standard dotenv loading
dotenv.config();

// Hard-code SESSION_SECRET if not available (for development only)
if (!process.env.SESSION_SECRET) {
  console.log("Setting hardcoded SESSION_SECRET as fallback");
  process.env.SESSION_SECRET = "kergjfgejfgkqjwhfowgeqrhrfgqwiherfwqgfjvbjhwqe";
}

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: false, limit: '50mb' }));

// Serve static files from public directory
app.use(express.static('public'));
console.log("Serving static files from public directory");

// Add health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    time: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  // Log authenticated user
  if (req.isAuthenticated && req.isAuthenticated() && req.user) {
    console.log(`Request by authenticated user: ${req.user.username} (ID: ${req.user.id})`);
  }

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Initialize email transport
  const { initEmailTransport } = await import("./lib/email");
  await initEmailTransport();

  // Setup authentication before registering routes
  setupAuth(app);

  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    console.error('Server Error:', err);
    res.status(status).json({ message });
  });

  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Use port 5000 consistently as specified in .replit
  const port = 5000;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`Server is running on port ${port}`);
    log(`Health check available at http://localhost:${port}/api/health`);
  });
})();