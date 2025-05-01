import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GitHubStrategy } from "passport-github2";
import type { Profile } from "passport-github2";
import express, { Express, Request, Response, NextFunction, RequestHandler } from "express";
import type { Handler } from 'express';
import session from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { storage } from "./storage";
import { User as SelectUser } from "@shared/schema";
import { generateVerificationToken, sendVerificationEmail } from "./lib/email";

declare global {
  namespace Express {
    interface User extends SelectUser {}
    type RequestHandler = import('express').RequestHandler;
  }
}

const scryptAsync = promisify(scrypt);

export async function hashPassword(password: string) {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

export async function comparePasswords(supplied: string, stored: string) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

export function setupAuth(app: Express) {
  // Access SESSION_SECRET from environment variables
  const sessionSecret = process.env.SESSION_SECRET;
  console.log("SESSION_SECRET available:", !!sessionSecret); // Log if session secret is available

  if (!sessionSecret) {
    throw new Error("SESSION_SECRET environment variable is required");
  }

  const sessionSettings: session.SessionOptions = {
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: true,
      sameSite: 'lax',
    },
    rolling: true, // Refresh session with each request
    name: 'prod_scan.sid', // Custom session cookie name
  };

  app.set("trust proxy", 1);
  app.use(session(sessionSettings) as any);
  // Use type assertion to handle passport middleware type compatibility
  app.use(passport.initialize() as any);
  app.use(passport.session() as any);

  // Add user serialization
  passport.serializeUser((user: Express.User, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: number, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user || false);
    } catch (error) {
      done(error);
    }
  });

  passport.use(
    new LocalStrategy(async (username: string, password: string, done) => {
      try {
        const user = await storage.getUserByUsername(username);
        if (!user || !(await comparePasswords(password, user.password))) {
          return done(null, false);
        }

        // Check if user is verified
        if (user.isVerified === false) {
          return done(null, false, { message: "Please verify your email before logging in" });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }),
  );

  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    passport.use(
      new GitHubStrategy(
        {
          clientID: process.env.GITHUB_CLIENT_ID,
          clientSecret: process.env.GITHUB_CLIENT_SECRET,
          callbackURL: "/api/auth/github/callback",
        },
        async (accessToken: string, refreshToken: string, profile: Profile, done: (error: any, user?: any) => void) => {
          try {
            let user = await storage.getUserByUsername(profile.username || '');
            if (!user) {
              // Create a new user with a random password
              const password = await hashPassword(randomBytes(32).toString("hex"));
              user = await storage.createUser({
                username: profile.username || profile.id,
                password,
                email: profile.emails?.[0]?.value || `${profile.username || profile.id}@example.com`,
              });
            }
            return done(null, user);
          } catch (error) {
            return done(error);
          }
        },
      ),
    );
  }

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id: number, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });

  // Update the registration endpoint to include better error handling
  // Endpoint to resend verification email
  app.post("/api/resend-verification", async (req: Request, res: Response) => {
    try {
      const { email } = req.body;
      
      // Find user by email
      const user = await storage.getUserByEmail(email);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "No account found with this email address."
        });
      }

      if (user.isVerified) {
        return res.status(400).json({
          success: false,
          message: "This account is already verified."
        });
      }

      // Generate new verification token
      const verificationToken = generateVerificationToken();
      
      // Update user with new token
      await storage.updateUserVerificationToken(user.id, verificationToken);
      
      // Send new verification email
      await sendVerificationEmail(email, verificationToken, req.body.username);

      res.status(200).json({
        success: true,
        message: "A new verification email has been sent. Please check your inbox."
      });
    } catch (error) {
      console.error("Error resending verification:", error);
      res.status(500).json({
        success: false,
        message: "Failed to resend verification email. Please try again later."
      });
    }
  });

  // Endpoint to delete unverified account
  app.post("/api/delete-unverified", async (req: Request, res: Response) => {
    try {
      const { email } = req.body;
      
      // Find user by email
      const user = await storage.getUserByEmail(email);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "No account found with this email address."
        });
      }

      if (user.isVerified) {
        return res.status(400).json({
          success: false,
          message: "This account is already verified and cannot be deleted."
        });
      }

      // Delete the unverified user
      await storage.deleteUser(user.id);

      res.status(200).json({
        success: true,
        message: "Unverified account has been deleted. You can now register again."
      });
    } catch (error) {
      console.error("Error deleting unverified account:", error);
      res.status(500).json({
        success: false,
        message: "Failed to delete account. Please try again later."
      });
    }
  });

  app.post("/api/register", async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Check if username or email exists
      const existingUser = await storage.getUserByUsername(req.body.username);
      const existingEmail = await storage.getUserByEmail(req.body.email);
      
      // Handle existing accounts
      if (existingUser) {
        // If username exists but not verified, delete it
        if (!existingUser.isVerified) {
          await storage.deleteUser(existingUser.id);
        } else {
          return res.status(400).json({
            success: false,
            message: "Username already exists and is verified"
          });
        }
      }
      
      if (existingEmail) {
        // If email exists but not verified, delete it
        if (!existingEmail.isVerified) {
          await storage.deleteUser(existingEmail.id);
        } else {
          return res.status(400).json({
            success: false,
            message: "Email already registered and verified"
          });
        }
      }

      const hashedPassword = await hashPassword(req.body.password);
      const verificationToken = generateVerificationToken();

      // Create user with verification token and isVerified set to false
      await storage.createUser({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword,
        verificationToken,
        isVerified: false
      });

      // Send verification email
      try {
        const previewUrl = await sendVerificationEmail(
          req.body.email,
          verificationToken,
          req.body.username
        );
        console.log("Verification email sent, preview:", previewUrl);
      } catch (emailError) {
        console.error("Failed to send verification email:", emailError);
        // If email fails, delete the user and return an error
        const user = await storage.getUserByEmail(req.body.email);
        if (user) {
          await storage.deleteUser(user.id);
        }
        return res.status(500).json({
          success: false,
          message: "Failed to send verification email. Please try registering again."
        });
      }

      // Return success response with verification required flag
      res.status(201).json({
        success: true,
        requiresVerification: true,
        message: "Registration successful! Please check your email to verify your account before logging in.",
        emailSent: true
      });
    } catch (error) {
      console.error("Registration error:", error);
      next(error);
    }
  });

  // In the setupAuth function, update the verification endpoint
  app.get("/api/verify-email", async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { token, code } = req.query;
      const verificationCode = token || code;

      if (!verificationCode || typeof verificationCode !== "string") {
        return res.status(400).json({
          success: false,
          message: "Please provide a verification code"
        });
      }

      // Find user with this verification code
      const user = await storage.getUserByVerificationToken(verificationCode);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Invalid or expired verification code"
        });
      }

      // Add initial credits (50) for new users
      await storage.updateUserCredits(user.id, 50);

      // Mark user as verified
      await storage.verifyUser(user.id);

      // Return success response
      return res.json({
        success: true,
        message: "Email verification successful! You can now log in."
      });
    } catch (error) {
      console.error("Email verification error:", error);
      return res.status(500).json({
        success: false,
        message: "Error during email verification"
      });
    }
  });

  app.post("/api/login", (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate("local", (err: Error | null, user: Express.User | false, info: any) => {
      if (err) return next(err);
      
      // Check if user exists but is not verified
      if (!user && info && info.message === "Please verify your email before logging in") {
        return res.status(403).json({
          success: false,
          requiresVerification: true,
          message: "Please verify your email before logging in. Check your inbox for the verification link."
        });
      }
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid credentials"
        });
      }

      req.login(user, (err) => {
        if (err) return next(err);
        console.log(`User logged in: ${user.username} (ID: ${user.id})`);
        res.json({
          success: true,
          user
        });
      });
    })(req, res, next);
  });

  app.post("/api/logout", (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;
    req.logout((err) => {
      if (err) return next(err);
      if (user) {
        console.log(`User logged out: ${user.username} (ID: ${user.id})`);
      }
      res.sendStatus(200);
    });
  });

  // Add guest access feature
  app.post("/api/guest", (req: Request, res: Response) => {
    // Create a guest session without requiring authentication
    if (req.isAuthenticated()) {
      return res.status(400).json({ message: "Already authenticated" });
    }

    // Set guest flag in session - no database record needed
    req.session.isGuest = true;
    req.session.guestCreatedAt = new Date().toISOString();

    res.status(200).json({
      guest: true,
      message: "Guest access granted",
      createdAt: req.session.guestCreatedAt
    });
  });

  // Get current user or guest status
  // Credit usage history endpoint
  app.get("/api/credits/history", async (req: Request, res: Response) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    try {
      const history = await storage.getCreditUsageHistory(req.user.id);
      res.json(history);
    } catch (error) {
      console.error("Error fetching credit history:", error);
      res.status(500).json({ message: "Error fetching credit history" });
    }
  });

  app.get("/api/user", (req: Request, res: Response) => {
    if (req.isAuthenticated()) {
      // Return authenticated user data
      return res.json(req.user);
    } else if (req.session.isGuest) {
      // Return guest status
      return res.json({
        guest: true,
        createdAt: req.session.guestCreatedAt
      });
    } else {
      // Not authenticated and not a guest
      return res.status(401).json({ message: "Not authenticated" });
    }
  });

  // GitHub OAuth routes
  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    app.get("/api/auth/github", passport.authenticate("github", { scope: ["user:email"] }));

    app.get(
      "/api/auth/github/callback",
      passport.authenticate("github", {
        successRedirect: "/",
        failureRedirect: "/auth",
      }),
    );
  }
}