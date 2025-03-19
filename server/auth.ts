import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GitHubStrategy } from "passport-github2";
import type { Profile } from "passport-github2";
import { Express } from "express";
import session from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { storage } from "./storage";
import { User as SelectUser } from "@shared/schema";
import { generateVerificationToken, sendVerificationEmail } from "./lib/email";

declare global {
  namespace Express {
    interface User extends SelectUser {}
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
    },
  };

  app.set("trust proxy", 1);
  app.use(session(sessionSettings));
  app.use(passport.initialize());
  app.use(passport.session());

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
  app.post("/api/register", async (req, res, next) => {
    try {
      // Check if username or email already exists
      const existingUser = await storage.getUserByUsername(req.body.username);
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "Username already exists"
        });
      }

      const existingEmail = await storage.getUserByEmail(req.body.email);
      if (existingEmail) {
        return res.status(400).json({
          success: false,
          message: "Email already exists"
        });
      }

      // Generate verification token
      const verificationToken = generateVerificationToken();

      // Hash password
      const hashedPassword = await hashPassword(req.body.password);

      // Create user
      const user = await storage.createUser({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword,
        verificationToken
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
        // Continue anyway but log the error
      }

      // Return success response
      res.status(201).json({
        success: true,
        message: "Registration successful! Please check your email to verify your account.",
        emailSent: true
      });
    } catch (error) {
      console.error("Registration error:", error);
      next(error);
    }
  });

  // In the setupAuth function, update the verification endpoint
  app.get("/api/verify-email", async (req, res) => {
    try {
      const { token } = req.query;

      if (!token || typeof token !== "string") {
        return res.status(400).json({
          success: false,
          message: "Invalid verification token"
        });
      }

      // Find user with this verification token
      const user = await storage.getUserByVerificationToken(token);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Verification token not found or already used"
        });
      }

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

  app.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err: Error | null, user: Express.User | false) => {
      if (err) return next(err);
      if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
      }
      req.login(user, (err) => {
        if (err) return next(err);
        console.log(`User logged in: ${user.username} (ID: ${user.id})`);
        res.json(user);
      });
    })(req, res, next);
  });

  app.post("/api/logout", (req, res, next) => {
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
  app.post("/api/guest", (req, res) => {
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
  app.get("/api/user", (req, res) => {
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