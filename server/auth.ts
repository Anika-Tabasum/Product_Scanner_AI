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
<<<<<<< HEAD
=======
import { generateVerificationToken, sendVerificationEmail } from "./lib/email";
>>>>>>> e6c0e49 (admin fix)

declare global {
  namespace Express {
    interface User extends SelectUser {}
  }
}

const scryptAsync = promisify(scrypt);

<<<<<<< HEAD
async function hashPassword(password: string) {
=======
export async function hashPassword(password: string) {
>>>>>>> e6c0e49 (admin fix)
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

<<<<<<< HEAD
async function comparePasswords(supplied: string, stored: string) {
=======
export async function comparePasswords(supplied: string, stored: string) {
>>>>>>> e6c0e49 (admin fix)
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

export function setupAuth(app: Express) {
  if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET environment variable is required");
  }

  const sessionSettings: session.SessionOptions = {
    secret: process.env.SESSION_SECRET,
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

<<<<<<< HEAD
  // Modify the registration endpoint to not automatically log in
  app.post("/api/register", async (req, res, next) => {
    try {
=======
  // Modify the registration endpoint to include email verification
  app.post("/api/register", async (req, res, next) => {
    try {
      // Check if username or email already exists
>>>>>>> e6c0e49 (admin fix)
      const existingUser = await storage.getUserByUsername(req.body.username);
      if (existingUser) {
        return res.status(400).json({ message: "Username already exists" });
      }
<<<<<<< HEAD

      const hashedPassword = await hashPassword(req.body.password);
      const user = await storage.createUser({
        username: req.body.username,
        password: hashedPassword,
      });

      // Return success without logging in
      res.status(201).json({ message: "Registration successful" });
=======
      
      const existingEmail = await storage.getUserByEmail(req.body.email);
      if (existingEmail) {
        return res.status(400).json({ message: "Email already exists" });
      }

      // Generate verification token
      const verificationToken = generateVerificationToken();
      
      // Hash password
      const hashedPassword = await hashPassword(req.body.password);
      
      // Create user with verification token
      const user = await storage.createUser({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword,
        isVerified: "false",
        verificationToken,
      });

      // Send verification email
      try {
        const emailUrl = await sendVerificationEmail(req.body.email, verificationToken, req.body.username);
        console.log("Verification email preview:", emailUrl);
      } catch (emailError) {
        console.error("Failed to send verification email:", emailError);
        // Continue anyway, we don't want to prevent registration if email fails
      }

      // Return success without logging in
      res.status(201).json({ 
        message: "Registration successful! Please check your email to verify your account." 
      });
>>>>>>> e6c0e49 (admin fix)
    } catch (error) {
      next(error);
    }
  });
<<<<<<< HEAD
=======
  
  // Add email verification endpoint
  app.get("/api/verify-email", async (req, res) => {
    try {
      const { token } = req.query;
      
      if (!token || typeof token !== "string") {
        return res.status(400).json({ message: "Invalid verification token" });
      }
      
      // Find user with this verification token
      const user = await storage.getUserByVerificationToken(token);
      
      if (!user) {
        return res.status(404).json({ message: "Verification token not found or already used" });
      }
      
      // Mark user as verified
      await storage.verifyUser(user.id);
      
      // Redirect to login page or show success message
      res.redirect("/auth?verified=true");
    } catch (error) {
      console.error("Email verification error:", error);
      res.status(500).json({ message: "Error during email verification" });
    }
  });
>>>>>>> e6c0e49 (admin fix)

  app.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err: Error | null, user: Express.User | false) => {
      if (err) return next(err);
      if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
      }
      req.login(user, (err) => {
        if (err) return next(err);
<<<<<<< HEAD
=======
        console.log(`User logged in: ${user.username} (ID: ${user.id})`);
>>>>>>> e6c0e49 (admin fix)
        res.json(user);
      });
    })(req, res, next);
  });

  app.post("/api/logout", (req, res, next) => {
<<<<<<< HEAD
    req.logout((err) => {
      if (err) return next(err);
=======
    const user = req.user;
    req.logout((err) => {
      if (err) return next(err);
      if (user) {
        console.log(`User logged out: ${user.username} (ID: ${user.id})`);
      }
>>>>>>> e6c0e49 (admin fix)
      res.sendStatus(200);
    });
  });

  app.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    res.json(req.user);
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