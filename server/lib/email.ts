import nodemailer from "nodemailer";
import { randomBytes } from "crypto";
import dotenv from 'dotenv';

dotenv.config();

let transporter: nodemailer.Transporter;

// Initialize email transporter
export async function initEmailTransport() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    // Production email configuration
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      }
    });
    console.log("Using configured SMTP server for emails");
  } else {
    // Development/testing - use Ethereal
    const testAccount = await nodemailer.createTestAccount();
    transporter = nodemailer.createTransport({
      host: "smtp.ethereal.email",
      port: 587,
      secure: false,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });
    console.log("Using Ethereal for email testing. Preview URL:", testAccount.web);
  }
}

export function generateVerificationCode(): string {
  // Generate a 6-digit code
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export function generateVerificationToken(): string {
  return generateVerificationCode();
}

export function generateResetToken(): string {
  return randomBytes(32).toString('hex');
}

export async function sendVerificationEmail(email: string, code: string, username: string): Promise<string> {
  const appUrl = process.env.APP_URL || 'http://localhost:5000';
  const verificationUrl = `${appUrl}/auth?code=${code}&verify=true`;

  console.log("Sending verification email to:", email);
  console.log("Verification URL:", verificationUrl);

  // Send verification email
  const info = await transporter.sendMail({
    from: process.env.SMTP_FROM || '"Product Scanner" <noreply@example.com>',
    to: email,
    subject: "Verify your email address",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome to Product Scanner!</h2>
        <p>Hi ${username},</p>
        <p>Your verification code is: <strong style="font-size: 24px; color: #4CAF50">${code}</strong></p>
        <p>You can either:</p>
        <ol>
          <li>Enter this code on the verification page, or</li>
          <li><a href="${verificationUrl}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Click here to verify automatically</a></li>
        </ol>
        <p>This code will expire in 24 hours.</p>
        <p>Thank you,<br>Product Scanner Team</p>
      </div>
    `
  });

  // Return preview URL for development
  const previewUrl = nodemailer.getTestMessageUrl(info);
  if (previewUrl) {
    console.log("Email preview URL:", previewUrl);
  }
  return typeof previewUrl === 'string' ? previewUrl : '';
}

export async function sendPasswordResetEmail(email: string, token: string, username: string): Promise<string> {
  const appUrl = process.env.APP_URL || 'http://localhost:5000';
  const resetUrl = `${appUrl}/auth?reset=${token}`;

  // Send reset email
  const info = await transporter.sendMail({
    from: process.env.SMTP_FROM || '"Product Scanner" <noreply@example.com>',
    to: email,
    subject: "Reset your password",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Password Reset Request</h2>
        <p>Hi ${username},</p>
        <p>We received a request to reset your password. Click the button below to reset it:</p>
        <p style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
        </p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        <p>This link will expire in 1 hour.</p>
        <p>Thank you,<br>Product Scanner Team</p>
      </div>
    `
  });

  // Return preview URL for development
  const previewUrl = nodemailer.getTestMessageUrl(info);
  if (previewUrl) {
    console.log("Email preview URL:", previewUrl);
  }
  return typeof previewUrl === 'string' ? previewUrl : '';
}