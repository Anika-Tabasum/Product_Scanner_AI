import { Session } from 'express-session';

declare module 'express-session' {
  interface Session {
    isGuest?: boolean;
    guestCreatedAt?: string;
  }
}