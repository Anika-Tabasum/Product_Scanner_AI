import { products, users, ggsData, type Product, type InsertProduct, type User, type InsertUser, type GGSData, type InsertGGSData } from "@shared/schema";
import { db } from "./db";
import { eq, sql, count, desc } from "drizzle-orm";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { pool } from "./db";

const PostgresSessionStore = connectPg(session);

export interface IStorage {
  createProduct(product: InsertProduct, userId: number): Promise<Product>;
  getProducts(): Promise<Product[]>;
  getProduct(id: number): Promise<Product | undefined>;
  searchProducts(query: string): Promise<Product[]>;
  getUserProducts(userId: number): Promise<Product[]>;

  // Auth related methods
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getUserByVerificationToken(token: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  verifyUser(userId: number): Promise<void>;
  updateUserProfile(userId: number, data: Partial<User>): Promise<User>;
  changePassword(userId: number, password: string): Promise<void>;
  deleteUser(userId: number): Promise<void>;
  getAllUsers(): Promise<User[]>;

  // Password reset methods
  setPasswordResetToken(userId: number, resetToken: string): Promise<void>;
  getUserByResetToken(resetToken: string): Promise<User | undefined>;
  resetPassword(userId: number, hashedPassword: string): Promise<void>;

  // Admin stats methods
  getUserCount(): Promise<number>;
  getProductCount(): Promise<number>;
  getUserProductsCount(userId: number): Promise<number>;

  //Session store
  sessionStore: session.Store;

  // Admin analytics methods
  getUsersByRole(): Promise<Record<string, number>>;
  getProductsByCategory(): Promise<Record<string, number>>;
  getRecentUsers(limit: number): Promise<User[]>;
  updateUserRole(userId: number, role: string): Promise<User>;
  deleteProduct(productId: number): Promise<void>;

  // GGS Data methods
  createGGSData(data: InsertGGSData): Promise<GGSData>;
  getGGSDataByGender(): Promise<{ male: number; female: number }>;
  getGGSEventsByGender(): Promise<{ male: GGSData[]; female: GGSData[] }>;
  clearGGSData(): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  sessionStore: session.Store;

  constructor() {
    this.sessionStore = new PostgresSessionStore({
      pool,
      createTableIfMissing: true,
    });
  }

  async createProduct(insertProduct: InsertProduct, userId: number): Promise<Product> {
    const [product] = await db
      .insert(products)
      .values({ ...insertProduct, userId })
      .returning();
    return product;
  }

  async getProducts(userId?: number): Promise<Product[]> {
    if (userId) {
      return await db
        .select()
        .from(products)
        .where(eq(products.userId, userId));
    }
    return await db.select().from(products);
  }

  async getProduct(id: number): Promise<Product | undefined> {
    const [product] = await db
      .select()
      .from(products)
      .where(eq(products.id, id));
    return product;
  }

  async searchProducts(query: string): Promise<Product[]> {
    const lowercaseQuery = query.toLowerCase();
    return await db
      .select()
      .from(products)
      .where(
        sql`LOWER(name) LIKE ${`%${lowercaseQuery}%`} OR 
            LOWER(description) LIKE ${`%${lowercaseQuery}%`} OR 
            LOWER(brand) LIKE ${`%${lowercaseQuery}%`}`
      );
  }

  async getUserProducts(userId: number): Promise<Product[]> {
    return await db
      .select()
      .from(products)
      .where(eq(products.userId, userId));
  }

  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, id));
    return user;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.username, username));
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email));
    return user;
  }

  async getUserByVerificationToken(token: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.verificationToken, token));
    return user;
  }

  async createUser(userData: InsertUser): Promise<User> {
    // Create a properly typed user object with all required fields
    const userDataWithDefaults = {
      ...userData,
      role: "user",
      deleted: false,
      // isVerified is handled by the database default (false)
    };

    const [user] = await db
      .insert(users)
      .values(userDataWithDefaults)
      .returning();
    return user;
  }

  async verifyUser(userId: number): Promise<void> {
    await db
      .update(users)
      .set({
        isVerified: true,
        verificationToken: null
      })
      .where(eq(users.id, userId));
  }

  async updateUserProfile(userId: number, userData: Partial<User>): Promise<User> {
    const [updatedUser] = await db
      .update(users)
      .set(userData)
      .where(eq(users.id, userId))
      .returning();
    return updatedUser;
  }

  async changePassword(userId: number, password: string): Promise<void> {
    await db
      .update(users)
      .set({ password })
      .where(eq(users.id, userId));
  }

  async deleteUser(userId: number): Promise<void> {
    // First delete all associated products
    await db
      .delete(products)
      .where(eq(products.userId, userId));

    // Then delete the user
    await db
      .delete(users)
      .where(eq(users.id, userId));
  }

  async getAllUsers(): Promise<User[]> {
    return await db
      .select()
      .from(users);
  }

  async setPasswordResetToken(userId: number, resetToken: string): Promise<void> {
    await db.update(users)
      .set({ resetToken })
      .where(eq(users.id, userId));
  }

  async getUserByResetToken(resetToken: string): Promise<User | undefined> {
    const result = await db.select()
      .from(users)
      .where(eq(users.resetToken, resetToken))
      .limit(1);
    return result[0];
  }

  async resetPassword(userId: number, hashedPassword: string): Promise<void> {
    await db.update(users)
      .set({
        password: hashedPassword,
        resetToken: null
      })
      .where(eq(users.id, userId));
  }

  async getUserCount(): Promise<number> {
    const result = await db.select({ count: count() }).from(users);
    return result[0].count || 0;
  }

  async getProductCount(): Promise<number> {
    const result = await db.select({ count: count() }).from(products);
    return result[0].count || 0;
  }

  async getUserProductsCount(userId: number): Promise<number> {
    const result = await db.select({ count: count() })
      .from(products)
      .where(eq(products.userId, userId));
    return result[0].count || 0;
  }

  async getUsersByRole(): Promise<Record<string, number>> {
    const result = await db.select({
      role: users.role,
      count: count()
    })
      .from(users)
      .groupBy(users.role);

    return result.reduce((acc, { role, count }) => {
      acc[role] = count;
      return acc;
    }, {} as Record<string, number>);
  }

  async getProductsByCategory(): Promise<Record<string, number>> {
    const result = await db.select({
      category: products.category,
      count: count()
    })
      .from(products)
      .groupBy(products.category);

    return result.reduce((acc, { category, count }) => {
      if (category) {
        acc[category] = count;
      }
      return acc;
    }, {} as Record<string, number>);
  }

  async getRecentUsers(limit: number): Promise<User[]> {
    return db.select()
      .from(users)
      .orderBy(desc(users.createdAt))
      .limit(limit);
  }

  async updateUserRole(userId: number, role: string): Promise<User> {
    const updatedUsers = await db.update(users)
      .set({ role })
      .where(eq(users.id, userId))
      .returning();

    if (!updatedUsers || updatedUsers.length === 0) {
      throw new Error(`User with ID ${userId} not found`);
    }

    return updatedUsers[0];
  }

  async deleteProduct(productId: number): Promise<void> {
    await db.delete(products).where(eq(products.id, productId));
  }

  async createGGSData(data: InsertGGSData): Promise<GGSData> {
    const [ggsEntry] = await db
      .insert(ggsData)
      .values(data)
      .returning();
    return ggsEntry;
  }

  async getGGSDataByGender(): Promise<{ male: number; female: number }> {
    const result = await db
      .select({
        sex: ggsData.sex,
        count: count()
      })
      .from(ggsData)
      .groupBy(ggsData.sex);

    const counts = { male: 0, female: 0 };
    result.forEach(({ sex, count }) => {
      if (sex === 1) counts.male = count;
      if (sex === 2) counts.female = count;
    });
    return counts;
  }

  async getGGSEventsByGender(): Promise<{ male: GGSData[]; female: GGSData[] }> {
    const data = await db
      .select()
      .from(ggsData)
      .orderBy(ggsData.age);

    return {
      male: data.filter(d => d.sex === 1),
      female: data.filter(d => d.sex === 2)
    };
  }
  async clearGGSData(): Promise<void> {
    await db.delete(ggsData);
  }
}

export const storage = new DatabaseStorage();