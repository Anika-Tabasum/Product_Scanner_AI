import { Request, Response, NextFunction } from "express";
import { deductCredits } from "../payment-bd";

// Credit costs for different operations
export const CREDIT_COSTS = {
  IDENTIFY_PRODUCT: 5,  // Cost for identifying a product
  SEARCH_PRODUCT: 1,    // Cost for searching products
};

export function requireCredits(cost: number) {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Skip credit check for guest users
    if (req.session.isGuest === true) {
      return next();
    }

    // Check if user is authenticated
    if (!req.isAuthenticated || !req.isAuthenticated() || !req.user) {
      return res.status(401).json({ 
        error: "Authentication required",
        requiresAuth: true
      });
    }

    try {
      await deductCredits(req.user.id, cost, "api_usage", {
        endpoint: req.path,
        method: req.method,
      });
      next();
    } catch (error) {
      const err = error as Error;
      if (err.message === "Insufficient credits") {
        return res.status(402).json({
          error: "Insufficient credits",
          requiredCredits: cost,
          requiresCredits: true
        });
      }
      next(error);
    }
  };
}
