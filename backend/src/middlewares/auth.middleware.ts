import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../modules/auth/auth.service.js";

export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const auth = req.headers.authorization || "";
    const [scheme, token] = auth.split(" ");

    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ message: "Access token required" });
    }

    const decoded = verifyAccessToken(token);

    req.user = {
      id: decoded.sub,
      email: "", // We don't include email in JWT for size optimization
      role: decoded.role,
    };

    return next();
  } catch (error: any) {
    if (error.message === "TOKEN_EXPIRED") {
      return res.status(401).json({
        message: "Access token expired",
        code: "TOKEN_EXPIRED",
      });
    }

    if (error.message === "INVALID_TOKEN") {
      return res.status(401).json({
        message: "Invalid access token",
        code: "INVALID_TOKEN",
      });
    }

    return res.status(401).json({ message: "Unauthorized" });
  }
}

// Optional auth middleware (doesn't fail if no token provided)
export function optionalAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const auth = req.headers.authorization || "";
    const [scheme, token] = auth.split(" ");

    if (scheme === "Bearer" && token) {
      const decoded = verifyAccessToken(token);

      req.user = {
        id: decoded.sub,
        email: "",
        role: decoded.role,
      };
    }

    return next();
  } catch {
    // In optional auth, we don't fail on token errors
    return next();
  }
}

// Role-based middleware
export function requireRole(role: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ message: "Authentication required" });
    }

    if (req.user.role !== role) {
      return res.status(403).json({
        message: "Insufficient permissions",
        required: role,
        current: req.user.role,
      });
    }

    return next();
  };
}

// Admin middleware (role = 1)
export const requireAdmin = requireRole(1);
