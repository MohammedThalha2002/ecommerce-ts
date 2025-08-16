import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET as string;

export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const auth = req.headers.authorization || "";
    const [scheme, token] = auth.split(" ");

    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const decoded = jwt.verify(token, JWT_SECRET) as {
      id: number;
      email: string;
      role?: string;
    };

    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role ?? "customer",
    };

    return next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}
