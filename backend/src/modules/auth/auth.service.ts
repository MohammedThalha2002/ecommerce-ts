import prisma from "../../config/db.js";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { nanoid } from "nanoid";

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET as string;
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || (process.env.JWT_SECRET as string);
const ACCESS_TOKEN_EXPIRES_IN = "15m"; // 15 minutes
const REFRESH_TOKEN_EXPIRES_IN = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds

// User roles enum
export enum UserRole {
  CUSTOMER = 0,
  ADMIN = 1,
}

// Types
type SafeUser = {
  id: string;
  email: string;
  name: string | null;
  role: number;
  emailVerifiedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

type AuthResponse = {
  user: SafeUser;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
};

type TokenPayload = {
  sub: string; // user id
  role: number;
  iat: number;
  exp: number;
  jti: string; // unique token id
};

type DeviceInfo = {
  ip?: string;
  userAgent?: string;
  deviceId?: string;
};

// Utility functions
const toSafeUser = (user: any): SafeUser => {
  const { passwordHash: _pw, ...rest } = user;
  return rest as SafeUser;
};

// Generate secure random token (256-bit)
function generateSecureToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

// Hash token using SHA-256
function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Create JWT access token
function createAccessToken(user: SafeUser): {
  token: string;
  expiresIn: number;
} {
  const jti = nanoid(); // Unique token ID
  const expiresIn = 15 * 60; // 15 minutes in seconds

  const payload: TokenPayload = {
    sub: user.id,
    role: user.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresIn,
    jti,
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    algorithm: "HS256", // Using HS256 for simplicity, ES256 would be better in production
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
  });

  return { token, expiresIn };
}

// Store refresh token with device info
async function storeRefreshToken(
  userId: string,
  token: string,
  deviceInfo: DeviceInfo
): Promise<void> {
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_IN);

  await prisma.refreshToken.create({
    data: {
      userId,
      tokenHash,
      expiresAt,
      createdByIp: deviceInfo.ip,
      userAgent: deviceInfo.userAgent,
      deviceId: deviceInfo.deviceId,
    },
  });
}

// Validate and get user from refresh token
async function validateRefreshToken(token: string): Promise<SafeUser> {
  const tokenHash = hashToken(token);

  const refreshToken = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    include: { user: true },
  });

  if (
    !refreshToken ||
    refreshToken.revokedAt ||
    refreshToken.expiresAt < new Date()
  ) {
    throw new Error("Invalid or expired refresh token");
  }

  return toSafeUser(refreshToken.user);
}

// Revoke refresh token (mark as revoked)
async function revokeRefreshToken(token: string): Promise<void> {
  const tokenHash = hashToken(token);

  await prisma.refreshToken.updateMany({
    where: { tokenHash },
    data: { revokedAt: new Date() },
  });
}

// Clean up expired and revoked tokens
async function cleanupExpiredTokens(userId?: string): Promise<void> {
  const where = userId
    ? {
        userId,
        OR: [{ expiresAt: { lt: new Date() } }, { revokedAt: { not: null } }],
      }
    : {
        OR: [{ expiresAt: { lt: new Date() } }, { revokedAt: { not: null } }],
      };

  await prisma.refreshToken.deleteMany({ where });
}

// Hash password using Argon2id
async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB
    timeCost: 3,
    parallelism: 4,
  });
}

// Verify password
async function verifyPassword(
  hash: string,
  password: string
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

// Auth service functions
export async function registerUser(params: {
  email: string;
  password: string;
  name?: string;
  deviceInfo?: DeviceInfo;
}): Promise<AuthResponse> {
  const { email, password, name, deviceInfo = {} } = params;

  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (existingUser) {
    throw new Error("Email already in use");
  }

  // Hash password
  const passwordHash = await hashPassword(password);

  // Create user
  const user = await prisma.user.create({
    data: {
      email: email.toLowerCase(),
      passwordHash,
      name,
      role: UserRole.CUSTOMER,
    },
  });

  const safeUser = toSafeUser(user);

  // Generate tokens
  const { token: accessToken, expiresIn } = createAccessToken(safeUser);
  const refreshToken = generateSecureToken();

  // Store refresh token
  await storeRefreshToken(user.id, refreshToken, deviceInfo);

  return {
    user: safeUser,
    accessToken,
    refreshToken,
    expiresIn,
  };
}

export async function loginUser(params: {
  email: string;
  password: string;
  deviceInfo?: DeviceInfo;
}): Promise<AuthResponse> {
  const { email, password, deviceInfo = {} } = params;

  // Find user
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (!user || !user.passwordHash) {
    throw new Error("Invalid email or password");
  }

  // Verify password
  const isValidPassword = await verifyPassword(user.passwordHash, password);
  if (!isValidPassword) {
    throw new Error("Invalid password");
  }

  // Clean up old tokens for this user
  await cleanupExpiredTokens(user.id);

  const safeUser = toSafeUser(user);

  // Generate tokens
  const { token: accessToken, expiresIn } = createAccessToken(safeUser);
  const refreshToken = generateSecureToken();

  // Store refresh token
  await storeRefreshToken(user.id, refreshToken, deviceInfo);

  return {
    user: safeUser,
    accessToken,
    refreshToken,
    expiresIn,
  };
}

export async function refreshAccessToken(
  oldRefreshToken: string,
  deviceInfo: DeviceInfo = {}
): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> {
  // Validate the old refresh token
  const user = await validateRefreshToken(oldRefreshToken);

  // Revoke the old refresh token (token rotation)
  await revokeRefreshToken(oldRefreshToken);

  // Generate new tokens
  const { token: accessToken, expiresIn } = createAccessToken(user);
  const newRefreshToken = generateSecureToken();

  // Store new refresh token
  await storeRefreshToken(user.id, newRefreshToken, deviceInfo);

  return {
    accessToken,
    refreshToken: newRefreshToken,
    expiresIn,
  };
}

export async function logoutUser(refreshToken: string): Promise<void> {
  await revokeRefreshToken(refreshToken);
}

export async function logoutAllDevices(userId: string): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { userId },
    data: { revokedAt: new Date() },
  });
}

export async function getCurrentUser(userId: string): Promise<SafeUser> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new Error("User not found");
  }

  return toSafeUser(user);
}

export async function getUserSessions(userId: string): Promise<any[]> {
  const sessions = await prisma.refreshToken.findMany({
    where: {
      userId,
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
    select: {
      id: true,
      createdByIp: true,
      userAgent: true,
      deviceId: true,
      createdAt: true,
      expiresAt: true,
    },
    orderBy: { createdAt: "desc" },
  });

  return sessions;
}

export async function revokeSession(
  userId: string,
  sessionId: string
): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: {
      id: sessionId,
      userId,
    },
    data: { revokedAt: new Date() },
  });
}

// Verify JWT token
export function verifyAccessToken(token: string): TokenPayload {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error("TOKEN_EXPIRED");
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error("INVALID_TOKEN");
    }
    throw new Error("TOKEN_ERROR");
  }
}

// Periodic cleanup function (should be called by a cron job)
export async function cleanupAllExpiredTokens(): Promise<void> {
  await cleanupExpiredTokens();
}
