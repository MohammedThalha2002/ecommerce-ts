import { Request, Response } from "express";
import {
  loginUser,
  registerUser,
  refreshAccessToken,
  logoutUser,
  logoutAllDevices,
  getCurrentUser,
  getUserSessions,
  revokeSession,
} from "./auth.service.js";

// Extract device info from request
function getDeviceInfo(req: Request) {
  return {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.get("User-Agent"),
    deviceId: req.get("X-Device-ID"), // Client can send this header for device tracking
  };
}

export async function register(req: Request, res: Response) {
  try {
    const { email, password, name } = req.body as {
      email: string;
      password: string;
      name?: string;
    };

    const deviceInfo = getDeviceInfo(req);
    const result = await registerUser({ email, password, name, deviceInfo });

    // Set refresh token as httpOnly cookie
    res.cookie("refreshToken", result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: "/api/auth/refresh", // Only send cookie to refresh endpoint
    });

    return res.status(201).json({
      message: "Registration successful",
      user: result.user,
      accessToken: result.accessToken,
      expiresIn: result.expiresIn,
    });
  } catch (err: any) {
    if (err?.message === "Email already in use") {
      return res.status(409).json({ message: err.message });
    }
    return res.status(500).json({ message: "Failed to register" });
  }
}

export async function login(req: Request, res: Response) {
  try {
    const { email, password } = req.body as {
      email: string;
      password: string;
    };

    const deviceInfo = getDeviceInfo(req);
    const result = await loginUser({ email, password, deviceInfo });

    // Set refresh token as httpOnly cookie
    res.cookie("refreshToken", result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: "/api/auth/refresh",
    });

    return res.status(200).json({
      message: "Login successful",
      user: result.user,
      accessToken: result.accessToken,
      expiresIn: result.expiresIn,
    });
  } catch (err: any) {
    if (err?.message === "Invalid email or password") {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    return res.status(500).json({ message: "Failed to login" });
  }
}

export async function refreshToken(req: Request, res: Response) {
  try {
    const oldRefreshToken = req.cookies.refreshToken;

    if (!oldRefreshToken) {
      return res.status(401).json({ message: "Refresh token not provided" });
    }

    const deviceInfo = getDeviceInfo(req);
    const result = await refreshAccessToken(oldRefreshToken, deviceInfo);

    // Set new refresh token as httpOnly cookie
    res.cookie("refreshToken", result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: "/api/auth/refresh",
    });

    return res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: result.accessToken,
      expiresIn: result.expiresIn,
    });
  } catch (err: any) {
    // Clear invalid refresh token
    res.clearCookie("refreshToken");
    return res
      .status(401)
      .json({ message: "Invalid or expired refresh token" });
  }
}

export async function logout(req: Request, res: Response) {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      await logoutUser(refreshToken);
    }

    // Clear the refresh token cookie
    res.clearCookie("refreshToken");

    return res.status(200).json({ message: "Logout successful" });
  } catch (err: any) {
    return res.status(500).json({ message: "Failed to logout" });
  }
}

export async function logoutAll(req: Request, res: Response) {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Revoke all refresh tokens for this user
    await logoutAllDevices(userId);

    // Clear the refresh token cookie
    res.clearCookie("refreshToken");

    return res.status(200).json({ message: "Logged out from all devices" });
  } catch (err: any) {
    return res
      .status(500)
      .json({ message: "Failed to logout from all devices" });
  }
}

export async function getProfile(req: Request, res: Response) {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await getCurrentUser(userId);

    return res.status(200).json({
      message: "Profile retrieved successfully",
      user,
    });
  } catch (err: any) {
    if (err?.message === "User not found") {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(500).json({ message: "Failed to get profile" });
  }
}

export async function getSessions(req: Request, res: Response) {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const sessions = await getUserSessions(userId);

    return res.status(200).json({
      message: "Sessions retrieved successfully",
      sessions,
    });
  } catch (err: any) {
    return res.status(500).json({ message: "Failed to get sessions" });
  }
}

export async function revokeSessionById(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    const { sessionId } = req.params;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    await revokeSession(userId, sessionId);

    return res.status(200).json({ message: "Session revoked successfully" });
  } catch (err: any) {
    return res.status(500).json({ message: "Failed to revoke session" });
  }
}
