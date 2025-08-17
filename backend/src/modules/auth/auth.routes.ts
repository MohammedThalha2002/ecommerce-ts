import { Router } from "express";
import {
  login,
  register,
  refreshToken,
  logout,
  logoutAll,
  getProfile,
  getSessions,
  revokeSessionById,
} from "./auth.controller.js";
import {
  validateRegister,
  validateLogin,
  handleValidationErrors,
} from "../../middlewares/validation.middleware.js";
import { authMiddleware } from "../../middlewares/auth.middleware.js";

const router = Router();

// Public routes
router.post("/register", validateRegister, handleValidationErrors, register);
router.post("/login", validateLogin, handleValidationErrors, login);
router.post("/refresh", refreshToken);

// Protected routes (require authentication)
router.post("/logout", logout); // Can work with or without auth
router.post("/logout-all", authMiddleware, logoutAll);
router.get("/profile", authMiddleware, getProfile);

// Session management
router.get("/sessions", authMiddleware, getSessions);
router.delete("/sessions/:sessionId", authMiddleware, revokeSessionById);

export default router;
