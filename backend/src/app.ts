import express, { Request, Response } from "express";
import dotenv from "dotenv";
import authRoutes from "./modules/auth/auth.routes.js";

dotenv.config();

const app = express();

// Middlewares
app.use(express.json());

// Health check endpoint
app.get("/health", (req: Request, res: Response) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Routes
app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.status(200).json({ message: "Hello World" });
});

export default app;
