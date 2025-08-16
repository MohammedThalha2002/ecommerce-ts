import { Request, Response } from "express";
import { loginUser, registerUser } from "./auth.service.js";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function register(req: Request, res: Response) {
  try {
    const { email, password, name } = req.body as {
      email?: string;
      password?: string;
      name?: string;
    };

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const result = await registerUser({ email, password, name });
    return res.status(201).json(result);
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
      email?: string;
      password?: string;
    };

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const result = await loginUser({ email, password });
    return res.status(200).json(result);
  } catch (err: any) {
    if (err?.message === "Invalid email or password") {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    return res.status(500).json({ message: "Failed to login" });
  }
}
