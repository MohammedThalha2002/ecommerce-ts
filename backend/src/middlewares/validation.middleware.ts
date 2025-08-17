import { Request, Response, NextFunction } from "express";
import { validationResult, body } from "express-validator";

/**
 * Middleware to handle validation errors from express-validator
 * This should be used after validation rules in the route chain
 */
export function handleValidationErrors(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const extractedErrors: { [key: string]: string } = {};

    errors.array().forEach((err: any) => {
      if (err.type === "field") {
        extractedErrors[err.path] = err.msg;
      }
    });

    return res.status(400).json({
      message: "Validation failed",
      errors: extractedErrors,
    });
  }

  next();
}

// Validation rules for registration
export const validateRegister = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email address")
    .normalizeEmail(),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage(
      "Password must contain at least one lowercase letter, one uppercase letter, and one number"
    ),
  body("name")
    .optional()
    .isLength({ min: 2 })
    .withMessage("Name must be at least 2 characters long")
    .trim(),
];

// Validation rules for login
export const validateLogin = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email address")
    .normalizeEmail(),
  body("password").notEmpty().withMessage("Password is required"),
];
