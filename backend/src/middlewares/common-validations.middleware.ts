import { body, query, param } from "express-validator";

/**
 * Common validation rules that can be reused across different modules
 */

// Email validation rule
export const validateEmail = body("email")
  .isEmail()
  .withMessage("Please provide a valid email address")
  .normalizeEmail();

// Password validation rule
export const validatePassword = body("password")
  .isLength({ min: 6 })
  .withMessage("Password must be at least 6 characters long");

// Strong password validation rule
export const validateStrongPassword = body("password")
  .isLength({ min: 8 })
  .withMessage("Password must be at least 8 characters long")
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
  .withMessage(
    "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character"
  );

// Name validation rule
export const validateName = body("name")
  .isLength({ min: 2, max: 50 })
  .withMessage("Name must be between 2 and 50 characters")
  .matches(/^[a-zA-Z\s]+$/)
  .withMessage("Name can only contain letters and spaces")
  .trim();

// Optional name validation rule
export const validateOptionalName = body("name")
  .optional()
  .isLength({ min: 2, max: 50 })
  .withMessage("Name must be between 2 and 50 characters")
  .matches(/^[a-zA-Z\s]+$/)
  .withMessage("Name can only contain letters and spaces")
  .trim();

// ID parameter validation
export const validateId = param("id")
  .isInt({ min: 1 })
  .withMessage("ID must be a positive integer");

// Pagination validation
export const validatePagination = [
  query("page")
    .optional()
    .isInt({ min: 1 })
    .withMessage("Page must be a positive integer"),
  query("limit")
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage("Limit must be between 1 and 100"),
];

// Phone number validation
export const validatePhone = body("phone")
  .optional()
  .isMobilePhone("any", { strictMode: false })
  .withMessage("Please provide a valid phone number");

// URL validation
export const validateUrl = body("url")
  .isURL()
  .withMessage("Please provide a valid URL");

// Price validation (for e-commerce)
export const validatePrice = body("price")
  .isFloat({ min: 0 })
  .withMessage("Price must be a positive number");

// Quantity validation
export const validateQuantity = body("quantity")
  .isInt({ min: 1 })
  .withMessage("Quantity must be a positive integer");
