# Validation Middleware Guide

This project uses `express-validator` for input validation. Here's how to use the validation middlewares:

## Basic Usage

### 1. Import the required validators and error handler

```typescript
import {
  validateLogin,
  validateRegister,
  handleValidationErrors,
} from "../../middlewares/validation.middleware.js";
```

### 2. Apply them to your routes

```typescript
// Order matters: validation rules first, then error handler, then controller
router.post("/register", validateRegister, handleValidationErrors, register);
router.post("/login", validateLogin, handleValidationErrors, login);
```

## Available Validation Rules

### Auth Validations (`validation.middleware.ts`)

- **`validateRegister`**: Validates email, password (strong), and optional name
- **`validateLogin`**: Validates email and password (basic)

### Common Validations (`common-validations.middleware.ts`)

- **`validateEmail`**: Email format validation
- **`validatePassword`**: Basic password (min 6 chars)
- **`validateStrongPassword`**: Strong password with special requirements
- **`validateName`**: Name validation (2-50 chars, letters/spaces only)
- **`validateOptionalName`**: Optional name validation
- **`validateId`**: ID parameter validation (positive integer)
- **`validatePagination`**: Page and limit query validation
- **`validatePhone`**: Phone number validation
- **`validateUrl`**: URL validation
- **`validatePrice`**: Price validation for e-commerce
- **`validateQuantity`**: Quantity validation

## Creating Custom Validation Rules

```typescript
// In your middleware file
const { body, param, query } = require("express-validator");

export const validateCustomField = [
  body("customField")
    .isLength({ min: 3, max: 20 })
    .withMessage("Custom field must be between 3 and 20 characters")
    .matches(/^[a-zA-Z0-9]+$/)
    .withMessage("Custom field can only contain letters and numbers"),
];
```

## Using in Routes

```typescript
import { Router } from "express";
import {
  validateCustomField,
  handleValidationErrors,
} from "../middlewares/validation.middleware.js";
import { controller } from "./controller.js";

const router = Router();

router.post(
  "/endpoint",
  validateCustomField,
  handleValidationErrors,
  controller
);
```

## Error Response Format

When validation fails, the middleware returns:

```json
{
  "message": "Validation failed",
  "errors": {
    "email": "Please provide a valid email address",
    "password": "Password must be at least 6 characters long"
  }
}
```

## Best Practices

1. **Always use `handleValidationErrors`** after your validation rules
2. **Order matters**: validation rules → `handleValidationErrors` → controller
3. **Reuse common validators** from `common-validations.middleware.ts`
4. **Create specific validators** for complex business logic
5. **Use meaningful error messages** that help users understand what's wrong

## Example: Product Validation

```typescript
// In products/validation.middleware.ts
const { body } = require("express-validator");

export const validateProduct = [
  body("name")
    .isLength({ min: 2, max: 100 })
    .withMessage("Product name must be between 2 and 100 characters"),
  body("description")
    .isLength({ min: 10, max: 1000 })
    .withMessage("Description must be between 10 and 1000 characters"),
  body("price")
    .isFloat({ min: 0 })
    .withMessage("Price must be a positive number"),
  body("category")
    .isIn(["electronics", "clothing", "books", "home"])
    .withMessage("Category must be one of: electronics, clothing, books, home"),
];

// In products/routes.ts
router.post(
  "/products",
  validateProduct,
  handleValidationErrors,
  createProduct
);
```
