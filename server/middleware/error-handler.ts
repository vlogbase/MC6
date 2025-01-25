import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { DrizzleError } from 'drizzle-orm';

// Custom error class for API errors
export class APIError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public details?: any
  ) {
    super(message);
    this.name = 'APIError';
  }
}

// Format error response based on environment
function formatError(err: Error, includeStack = false) {
  const baseError = {
    message: err.message,
    type: err.name
  };

  if (includeStack && err.stack) {
    return { ...baseError, stack: err.stack };
  }

  return baseError;
}

// Main error handling middleware
export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  // Log the error
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  const isDev = process.env.NODE_ENV !== 'production';

  // Handle different types of errors
  if (err instanceof APIError) {
    return res.status(err.statusCode).json({
      error: formatError(err, isDev),
      details: err.details
    });
  }

  if (err instanceof ZodError) {
    return res.status(400).json({
      error: {
        message: 'Validation Error',
        type: 'ValidationError',
        details: err.errors
      }
    });
  }

  if (err instanceof DrizzleError) {
    return res.status(500).json({
      error: {
        message: 'Database Error',
        type: 'DatabaseError',
        details: isDev ? err.message : undefined
      }
    });
  }

  // Default error response
  const statusCode = err instanceof Error ? 500 : 400;
  res.status(statusCode).json({
    error: formatError(err, isDev)
  });
}

// Catch-all for unhandled errors
export function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Not found handler
export function notFoundHandler(req: Request, res: Response) {
  res.status(404).json({
    error: {
      message: `Cannot ${req.method} ${req.path}`,
      type: 'NotFoundError'
    }
  });
}
