export class ControlPlaneError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.name = 'ControlPlaneError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

export function invalidRequest(message: string): ControlPlaneError {
  return new ControlPlaneError(400, 'INVALID_REQUEST', message);
}

export function unauthorized(message = 'Authentication required'): ControlPlaneError {
  return new ControlPlaneError(401, 'UNAUTHORIZED', message);
}

export function forbidden(message = 'Permission denied'): ControlPlaneError {
  return new ControlPlaneError(403, 'FORBIDDEN', message);
}

export function notFound(message: string): ControlPlaneError {
  return new ControlPlaneError(404, 'NOT_FOUND', message);
}

export function conflict(message: string): ControlPlaneError {
  return new ControlPlaneError(409, 'CONFLICT', message);
}

export function creditRequired(message = 'Insufficient credits'): ControlPlaneError {
  return new ControlPlaneError(402, 'CREDIT_REQUIRED', message);
}

export function creditHoldUnavailable(message = 'Credit hold is unavailable'): ControlPlaneError {
  return new ControlPlaneError(409, 'CREDIT_HOLD_UNAVAILABLE', message);
}

export function rateLimited(message: string): ControlPlaneError {
  return new ControlPlaneError(429, 'RATE_LIMITED', message);
}

export function capacityExceeded(message: string): ControlPlaneError {
  return new ControlPlaneError(429, 'CAPACITY_EXCEEDED', message);
}

export function approvalRequired(message: string): ControlPlaneError {
  return new ControlPlaneError(428, 'APPROVAL_REQUIRED', message);
}
