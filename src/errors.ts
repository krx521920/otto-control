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

export function notFound(message: string): ControlPlaneError {
  return new ControlPlaneError(404, 'NOT_FOUND', message);
}

export function conflict(message: string): ControlPlaneError {
  return new ControlPlaneError(409, 'CONFLICT', message);
}
