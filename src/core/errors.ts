export type AIDErrorCode =
  | 'DISCOVERY_ERROR'
  | 'CALLBACK_ERROR'
  | 'TOKEN_ERROR'
  | 'AUTHENTICATION_ERROR'
  | 'CONFIGURATION_ERROR'
  | 'STORAGE_ERROR';

export class AIDError extends Error {
  readonly code: AIDErrorCode;
  override readonly cause?: unknown;

  constructor(code: AIDErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'AIDError';
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

export class AIDDiscoveryError extends AIDError {
  constructor(message: string, cause?: unknown) {
    super('DISCOVERY_ERROR', message, cause);
    this.name = 'AIDDiscoveryError';
  }
}

export class AIDCallbackError extends AIDError {
  constructor(message: string, cause?: unknown) {
    super('CALLBACK_ERROR', message, cause);
    this.name = 'AIDCallbackError';
  }
}

export class AIDTokenError extends AIDError {
  readonly error?: string;

  constructor(
    message: string,
    cause?: unknown,
    error?: string,
  ) {
    super('TOKEN_ERROR', message, cause);
    this.name = 'AIDTokenError';
    this.error = error;
  }
}

export class AIDAuthenticationError extends AIDError {
  constructor(message: string, cause?: unknown) {
    super('AUTHENTICATION_ERROR', message, cause);
    this.name = 'AIDAuthenticationError';
  }
}