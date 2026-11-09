export type AuthStatus = 
  | 'SUCCESS'
  | 'MUST_CHANGE_PASSWORD'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_EXPIRED'
  | 'INVALID_CREDENTIALS'
  | 'SERVICE_ERROR';

export type UserRole = 'ADMIN' | 'USER';

export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  displayName: string;
  role: UserRole;
  ldapDn: string;
}

export interface AuthResponse {
  status: AuthStatus;
  message: string;
  token?: string;
  user?: AuthenticatedUser;
  mustChangePasswordToken?: string;
  errorCode?: string;
}

