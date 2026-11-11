import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { ldapService } from './ldap.service';
import { config } from './config';

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      status: 'INVALID_CREDENTIALS',
      message: 'Both username and password are required',
    });
  }

  try {
    const authResult = await ldapService.authenticate(username, password);

    if (authResult.status === 'SUCCESS') {
      return res.status(200).json(authResult);
    }

    if (authResult.status === 'MUST_CHANGE_PASSWORD') {
      return res.status(200).json(authResult);
    }

    if (
      authResult.status === 'ACCOUNT_LOCKED' ||
      authResult.status === 'ACCOUNT_EXPIRED' ||
      authResult.status === 'UNAUTHORIZED_GROUP'
    ) {
      return res.status(403).json(authResult);
    }

    return res.status(401).json(authResult);
  } catch (error: any) {
    return res.status(500).json({
      status: 'SERVICE_ERROR',
      message: error.message || 'Authentication service error',
    });
  }
};

export const changePassword = async (req: Request, res: Response) => {
  const { mustChangePasswordToken, newPassword } = req.body;

  if (!mustChangePasswordToken || !newPassword) {
    return res.status(400).json({
      success: false,
      message: 'Password change token and new password are required.',
    });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({
      success: false,
      message: 'New password does not meet complexity requirements (minimum 8 characters).',
    });
  }

  const result = await ldapService.changePassword(mustChangePasswordToken, newPassword);

  if (result.success) {
    return res.status(200).json(result);
  }
  return res.status(400).json(result);
};

export const verifyToken = async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ valid: false, error: 'Missing token' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    return res.status(200).json({ valid: true, payload: decoded });
  } catch (err: any) {
    return res.status(401).json({ valid: false, error: err.message });
  }
};

