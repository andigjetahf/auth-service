import express from 'express';
import cors from 'cors';
import { config } from './config';
import { login, changePassword, verifyToken } from './auth.controller';

const app = express();

app.use(cors());
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({
    service: 'auth-service',
    role: 'VM 1: AD LDAP Proxy',
    status: 'healthy',
    timestamp: new Date().toISOString(),
  });
});

// Authentication endpoints
app.post('/api/auth/login', login);
app.post('/api/auth/change-password', changePassword);
app.get('/api/auth/verify', verifyToken);

app.listen(config.port, () => {
  console.log(`====================================================`);
  console.log(` [VM 1] AD Proxy Auth Service running on port ${config.port}`);
  console.log(` Active Directory DC: ${config.ldap.url}`);
  console.log(` Dev Mock Auth Active: ${config.devMockAuth}`);
  console.log(`====================================================`);
});

