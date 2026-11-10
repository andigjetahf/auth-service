import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: parseInt(process.env.AUTH_PORT || '4000', 10),
  nodeEnv: process.env.NODE_ENV || 'production',
  jwt: {
    secret: process.env.JWT_SHARED_SECRET || 'distributed-ctf-jwt-secret-shared-across-vms-2026!',
    expiry: process.env.JWT_EXPIRY || '8h',
  },
  ldap: {
    url: process.env.LDAP_URL || 'ldap://192.168.20.80:389',
    bindDn: process.env.LDAP_BIND_DN || 'cn=svc_ctf,ou=ServiceAccounts,dc=corp,dc=local',
    bindPassword: process.env.LDAP_BIND_PASSWORD || 'LdapServicePassword123!',
    baseDn: process.env.LDAP_BASE_DN || 'dc=corp,dc=local',
    adminGroupDn: process.env.LDAP_ADMIN_GROUP_DN || 'cn=CTF_Admins,ou=Groups,dc=corp,dc=local',
    userGroupDn: process.env.LDAP_USER_GROUP_DN || 'cn=CTF_Users,ou=Groups,dc=corp,dc=local',
  },
  devMockAuth: process.env.DEV_MOCK_AUTH === 'true',
  adminUsernames: (process.env.ADMIN_USERNAMES || 'admin')
    .toLowerCase()
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
};

