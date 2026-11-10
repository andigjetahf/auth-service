import ldap from 'ldapjs';
import jwt from 'jsonwebtoken';
import { config } from './config';
import { AuthResponse, AuthenticatedUser } from './types';

export class LdapService {
  private createClient(): ldap.Client {
    return ldap.createClient({
      url: config.ldap.url,
      timeout: 5000,
      connectTimeout: 5000,
    });
  }

  /**
   * Authenticates user against Active Directory, checks roles & "Must Change Password" flags
   */
  public async authenticate(username: string, password: string): Promise<AuthResponse> {
    if (config.devMockAuth) {
      return this.mockAuthenticate(username, password);
    }

    const adminClient = this.createClient();

    try {
      // 1. Service Account Bind to search for user object
      await new Promise<void>((resolve, reject) => {
        adminClient.bind(config.ldap.bindDn, config.ldap.bindPassword, (err) => {
          if (err) return reject(new Error(`AD Service Account Bind Failed: ${err.message}`));
          resolve();
        });
      });

      // 2. Search for user by sAMAccountName or userPrincipalName
      const sanitizedUser = this.sanitizeLdapFilter(username);
      const searchFilter = `(|(sAMAccountName=${sanitizedUser})(userPrincipalName=${sanitizedUser})(mail=${sanitizedUser}))`;
      const searchOptions: ldap.SearchOptions = {
        filter: searchFilter,
        scope: 'sub',
        attributes: [
          'dn',
          'sAMAccountName',
          'mail',
          'displayName',
          'cn',
          'memberOf',
          'pwdLastSet',
          'userAccountControl',
        ],
      };

      const userEntry = await new Promise<any>((resolve, reject) => {
        adminClient.search(config.ldap.baseDn, searchOptions, (err, res) => {
          if (err) return reject(err);

          let entry: any = null;
          res.on('searchEntry', (item: any) => {
            entry = item.pojo;
          });
          res.on('error', (searchErr: any) => reject(searchErr));
          res.on('end', (result: any) => {
            if (result && result.status !== 0) {
              return reject(new Error(`LDAP search returned status ${result.status}`));
            }
            if (!entry) {
              return reject(new Error('USER_NOT_FOUND'));
            }
            resolve(entry);
          });
        });
      });

      adminClient.unbind(() => {});

      const userDn = userEntry.objectName;
      const attributes = userEntry.attributes.reduce((acc: any, attr: any) => {
        acc[attr.type] = attr.values.length === 1 ? attr.values[0] : attr.values;
        return acc;
      }, {});

      // 3. Proactive check: pwdLastSet === '0' indicates "Must change password at next logon" in AD
      if (attributes.pwdLastSet === '0') {
        const mustChangeToken = jwt.sign(
          { username: attributes.sAMAccountName || username, dn: userDn, action: 'MUST_CHANGE_PASSWORD' },
          config.jwt.secret,
          { expiresIn: '15m' as any }
        );

        return {
          status: 'MUST_CHANGE_PASSWORD',
          message: 'Active Directory policy requires you to change your password before logging in.',
          mustChangePasswordToken: mustChangeToken,
          errorCode: 'DATA_773_PRECHECK',
        };
      }

      // 4. Attempt user bind to verify password
      const userClient = this.createClient();
      const bindError = await new Promise<any>((resolve) => {
        userClient.bind(userDn, password, (err) => {
          if (err) return resolve(err);
          resolve(null);
        });
      });

      userClient.unbind(() => {});

      if (bindError) {
        return this.parseActiveDirectoryError(bindError, attributes.sAMAccountName || username, userDn);
      }

      // 5. User bind succeeded: parse Active Directory Security Groups (RBAC)
      const memberOfList: string[] = Array.isArray(attributes.memberOf)
        ? attributes.memberOf
        : attributes.memberOf ? [attributes.memberOf] : [];

      const normalizeDn = (dn: string) => dn.toLowerCase().replace(/\s*,\s*/g, ',').trim();
      const targetAdminDn = normalizeDn(config.ldap.adminGroupDn);
      const targetAdminCnMatch = targetAdminDn.match(/^(cn=[^,]+)/);
      const targetAdminCn = targetAdminCnMatch ? targetAdminCnMatch[1] : '';

      const isAdminByGroup = memberOfList.some((groupDn: string) => {
        const normalized = normalizeDn(groupDn);
        return (
          normalized === targetAdminDn ||
          normalized.includes(targetAdminDn) ||
          (targetAdminCn && (normalized === targetAdminCn || normalized.startsWith(targetAdminCn + ',')))
        );
      });

      const isAdminByUsername = config.adminUsernames.includes(username.toLowerCase());
      const isAdmin = isAdminByGroup || isAdminByUsername;

      console.log(`[LDAP] User '${username}' groups:`, memberOfList);
      console.log(`[LDAP] User '${username}' resolved isAdmin: ${isAdmin} (byGroup: ${isAdminByGroup}, byUsername: ${isAdminByUsername})`);

      const authenticatedUser: AuthenticatedUser = {
        id: attributes.sAMAccountName || username,
        username: attributes.sAMAccountName || username,
        email: attributes.mail || `${username}@corp.local`,
        displayName: attributes.displayName || attributes.cn || username,
        role: isAdmin ? 'ADMIN' : 'USER',
        ldapDn: userDn,
      };

      // Sign JWT with distributed shared secret for VM 2 (Frontend) and VM 3 (Core Backend)
      const token = jwt.sign(
        {
          id: authenticatedUser.id,
          username: authenticatedUser.username,
          email: authenticatedUser.email,
          displayName: attributes.displayName || attributes.cn || username,
          role: isAdmin ? 'ADMIN' : 'USER',
        },
        config.jwt.secret,
        {
          expiresIn: config.jwt.expiry as any,
          issuer: 'ctf-auth-vm1',
        }
      );

      return {
        status: 'SUCCESS',
        message: 'Active Directory authentication successful',
        token,
        user: authenticatedUser,
      };
    } catch (err: any) {
      try { adminClient.unbind(() => {}); } catch (_) {}

      if (err.message === 'USER_NOT_FOUND') {
        return {
          status: 'INVALID_CREDENTIALS',
          message: 'User does not exist in Active Directory',
        };
      }

      return {
        status: 'SERVICE_ERROR',
        message: `LDAP Service Failure: ${err.message}`,
      };
    }
  }

  /**
   * Parses Microsoft Active Directory Win32 data error codes embedded in LDAP error messages
   * Reference: 80090308: LdapErr: DSID-..., comment: AcceptSecurityContext error, data <HEX/DEC>, ...
   */
  private parseActiveDirectoryError(error: any, username: string, userDn: string): AuthResponse {
    const errorMsg = error.message || error.toString();

    // Data 773: User must reset password before logging in
    if (errorMsg.includes('data 773') || errorMsg.includes('data 305')) {
      const mustChangeToken = jwt.sign(
        { username, dn: userDn, action: 'MUST_CHANGE_PASSWORD' },
        config.jwt.secret,
        { expiresIn: '15m' as any }
      );

      return {
        status: 'MUST_CHANGE_PASSWORD',
        message: 'Active Directory: Password has expired or must be changed at next logon.',
        mustChangePasswordToken: mustChangeToken,
        errorCode: 'ERROR_PASSWORD_MUST_CHANGE_773',
      };
    }

    // Data 532: Password expired
    if (errorMsg.includes('data 532')) {
      const mustChangeToken = jwt.sign(
        { username, dn: userDn, action: 'MUST_CHANGE_PASSWORD' },
        config.jwt.secret,
        { expiresIn: '15m' as any }
      );

      return {
        status: 'MUST_CHANGE_PASSWORD',
        message: 'Active Directory: Password has expired and must be updated.',
        mustChangePasswordToken: mustChangeToken,
        errorCode: 'ERROR_PASSWORD_EXPIRED_532',
      };
    }

    // Data 533: Account disabled
    if (errorMsg.includes('data 533')) {
      return {
        status: 'ACCOUNT_LOCKED',
        message: 'Active Directory: Your account is disabled. Contact your instructor.',
        errorCode: 'ERROR_ACCOUNT_DISABLED_533',
      };
    }

    // Data 701: Account expired
    if (errorMsg.includes('data 701')) {
      return {
        status: 'ACCOUNT_EXPIRED',
        message: 'Active Directory: Your student account has expired.',
        errorCode: 'ERROR_ACCOUNT_EXPIRED_701',
      };
    }

    // Data 775: Account locked out
    if (errorMsg.includes('data 775')) {
      return {
        status: 'ACCOUNT_LOCKED',
        message: 'Active Directory: Account is locked due to too many failed attempts.',
        errorCode: 'ERROR_ACCOUNT_LOCKED_OUT_775',
      };
    }

    // Data 52e or default: Invalid credentials
    return {
      status: 'INVALID_CREDENTIALS',
      message: 'Invalid username or password',
      errorCode: 'ERROR_LOGON_FAILURE_52E',
    };
  }

  /**
   * Changes the user's Active Directory password via LDAP unicodePwd attribute
   */
  public async changePassword(
    mustChangePasswordToken: string,
    newPassword: string
  ): Promise<{ success: boolean; message: string }> {
    if (config.devMockAuth) {
      return { success: true, message: 'Password updated successfully in development mock mode.' };
    }

    try {
      const decoded = jwt.verify(mustChangePasswordToken, config.jwt.secret) as any;
      if (decoded.action !== 'MUST_CHANGE_PASSWORD') {
        throw new Error('Invalid password change token');
      }

      const adminClient = this.createClient();
      await new Promise<void>((resolve, reject) => {
        adminClient.bind(config.ldap.bindDn, config.ldap.bindPassword, (err) => {
          if (err) return reject(err);
          resolve();
        });
      });

      // Active Directory requires password encoded in UTF-16LE wrapped in quotation marks
      const encodedPassword = Buffer.from(`"${newPassword}"`, 'utf16le');

      const change = new ldap.Change({
        operation: 'replace',
        modification: {
          unicodePwd: encodedPassword,
          pwdLastSet: '-1', // Clears "must change password at next logon" flag
        },
      });

      await new Promise<void>((resolve, reject) => {
        adminClient.modify(decoded.dn, change, (err) => {
          if (err) return reject(err);
          resolve();
        });
      });

      adminClient.unbind(() => {});
      return { success: true, message: 'Active Directory password changed successfully. You may now log in.' };
    } catch (err: any) {
      return { success: false, message: `Failed to change AD password: ${err.message}` };
    }
  }

  private sanitizeLdapFilter(input: string): string {
    return input.replace(/([\\*()\\0])/g, '\\$1');
  }

  /**
   * Dev mock for testing without live Active Directory server
   */
  private mockAuthenticate(username: string, password: string): AuthResponse {
    const user = username.toLowerCase();

    // Trigger MUST_CHANGE_PASSWORD for student_expired or when password is 'expired'
    if (user.includes('expired') || password === 'expired') {
      const mustChangeToken = jwt.sign(
        { username, dn: `cn=${username},ou=Users,${config.ldap.baseDn}`, action: 'MUST_CHANGE_PASSWORD' },
        config.jwt.secret,
        { expiresIn: '15m' as any }
      );

      return {
        status: 'MUST_CHANGE_PASSWORD',
        message: 'Active Directory policy requires you to change your password before continuing.',
        mustChangePasswordToken: mustChangeToken,
        errorCode: 'ERROR_PASSWORD_MUST_CHANGE_773',
      };
    }

    if (password === 'locked') {
      return {
        status: 'ACCOUNT_LOCKED',
        message: 'Active Directory: Account is locked out due to invalid logon attempts.',
        errorCode: 'ERROR_ACCOUNT_LOCKED_OUT_775',
      };
    }

    if (password === 'wrong') {
      return {
        status: 'INVALID_CREDENTIALS',
        message: 'Invalid username or password',
        errorCode: 'ERROR_LOGON_FAILURE_52E',
      };
    }

    const isAdmin =
      user.includes('admin') || config.adminUsernames.includes(user);
    const authenticatedUser: AuthenticatedUser = {
      id: username,
      username,
      email: `${username}@corp.local`,
      displayName: isAdmin ? 'Instructor / CTF Administrator' : `Student (${username})`,
      role: isAdmin ? 'ADMIN' : 'USER',
      ldapDn: `cn=${username},ou=Users,${config.ldap.baseDn}`,
    };

    const token = jwt.sign(
      {
        id: authenticatedUser.id,
        username: authenticatedUser.username,
        email: authenticatedUser.email,
        displayName: authenticatedUser.displayName,
        role: authenticatedUser.role,
      },
      config.jwt.secret,
      {
        expiresIn: config.jwt.expiry as any,
        issuer: 'ctf-auth-vm1',
      }
    );

    return {
      status: 'SUCCESS',
      message: 'Active Directory authentication successful (Dev Mock)',
      token,
      user: authenticatedUser,
    };
  }
}

export const ldapService = new LdapService();

