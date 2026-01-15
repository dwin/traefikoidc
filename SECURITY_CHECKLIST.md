# Security Checklist for TraefikOIDC Plugin
## Deployment Security Guidelines

This checklist helps operators ensure secure deployment and configuration of the TraefikOIDC plugin.

---

## Pre-Deployment Security Checklist

### 1. Configuration Security

- [ ] **Session Encryption Key**
  - [ ] Minimum 32 bytes in length
  - [ ] Generated using cryptographically secure random source
  - [ ] Unique per deployment environment
  - [ ] Stored securely (Kubernetes secrets, environment variables, vault)
  - [ ] Never committed to version control

- [ ] **Client Credentials**
  - [ ] Client ID and Client Secret obtained from OIDC provider
  - [ ] Client Secret stored securely (not in plain text config files)
  - [ ] Use Kubernetes secrets: `urn:k8s:secret:namespace:secretname`
  - [ ] Rotate credentials periodically

- [ ] **HTTPS Enforcement**
  - [ ] `forceHTTPS: true` when TLS terminates at load balancer
  - [ ] Verify callback URLs use HTTPS scheme
  - [ ] No HTTP URLs in production

### 2. Network Security

- [ ] **URL Validation**
  - [ ] Provider URLs use HTTPS (not HTTP)
  - [ ] No access to internal/private networks unless required
  - [ ] Set `allowPrivateIPAddresses: false` in production
  - [ ] Verify excluded URLs are truly public

- [ ] **CORS Configuration**
  - [ ] CORS enabled only if cross-origin requests needed
  - [ ] Specific origins listed (avoid `*` wildcard)
  - [ ] `corsAllowCredentials` set appropriately
  - [ ] Review allowed methods and headers

### 3. Access Control

- [ ] **Domain Restrictions**
  - [ ] `allowedUserDomains` configured if restricting by domain
  - [ ] Email domain validation is case-insensitive
  - [ ] Test with various email formats

- [ ] **User Restrictions**
  - [ ] `allowedUsers` configured for specific user access
  - [ ] Email addresses are validated
  - [ ] Consider both domain and user restrictions

- [ ] **Role-Based Access Control**
  - [ ] `allowedRolesAndGroups` configured if using RBAC
  - [ ] Verify role/group claim names match OIDC provider
  - [ ] Test role validation with different users

### 4. Session Security

- [ ] **Cookie Configuration**
  - [ ] `cookieDomain` set correctly for multi-subdomain setups
  - [ ] `cookiePrefix` unique per middleware instance
  - [ ] Different encryption keys for different instances
  - [ ] Session timeout appropriate for use case

- [ ] **Session Isolation**
  - [ ] Multiple instances use different cookie prefixes
  - [ ] Different callback URLs per instance
  - [ ] No session sharing between instances

### 5. Rate Limiting

- [ ] **Request Throttling**
  - [ ] `rateLimit` configured appropriately (default: 100 req/s)
  - [ ] Consider application load patterns
  - [ ] Monitor for rate limit hits
  - [ ] Alert on suspicious activity

### 6. Logging & Monitoring

- [ ] **Log Level**
  - [ ] Production: `logLevel: info` or `error`
  - [ ] Development: `logLevel: debug` (acceptable)
  - [ ] Never log sensitive data (tokens, secrets)

- [ ] **Security Monitoring**
  - [ ] Monitor authentication failures
  - [ ] Monitor rate limit hits
  - [ ] Monitor suspicious patterns
  - [ ] Set up alerts for security events

---

## OIDC Provider Configuration Checklist

### 1. Provider Setup

- [ ] **Application Registration**
  - [ ] Application registered with OIDC provider
  - [ ] Redirect URIs configured correctly
  - [ ] Logout URIs configured if using logout
  - [ ] Application type set to "Web Application"

- [ ] **Scopes & Claims**
  - [ ] Required scopes configured: `openid`, `profile`, `email`
  - [ ] Additional scopes added as needed
  - [ ] Claims included in ID token (not just access token)
  - [ ] Verify claims with token inspection

### 2. Provider-Specific Settings

#### Google
- [ ] OAuth consent screen published (not in testing mode)
- [ ] Authorized redirect URIs include callback URL
- [ ] Refresh tokens enabled (automatically handled by plugin)

#### Azure AD
- [ ] Token configuration includes group claims if needed
- [ ] Optional claims configured for custom attributes
- [ ] Multi-tenant settings appropriate for deployment

#### Auth0
- [ ] Custom claims added via Actions/Rules to ID token
- [ ] Namespaced claims follow format: `https://domain/claim`
- [ ] Audience configured for custom APIs
- [ ] Allowed Logout URLs include post-logout redirect URI

#### Keycloak
- [ ] Client mappers configured for email, roles, groups
- [ ] "Add to ID token" enabled for all required mappers
- [ ] Token claim names match configuration

---

## Security Headers Checklist

### 1. Content Security Policy

- [ ] **CSP Configuration**
  - [ ] Profile selected: `default`, `strict`, `api`, `custom`
  - [ ] Custom CSP aligns with application needs
  - [ ] No `unsafe-inline` or `unsafe-eval` unless necessary
  - [ ] Review all source directives

### 2. Transport Security

- [ ] **HSTS Configuration**
  - [ ] `strictTransportSecurity: true` for HTTPS sites
  - [ ] `maxAge` appropriate (1 year = 31536000 seconds)
  - [ ] `includeSubDomains` set if applicable
  - [ ] Consider HSTS preload list

### 3. Additional Headers

- [ ] **Frame Protection**
  - [ ] `X-Frame-Options: DENY` or `SAMEORIGIN`
  - [ ] Prevents clickjacking attacks

- [ ] **Content Type**
  - [ ] `X-Content-Type-Options: nosniff`
  - [ ] Prevents MIME type sniffing

- [ ] **XSS Protection**
  - [ ] `X-XSS-Protection: 1; mode=block`
  - [ ] Browser-level XSS filtering

---

## Redis Cache Security Checklist (Optional)

### 1. Redis Configuration

- [ ] **Connection Security**
  - [ ] Redis password configured
  - [ ] TLS enabled if supported: `enableTLS: true`
  - [ ] Network isolation (private network)
  - [ ] Firewall rules restrict access

- [ ] **Cache Settings**
  - [ ] Key prefix set for namespace isolation
  - [ ] Appropriate TTL values
  - [ ] Monitor cache hit/miss rates
  - [ ] Plan for cache invalidation

### 2. High Availability

- [ ] **Redundancy**
  - [ ] Redis Sentinel for HA if needed
  - [ ] Redis Cluster for distributed deployments
  - [ ] Circuit breaker enabled: `enableCircuitBreaker: true`
  - [ ] Health checks enabled: `enableHealthCheck: true`

---

## Token Security Checklist

### 1. Token Validation

- [ ] **JWT Validation**
  - [ ] Signature algorithm validation (RS256, ES256, etc.)
  - [ ] Issuer validation matches provider
  - [ ] Audience validation matches client ID or custom audience
  - [ ] Expiration validation with clock skew tolerance
  - [ ] Replay protection enabled (default, unless multi-replica)

### 2. Token Refresh

- [ ] **Refresh Token Handling**
  - [ ] Refresh tokens obtained from provider
  - [ ] Grace period configured: `refreshGracePeriodSeconds`
  - [ ] Automatic refresh before expiration
  - [ ] Failed refresh triggers re-authentication

### 3. Token Introspection (Optional)

- [ ] **Opaque Tokens**
  - [ ] `allowOpaqueTokens: true` if provider uses opaque tokens
  - [ ] `requireTokenIntrospection: true` for validation
  - [ ] Introspection endpoint configured

---

## Multi-Replica Deployment Checklist

### 1. Replay Detection

- [ ] **JTI Cache**
  - [ ] Redis cache enabled for shared JTI tracking
  - [ ] OR `disableReplayDetection: true` if no Redis
  - [ ] Understand security trade-offs

### 2. Session Sharing

- [ ] **Distributed Sessions**
  - [ ] Redis cache enabled for session sharing
  - [ ] OR sticky sessions configured at load balancer
  - [ ] Test session persistence across replicas

### 3. Dynamic Client Registration

- [ ] **DCR Credentials**
  - [ ] Credentials file path accessible to all replicas
  - [ ] OR Redis storage for DCR credentials
  - [ ] Credential refresh mechanism tested

---

## Testing Checklist

### 1. Functional Testing

- [ ] **Authentication Flow**
  - [ ] Login successful with valid credentials
  - [ ] Login fails with invalid credentials
  - [ ] Callback URL redirects correctly
  - [ ] Post-authentication landing page works

- [ ] **Logout Flow**
  - [ ] Logout clears session
  - [ ] Redirect to post-logout URI
  - [ ] Re-authentication required after logout

### 2. Security Testing

- [ ] **Access Control**
  - [ ] Domain restrictions enforced
  - [ ] User restrictions enforced
  - [ ] Role/group restrictions enforced
  - [ ] Excluded URLs bypass authentication

- [ ] **Session Security**
  - [ ] Session cookies are HTTP-only
  - [ ] Session cookies are Secure (HTTPS)
  - [ ] Session timeout enforced
  - [ ] Multiple instances don't share sessions

### 3. Edge Cases

- [ ] **Error Handling**
  - [ ] CSRF token mismatch handled gracefully
  - [ ] Expired token triggers re-authentication
  - [ ] Invalid state parameter rejected
  - [ ] Network errors logged appropriately

- [ ] **Rate Limiting**
  - [ ] Rate limit enforced after threshold
  - [ ] IP blocking after failed attempts
  - [ ] Legitimate users not affected

---

## Monitoring Checklist

### 1. Metrics

- [ ] **Authentication Metrics**
  - [ ] Successful authentications tracked
  - [ ] Failed authentications tracked
  - [ ] Authentication latency monitored
  - [ ] Token refresh success/failure tracked

### 2. Security Events

- [ ] **Event Monitoring**
  - [ ] Authentication failures logged
  - [ ] Token validation failures logged
  - [ ] Rate limit hits logged
  - [ ] Suspicious activity logged

### 3. Alerting

- [ ] **Alert Configuration**
  - [ ] High failure rate alerts
  - [ ] Potential attack pattern alerts
  - [ ] Service degradation alerts
  - [ ] Configuration error alerts

---

## Incident Response Checklist

### 1. Preparation

- [ ] **Documentation**
  - [ ] Security incident response plan
  - [ ] Contact information for security team
  - [ ] Escalation procedures
  - [ ] Communication templates

### 2. Detection

- [ ] **Monitoring**
  - [ ] Real-time security event monitoring
  - [ ] Log aggregation and analysis
  - [ ] Anomaly detection
  - [ ] Alert routing

### 3. Response

- [ ] **Actions**
  - [ ] Procedure for blocking malicious IPs
  - [ ] Procedure for rotating credentials
  - [ ] Procedure for revoking sessions
  - [ ] Procedure for updating configuration

---

## Periodic Security Review Checklist

### Monthly

- [ ] Review authentication failure logs
- [ ] Review rate limit hits
- [ ] Review suspicious activity patterns
- [ ] Update allowlists/denylists as needed

### Quarterly

- [ ] Review and rotate credentials
- [ ] Review session timeout settings
- [ ] Review access control rules
- [ ] Update dependencies

### Annually

- [ ] Full security audit
- [ ] Penetration testing
- [ ] Compliance review
- [ ] Disaster recovery drill

---

## Compliance Checklist

### GDPR (if applicable)

- [ ] User consent mechanisms
- [ ] Data retention policies
- [ ] Right to erasure procedures
- [ ] Data processing agreements

### SOC 2 (if applicable)

- [ ] Access logging
- [ ] Audit trails
- [ ] Change management
- [ ] Incident response

### HIPAA (if applicable)

- [ ] Encryption at rest and in transit
- [ ] Access controls
- [ ] Audit logs
- [ ] Business associate agreements

---

## Documentation Checklist

- [ ] Configuration documented
- [ ] Security settings documented
- [ ] Runbook for operations team
- [ ] Incident response procedures
- [ ] Change management process
- [ ] Disaster recovery plan

---

**Last Updated**: January 15, 2026  
**Version**: 1.0  
**Review Frequency**: Quarterly
