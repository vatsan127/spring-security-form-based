# Form-Based Login in Spring Security

## Overview

Form-based login is the most common authentication method for web applications. Users enter credentials (username/password) in an HTML form, which is submitted to the server for validation.

---

## How Form-Based Login Works

### Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│ 1. User accesses protected resource (/dashboard)             │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. Spring Security detects unauthenticated request           │
│    → Redirects to login page (/login)                        │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ 3. User sees login form                                      │
│    → Enters username and password                            │
│    → Submits form (POST /login)                              │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. UsernamePasswordAuthenticationFilter intercepts           │
│    → Extracts username and password                          │
│    → Creates UsernamePasswordAuthenticationToken             │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ 5. AuthenticationManager authenticates                       │
│    → UserDetailsService loads user                           │
│    → PasswordEncoder verifies password                       │
└────────────────────────┬─────────────────────────────────────┘
                         │
                    ┌────┴────┐
                    │         │
              Success       Failure
                    │         │
                    ▼         ▼
┌──────────────────────┐  ┌──────────────────────────────┐
│ 6a. Authentication   │  │ 6b. Authentication fails     │
│     successful       │  │     → Redirect to            │
│     → Create session │  │       /login?error           │
│     → Redirect to    │  └──────────────────────────────┘
│       /dashboard     │
└──────────────────────┘
```

---

## Basic Configuration

### 1. Minimal Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults()); // Uses default login page
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

This provides:
- Default login page at `/login`
- Default logout at `/logout`
- Username parameter: `username`
- Password parameter: `password`

### 2. Custom Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/home", "/register", "/css/**", "/js/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")                    // Custom login page URL
                .loginProcessingUrl("/perform_login")   // URL to submit credentials
                .defaultSuccessUrl("/dashboard", true)  // Redirect after successful login
                .failureUrl("/login?error=true")        // Redirect after failed login
                .usernameParameter("email")             // Custom username parameter
                .passwordParameter("pass")              // Custom password parameter
                .permitAll()                            // Allow everyone to access login page
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            );
        
        return http.build();
    }
}
```

---

## Custom Login Page

### HTML Form (login.html)

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="/css/login.css">
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        
        <!-- Error message -->
        <div th:if="${param.error}" class="alert alert-danger">
            Invalid username or password.
        </div>
        
        <!-- Logout message -->
        <div th:if="${param.logout}" class="alert alert-success">
            You have been logged out successfully.
        </div>
        
        <!-- Login form -->
        <form th:action="@{/perform_login}" method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" 
                       id="username" 
                       name="username" 
                       required 
                       autofocus>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" 
                       id="password" 
                       name="password" 
                       required>
            </div>
            
            <div class="form-group">
                <label>
                    <input type="checkbox" name="remember-me"> Remember Me
                </label>
            </div>
            
            <!-- CSRF token (automatically added by Thymeleaf) -->
            <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>
            
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        
        <div class="register-link">
            <p>Don't have an account? <a th:href="@{/register}">Register here</a></p>
        </div>
    </div>
</body>
</html>
```

### Controller

```java
@Controller
public class LoginController {
    
    @GetMapping("/login")
    public String login() {
        return "login";
    }
    
    @GetMapping("/")
    public String home() {
        return "home";
    }
    
    @GetMapping("/dashboard")
    public String dashboard(Model model, Authentication authentication) {
        model.addAttribute("username", authentication.getName());
        return "dashboard";
    }
}
```

---

## UserDetailsService Implementation

### Entity Classes

```java
@Entity
@Table(name = "users")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(nullable = false)
    private String password;
    
    @Column(nullable = false)
    private boolean enabled = true;
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
    
    // Getters and setters
}

@Entity
@Table(name = "roles")
public class Role {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String name; // ROLE_USER, ROLE_ADMIN
    
    // Getters and setters
}
```

### Repository

```java
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
```

### UserDetailsService

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) 
            throws UsernameNotFoundException {
        
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(
                "User not found: " + username));
        
        return org.springframework.security.core.userdetails.User
            .withUsername(user.getUsername())
            .password(user.getPassword())
            .authorities(getAuthorities(user.getRoles()))
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(!user.isEnabled())
            .build();
    }
    
    private Collection<? extends GrantedAuthority> getAuthorities(Set<Role> roles) {
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toList());
    }
}
```

---

## Advanced Features

### 1. Remember Me

```java
http.rememberMe(remember -> remember
    .key("uniqueAndSecret")
    .tokenValiditySeconds(86400) // 24 hours
    .rememberMeParameter("remember-me")
    .rememberMeCookieName("my-remember-me")
);
```

**HTML:**
```html
<input type="checkbox" name="remember-me"> Remember Me
```

### 2. Custom Authentication Success Handler

```java
@Component
public class CustomAuthenticationSuccessHandler 
        implements AuthenticationSuccessHandler {
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) 
            throws IOException, ServletException {
        
        // Log successful login
        String username = authentication.getName();
        logger.info("User {} logged in successfully", username);
        
        // Redirect based on role
        Set<String> roles = AuthorityUtils.authorityListToSet(
            authentication.getAuthorities());
        
        if (roles.contains("ROLE_ADMIN")) {
            response.sendRedirect("/admin/dashboard");
        } else {
            response.sendRedirect("/user/dashboard");
        }
    }
}

// Configuration
http.formLogin(form -> form
    .successHandler(customAuthenticationSuccessHandler)
);
```

### 3. Custom Authentication Failure Handler

```java
@Component
public class CustomAuthenticationFailureHandler 
        implements AuthenticationFailureHandler {
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) 
            throws IOException, ServletException {
        
        String errorMessage;
        
        if (exception instanceof BadCredentialsException) {
            errorMessage = "Invalid username or password";
        } else if (exception instanceof DisabledException) {
            errorMessage = "Account is disabled";
        } else if (exception instanceof LockedException) {
            errorMessage = "Account is locked";
        } else {
            errorMessage = "Authentication failed";
        }
        
        request.getSession().setAttribute("errorMessage", errorMessage);
        response.sendRedirect("/login?error=true");
    }
}

// Configuration
http.formLogin(form -> form
    .failureHandler(customAuthenticationFailureHandler)
);
```

### 4. Account Lockout (Brute Force Protection)

```java
@Service
public class LoginAttemptService {
    
    private static final int MAX_ATTEMPTS = 3;
    private Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();
    
    public void loginSucceeded(String username) {
        attemptsCache.remove(username);
    }
    
    public void loginFailed(String username) {
        int attempts = attemptsCache.getOrDefault(username, 0);
        attemptsCache.put(username, attempts + 1);
    }
    
    public boolean isBlocked(String username) {
        return attemptsCache.getOrDefault(username, 0) >= MAX_ATTEMPTS;
    }
}

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private LoginAttemptService loginAttemptService;
    
    @Override
    public Authentication authenticate(Authentication authentication) 
            throws AuthenticationException {
        
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        
        // Check if account is locked
        if (loginAttemptService.isBlocked(username)) {
            throw new LockedException("Account is locked due to too many failed attempts");
        }
        
        UserDetails user = userDetailsService.loadUserByUsername(username);
        
        if (passwordEncoder.matches(password, user.getPassword())) {
            loginAttemptService.loginSucceeded(username);
            return new UsernamePasswordAuthenticationToken(
                user, password, user.getAuthorities());
        } else {
            loginAttemptService.loginFailed(username);
            throw new BadCredentialsException("Invalid credentials");
        }
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

### 5. Session Management

```java
http.sessionManagement(session -> session
    // Session creation policy
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    
    // Maximum sessions per user
    .maximumSessions(1)
    .maxSessionsPreventsLogin(true) // Prevent new login if max reached
    .expiredUrl("/login?expired")
    
    // Session fixation protection
    .sessionFixation().migrateSession()
    
    // Invalid session URL
    .invalidSessionUrl("/login?invalid")
);
```

---

## Complete Example

### Project Structure
```
src/main/java/com/example/security/
├── config/
│   └── SecurityConfig.java
├── controller/
│   ├── LoginController.java
│   └── DashboardController.java
├── entity/
│   ├── User.java
│   └── Role.java
├── repository/
│   └── UserRepository.java
├── service/
│   └── CustomUserDetailsService.java
└── handler/
    ├── CustomAuthenticationSuccessHandler.java
    └── CustomAuthenticationFailureHandler.java

src/main/resources/
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   └── home.html
└── static/
    └── css/
        └── login.css
```

### Complete SecurityConfig.java

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Autowired
    private CustomUserDetailsService userDetailsService;
    
    @Autowired
    private CustomAuthenticationSuccessHandler successHandler;
    
    @Autowired
    private CustomAuthenticationFailureHandler failureHandler;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/home", "/register", "/css/**", "/js/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/perform_login")
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .rememberMe(remember -> remember
                .key("uniqueAndSecret")
                .tokenValiditySeconds(86400)
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true)
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            );
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
```

---

## Testing

### Test User Setup

```java
@Component
public class DataInitializer implements CommandLineRunner {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() == 0) {
            // Create roles
            Role userRole = new Role();
            userRole.setName("ROLE_USER");
            roleRepository.save(userRole);
            
            Role adminRole = new Role();
            adminRole.setName("ROLE_ADMIN");
            roleRepository.save(adminRole);
            
            // Create users
            User user = new User();
            user.setUsername("user");
            user.setPassword(passwordEncoder.encode("password"));
            user.setEnabled(true);
            user.setRoles(Set.of(userRole));
            userRepository.save(user);
            
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin"));
            admin.setEnabled(true);
            admin.setRoles(Set.of(adminRole, userRole));
            userRepository.save(admin);
        }
    }
}
```

---

## Best Practices

1. **Always use HTTPS** in production
2. **Hash passwords** with BCrypt or Argon2
3. **Implement CSRF protection** (enabled by default)
4. **Use strong session management**
5. **Implement account lockout** for brute force protection
6. **Log authentication events** for security auditing
7. **Validate input** on both client and server side
8. **Use parameterized queries** to prevent SQL injection
9. **Implement password policies** (complexity, expiration)
10. **Enable Remember Me** with secure token

---

## Common Issues and Solutions

### Issue 1: CSRF Token Missing
**Solution:** Ensure CSRF token is included in form
```html
<input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>
```

### Issue 2: Circular Redirect to Login Page
**Solution:** Ensure login page is permitted for all
```java
.formLogin(form -> form.loginPage("/login").permitAll())
```

### Issue 3: Password Not Matching
**Solution:** Ensure password is encoded when saving
```java
user.setPassword(passwordEncoder.encode(rawPassword));
```

---

## Summary

Form-based login in Spring Security provides:
- ✅ Secure authentication mechanism
- ✅ Customizable login pages
- ✅ Session management
- ✅ Remember me functionality
- ✅ CSRF protection
- ✅ Account lockout capabilities
- ✅ Role-based access control

Next steps: Implementation of a complete form-based login application!
