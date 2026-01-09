# Spring Security Architecture

## Overview

Spring Security is a powerful framework that provides authentication, authorization, and protection against common attacks. Understanding its architecture is crucial for effective implementation.

---

## Core Components

```
┌─────────────────────────────────────────────────────────┐
│                    HTTP Request                          │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Security Filter Chain                       │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Filter 1: SecurityContextPersistenceFilter      │   │
│  │  Filter 2: LogoutFilter                          │   │
│  │  Filter 3: UsernamePasswordAuthenticationFilter  │   │
│  │  Filter 4: ExceptionTranslationFilter            │   │
│  │  Filter 5: FilterSecurityInterceptor             │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  Application                             │
└─────────────────────────────────────────────────────────┘
```

---

## 1. Security Filter Chain

### What is it?
A chain of servlet filters that intercept HTTP requests before they reach your application.

### Key Filters (in order)

#### 1. SecurityContextPersistenceFilter
- **Purpose**: Manages SecurityContext between requests
- **Function**: Loads/saves authentication information from session

```java
// Loads SecurityContext from session at start of request
// Saves SecurityContext to session at end of request
```

#### 2. LogoutFilter
- **Purpose**: Handles logout requests
- **Function**: Clears authentication, invalidates session

```java
http.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessUrl("/login?logout")
    .invalidateHttpSession(true)
    .deleteCookies("JSESSIONID")
);
```

#### 3. UsernamePasswordAuthenticationFilter
- **Purpose**: Processes login form submissions
- **Function**: Extracts username/password, attempts authentication

```java
// Intercepts POST /login
// Extracts username and password parameters
// Creates UsernamePasswordAuthenticationToken
// Delegates to AuthenticationManager
```

#### 4. ExceptionTranslationFilter
- **Purpose**: Handles security exceptions
- **Function**: Converts exceptions to HTTP responses

```java
// AuthenticationException → Redirect to login page
// AccessDeniedException → Show 403 error page
```

#### 5. FilterSecurityInterceptor
- **Purpose**: Performs authorization checks
- **Function**: Decides if request should be allowed

```java
// Checks if authenticated user has required roles/permissions
// Uses AccessDecisionManager to make decision
```

### Custom Filter Example

```java
@Component
public class CustomLoggingFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) 
            throws ServletException, IOException {
        
        logger.info("Request: {} {}", request.getMethod(), request.getRequestURI());
        
        filterChain.doFilter(request, response);
        
        logger.info("Response status: {}", response.getStatus());
    }
}

// Add to security configuration
http.addFilterBefore(customLoggingFilter, UsernamePasswordAuthenticationFilter.class);
```

---

## 2. Authentication Architecture

### Authentication Flow

```
┌──────────────┐
│   Request    │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  UsernamePasswordAuthenticationFilter   │
│  - Extracts credentials                 │
│  - Creates Authentication token         │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│      AuthenticationManager              │
│      (ProviderManager)                  │
│  - Delegates to AuthenticationProvider  │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│    AuthenticationProvider               │
│    (DaoAuthenticationProvider)          │
│  - Validates credentials                │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│      UserDetailsService                 │
│  - Loads user from database             │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│      PasswordEncoder                    │
│  - Verifies password hash               │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│   Authentication Object (Success)       │
│  - Principal: UserDetails               │
│  - Credentials: (cleared)               │
│  - Authorities: Roles/Permissions       │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│      SecurityContext                    │
│  - Stores Authentication                │
└─────────────────────────────────────────┘
```

### Core Authentication Components

#### A. Authentication Interface

```java
public interface Authentication extends Principal, Serializable {
    
    // User's roles/permissions
    Collection<? extends GrantedAuthority> getAuthorities();
    
    // Password (cleared after authentication)
    Object getCredentials();
    
    // Additional details (IP address, session ID, etc.)
    Object getDetails();
    
    // User object (UserDetails)
    Object getPrincipal();
    
    // Is authenticated?
    boolean isAuthenticated();
    
    void setAuthenticated(boolean isAuthenticated);
}
```

**Example:**
```java
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
String username = auth.getName();
Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
boolean isAuthenticated = auth.isAuthenticated();
```

#### B. AuthenticationManager

```java
public interface AuthenticationManager {
    Authentication authenticate(Authentication authentication) 
        throws AuthenticationException;
}
```

**Default Implementation: ProviderManager**
```java
@Bean
public AuthenticationManager authenticationManager(
        AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager();
}
```

#### C. AuthenticationProvider

```java
public interface AuthenticationProvider {
    
    // Perform authentication
    Authentication authenticate(Authentication authentication) 
        throws AuthenticationException;
    
    // Can this provider handle this authentication type?
    boolean supports(Class<?> authentication);
}
```

**Common Implementation: DaoAuthenticationProvider**
```java
@Bean
public DaoAuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(userDetailsService);
    provider.setPasswordEncoder(passwordEncoder());
    return provider;
}
```

#### D. UserDetailsService

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) 
        throws UsernameNotFoundException;
}
```

**Implementation:**
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
            .disabled(false)
            .build();
    }
    
    private Collection<? extends GrantedAuthority> getAuthorities(Set<Role> roles) {
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toList());
    }
}
```

#### E. UserDetails Interface

```java
public interface UserDetails extends Serializable {
    Collection<? extends GrantedAuthority> getAuthorities();
    String getPassword();
    String getUsername();
    boolean isAccountNonExpired();
    boolean isAccountNonLocked();
    boolean isCredentialsNonExpired();
    boolean isEnabled();
}
```

**Custom Implementation:**
```java
@Entity
public class User implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String password;
    private boolean enabled;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    
    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles;
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toList());
    }
    
    // Other getters...
}
```

#### F. PasswordEncoder

```java
public interface PasswordEncoder {
    String encode(CharSequence rawPassword);
    boolean matches(CharSequence rawPassword, String encodedPassword);
}
```

**Common Implementations:**
```java
// BCrypt (Recommended)
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

// Argon2
@Bean
public PasswordEncoder passwordEncoder() {
    return new Argon2PasswordEncoder();
}

// Delegating (supports multiple encoders)
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```

---

## 3. SecurityContext and SecurityContextHolder

### SecurityContext
Stores authentication information for the current thread.

```java
public interface SecurityContext extends Serializable {
    Authentication getAuthentication();
    void setAuthentication(Authentication authentication);
}
```

### SecurityContextHolder
Provides access to SecurityContext.

```java
// Get current authentication
Authentication auth = SecurityContextHolder.getContext().getAuthentication();

// Set authentication (after successful login)
SecurityContextHolder.getContext().setAuthentication(authentication);

// Clear authentication (logout)
SecurityContextHolder.clearContext();
```

### Storage Strategies

```java
// 1. ThreadLocal (default) - per thread
SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);

// 2. InheritableThreadLocal - inherited by child threads
SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

// 3. Global - shared across all threads
SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_GLOBAL);
```

---

## 4. Authorization Architecture

### Authorization Flow

```
┌──────────────────────────────────────┐
│  FilterSecurityInterceptor           │
│  - Intercepts secured requests       │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  AccessDecisionManager               │
│  - Makes access decision             │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  AccessDecisionVoter (multiple)      │
│  - Vote: GRANT, DENY, ABSTAIN        │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  Decision: Allow or Deny             │
└──────────────────────────────────────┘
```

### AccessDecisionManager

```java
public interface AccessDecisionManager {
    void decide(Authentication authentication, 
                Object secureObject,
                Collection<ConfigAttribute> attributes) 
        throws AccessDeniedException;
}
```

**Implementations:**

1. **AffirmativeBased** (default): Grant if any voter grants
2. **ConsensusBased**: Grant if more voters grant than deny
3. **UnanimousBased**: Grant only if all voters grant

### AccessDecisionVoter

```java
public interface AccessDecisionVoter<S> {
    int ACCESS_GRANTED = 1;
    int ACCESS_ABSTAIN = 0;
    int ACCESS_DENIED = -1;
    
    int vote(Authentication authentication, S object, 
             Collection<ConfigAttribute> attributes);
}
```

**Common Voters:**
- **RoleVoter**: Votes based on roles
- **AuthenticatedVoter**: Votes based on authentication level
- **WebExpressionVoter**: Evaluates SpEL expressions

---

## 5. Complete Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         HTTP Request                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   DelegatingFilterProxy                          │
│              (Delegates to FilterChainProxy)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FilterChainProxy                              │
│              (Manages SecurityFilterChain)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  SecurityFilterChain                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ SecurityContextPersistenceFilter                         │   │
│  │   ↓                                                      │   │
│  │ LogoutFilter                                             │   │
│  │   ↓                                                      │   │
│  │ UsernamePasswordAuthenticationFilter ──────┐            │   │
│  │   ↓                                        │            │   │
│  │ ExceptionTranslationFilter                 │            │   │
│  │   ↓                                        │            │   │
│  │ FilterSecurityInterceptor                  │            │   │
│  └────────────────────────────────────────────┼────────────┘   │
└───────────────────────────────────────────────┼────────────────┘
                                                 │
                    ┌────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                  AuthenticationManager                           │
│                   (ProviderManager)                              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│               AuthenticationProvider                             │
│              (DaoAuthenticationProvider)                         │
└──────────┬─────────────────────────────────────┬────────────────┘
           │                                     │
           ▼                                     ▼
┌────────────────────────┐          ┌────────────────────────────┐
│  UserDetailsService    │          │    PasswordEncoder         │
│  - Load user from DB   │          │    - Verify password       │
└────────────────────────┘          └────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    UserDetails                                   │
│  - Username, Password, Authorities                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Authentication Object                           │
│  - Stored in SecurityContext                                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   SecurityContext                                │
│              (Stored in SecurityContextHolder)                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Configuration Example

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CSRF protection
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            
            // Authorization rules
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/home", "/register").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
            )
            
            // Form login
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/perform_login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            
            // Logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            
            // Session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true)
            )
            
            // Exception handling
            .exceptionHandling(ex -> ex
                .accessDeniedPage("/access-denied")
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

## Key Takeaways

1. **Filter Chain**: All requests pass through security filters
2. **Authentication**: Managed by AuthenticationManager and providers
3. **UserDetailsService**: Loads user information from your data source
4. **SecurityContext**: Stores authentication for current request
5. **Authorization**: Controlled by AccessDecisionManager and voters
6. **Customization**: All components can be customized for specific needs

---

## Summary

Spring Security architecture is built on:
- **Filters** for request interception
- **Managers** for authentication/authorization decisions
- **Providers** for pluggable authentication mechanisms
- **Services** for loading user details
- **Context** for storing security information

Understanding this architecture allows you to customize Spring Security to meet your specific security requirements.
