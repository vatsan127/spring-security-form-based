# Authentication vs Authorization

## Overview

```
Authentication: "Who are you?"
Authorization: "What can you do?"
```

---

## Authentication

### Definition
**Authentication** is the process of verifying the identity of a user, device, or system.

### Key Question
"Are you really who you claim to be?"

### Common Authentication Methods

#### 1. Knowledge-Based (Something You Know)
```java
// Username + Password
public class UsernamePasswordAuthentication {
    private String username;
    private String password;
}
```

#### 2. Possession-Based (Something You Have)
- Security tokens
- Smart cards
- Mobile devices (OTP)
- Hardware keys (YubiKey)

#### 3. Inherence-Based (Something You Are)
- Fingerprint
- Facial recognition
- Iris scan
- Voice recognition

#### 4. Multi-Factor Authentication (MFA)
Combines 2+ methods for stronger security.

```
Example: Password (knowledge) + OTP from phone (possession)
```

### Authentication Flow

```
1. User submits credentials (username/password)
2. System validates credentials against stored data
3. If valid → Create session/token
4. If invalid → Reject access
```

### Spring Security Authentication Example

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) 
            throws UsernameNotFoundException {
        
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        return org.springframework.security.core.userdetails.User
            .withUsername(user.getUsername())
            .password(user.getPassword())
            .authorities(user.getRoles())
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(false)
            .build();
    }
}
```

### Authentication States

```java
// Authenticated
SecurityContext context = SecurityContextHolder.getContext();
Authentication auth = context.getAuthentication();
if (auth != null && auth.isAuthenticated()) {
    String username = auth.getName();
}

// Not Authenticated (Anonymous)
if (auth == null || !auth.isAuthenticated()) {
    // Redirect to login
}
```

---

## Authorization

### Definition
**Authorization** is the process of determining what an authenticated user is allowed to do.

### Key Question
"What permissions do you have?"

### Authorization Happens AFTER Authentication

```
Step 1: Authentication → Verify identity
Step 2: Authorization → Check permissions
```

### Common Authorization Models

#### 1. Role-Based Access Control (RBAC)

```java
@Entity
public class User {
    @Id
    private Long id;
    private String username;
    
    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles;
}

@Entity
public class Role {
    @Id
    private Long id;
    private String name; // ROLE_USER, ROLE_ADMIN, ROLE_MANAGER
}
```

**Example:**
```
User: john
Roles: ROLE_USER, ROLE_ADMIN

Admin can: Create, Read, Update, Delete
User can: Read only
```

#### 2. Permission-Based Access Control

```java
@Entity
public class Role {
    @Id
    private Long id;
    private String name;
    
    @ManyToMany
    private Set<Permission> permissions;
}

@Entity
public class Permission {
    @Id
    private Long id;
    private String name; // READ_USERS, WRITE_USERS, DELETE_USERS
}
```

#### 3. Attribute-Based Access Control (ABAC)

Based on attributes of user, resource, and environment.

```java
// Example: User can edit only their own posts
if (post.getAuthor().equals(currentUser) || currentUser.hasRole("ADMIN")) {
    // Allow edit
}
```

### Spring Security Authorization

#### Method 1: URL-Based Authorization

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().denyAll()
            );
        return http.build();
    }
}
```

#### Method 2: Method-Level Authorization

```java
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
}

@Service
public class UserService {
    
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long userId) {
        // Only admins can execute
    }
    
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public User getUser(Long userId) {
        // Users and admins can execute
    }
    
    @PreAuthorize("#username == authentication.principal.username or hasRole('ADMIN')")
    public void updateUser(String username, User user) {
        // Users can update their own profile, admins can update anyone
    }
    
    @PostAuthorize("returnObject.username == authentication.principal.username")
    public User getUserDetails(Long userId) {
        // Check after method execution
    }
}
```

#### Method 3: Expression-Based Authorization

```java
@PreAuthorize("hasPermission(#post, 'WRITE')")
public void editPost(Post post) {
    // Custom permission evaluator
}

// Custom Permission Evaluator
@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {
    
    @Override
    public boolean hasPermission(Authentication auth, Object targetDomainObject, 
                                 Object permission) {
        if (targetDomainObject instanceof Post) {
            Post post = (Post) targetDomainObject;
            String username = auth.getName();
            
            // User can edit their own posts
            if (post.getAuthor().equals(username)) {
                return true;
            }
            
            // Admins can edit any post
            return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        }
        return false;
    }
    
    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, 
                                 String targetType, Object permission) {
        return false;
    }
}
```

---

## Key Differences

| Aspect | Authentication | Authorization |
|--------|---------------|---------------|
| **Purpose** | Verify identity | Grant permissions |
| **Question** | Who are you? | What can you do? |
| **Process** | Login with credentials | Check access rights |
| **When** | First step | After authentication |
| **Data Used** | Username, password, biometrics | Roles, permissions, policies |
| **Result** | Authenticated or not | Allowed or denied |
| **Example** | Login to Gmail | Access to specific emails/folders |

---

## Real-World Examples

### Example 1: Banking Application

```java
// Authentication
User logs in with username + password + OTP
→ System verifies credentials
→ User is authenticated

// Authorization
Authenticated user tries to transfer money
→ Check if user has "TRANSFER_MONEY" permission
→ Check if account belongs to user
→ Check daily transfer limit
→ Allow or deny transaction
```

### Example 2: E-commerce Platform

```java
// Authentication
Customer logs in with email + password
→ System validates credentials
→ Customer is authenticated

// Authorization
Customer tries to access order history
→ Can view own orders ✓
→ Cannot view other customers' orders ✗
→ Cannot access admin panel ✗

Admin logs in
→ Can view all orders ✓
→ Can access admin panel ✓
→ Can manage products ✓
```

---

## Complete Spring Security Example

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Authentication configuration
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout")
                .permitAll()
            )
            
            // Authorization configuration
            .authorizeHttpRequests(auth -> auth
                // Public access
                .requestMatchers("/", "/home", "/register").permitAll()
                
                // Role-based access
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                .requestMatchers("/user/**").hasRole("USER")
                
                // Authenticated users
                .requestMatchers("/profile/**").authenticated()
                
                // Deny all others
                .anyRequest().denyAll()
            );
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

@RestController
@RequestMapping("/api")
public class UserController {
    
    // Anyone can access (no authentication required)
    @GetMapping("/public/info")
    public String publicInfo() {
        return "Public information";
    }
    
    // Must be authenticated
    @GetMapping("/user/profile")
    public String userProfile() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Profile of: " + auth.getName();
    }
    
    // Must have ADMIN role
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/admin/users/{id}")
    public String deleteUser(@PathVariable Long id) {
        return "User deleted";
    }
    
    // Must have specific permission
    @PreAuthorize("hasAuthority('DELETE_USERS')")
    @DeleteMapping("/users/{id}")
    public String deleteUserByPermission(@PathVariable Long id) {
        return "User deleted";
    }
    
    // Custom authorization logic
    @PreAuthorize("#id == authentication.principal.id or hasRole('ADMIN')")
    @PutMapping("/users/{id}")
    public String updateUser(@PathVariable Long id, @RequestBody User user) {
        return "User updated";
    }
}
```

---

## Best Practices

### Authentication Best Practices

1. **Use Strong Password Policies**
```java
@Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$")
private String password;
```

2. **Hash Passwords**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12); // strength factor
}
```

3. **Implement Account Lockout**
```java
if (failedAttempts >= 3) {
    user.setAccountLocked(true);
}
```

4. **Use HTTPS**
5. **Implement Session Timeout**
6. **Enable MFA for sensitive operations**

### Authorization Best Practices

1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Deny by Default**: Explicitly allow, implicitly deny
```java
.anyRequest().denyAll() // Not permitAll()
```

3. **Centralized Authorization Logic**
4. **Regular Access Reviews**
5. **Audit Logging**
```java
@PostAuthorize("returnObject != null")
public User getUser(Long id) {
    logger.info("User {} accessed user {}", currentUser, id);
    return userRepository.findById(id);
}
```

---

## Summary

```
┌─────────────────────────────────────────────────────┐
│                    User Request                      │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              AUTHENTICATION                          │
│  "Who are you?"                                      │
│  - Verify credentials                                │
│  - Create session/token                              │
└─────────────────────────────────────────────────────┘
                         │
                    ✓ Authenticated
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              AUTHORIZATION                           │
│  "What can you do?"                                  │
│  - Check roles/permissions                           │
│  - Evaluate access rules                             │
└─────────────────────────────────────────────────────┘
                         │
                    ✓ Authorized
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              Access Granted                          │
└─────────────────────────────────────────────────────┘
```

**Remember**: You cannot have authorization without authentication, but you can have authentication without authorization (e.g., all authenticated users have the same access).
