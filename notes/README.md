# Spring Security Learning Notes - Index

## Overview
This directory contains comprehensive notes on Spring Security fundamentals, covering security attacks, authentication/authorization concepts, architecture, and form-based login implementation.

---

## Table of Contents

### 1. [Security Attacks](01-security-attacks.md)
Detailed coverage of common web security attacks and prevention techniques:
- **CSRF (Cross-Site Request Forgery)**
  - How CSRF attacks work
  - Prevention with CSRF tokens
  - Spring Security protection
- **XSS (Cross-Site Scripting)**
  - Stored, Reflected, and DOM-based XSS
  - Output encoding and input validation
  - Content Security Policy (CSP)
- **CORS (Cross-Origin Resource Sharing)**
  - Same-Origin Policy
  - CORS configuration in Spring
  - Security considerations
- **SQL Injection**
  - Attack vectors and examples
  - Prepared statements and parameterized queries
  - JPA/Hibernate best practices

### 2. [Authentication vs Authorization](02-authentication-vs-authorization.md)
Understanding the fundamental difference between authentication and authorization:
- **Authentication**
  - Definition and purpose
  - Authentication methods (knowledge, possession, inherence)
  - Multi-Factor Authentication (MFA)
  - Spring Security authentication flow
- **Authorization**
  - Definition and purpose
  - Authorization models (RBAC, Permission-based, ABAC)
  - URL-based and method-level authorization
  - Expression-based security
- **Key Differences**
  - Comparison table
  - Real-world examples
  - Best practices

### 3. [Spring Security Architecture](03-spring-security-architecture.md)
Deep dive into Spring Security's internal architecture:
- **Security Filter Chain**
  - Filter execution order
  - Key filters and their roles
  - Custom filter implementation
- **Authentication Architecture**
  - Authentication flow diagram
  - Core components (AuthenticationManager, AuthenticationProvider, UserDetailsService)
  - UserDetails and PasswordEncoder
- **SecurityContext and SecurityContextHolder**
  - Storage strategies
  - Thread-local security context
- **Authorization Architecture**
  - AccessDecisionManager
  - AccessDecisionVoter
  - Role-based and permission-based authorization
- **Complete Architecture Diagram**
- **Configuration Examples**

### 4. [Form-Based Login](04-form-based-login.md)
Complete guide to implementing form-based authentication:
- **How Form-Based Login Works**
  - Authentication flow
  - Request/response cycle
- **Basic and Custom Configuration**
  - Minimal setup
  - Custom login pages
  - Custom parameters
- **Custom Login Page Implementation**
  - HTML form with Thymeleaf
  - Controller setup
  - CSRF token handling
- **UserDetailsService Implementation**
  - Entity classes (User, Role)
  - Repository layer
  - Custom UserDetailsService
- **Advanced Features**
  - Remember Me functionality
  - Custom success/failure handlers
  - Account lockout (brute force protection)
  - Session management
- **Complete Working Example**
  - Project structure
  - Full configuration
  - Test user setup
- **Best Practices and Common Issues**

---

## Learning Path

### Recommended Reading Order:
1. Start with **Authentication vs Authorization** to understand the fundamentals
2. Read **Security Attacks** to learn about common vulnerabilities
3. Study **Spring Security Architecture** to understand how Spring Security works internally
4. Finally, dive into **Form-Based Login** for practical implementation

### Next Steps:
After completing these notes, you'll be ready to:
- Implement a complete form-based login application
- Configure OAuth2 and JWT authentication
- Implement method-level security
- Add custom security features
- Handle advanced authorization scenarios

---

## Quick Reference

### Common Annotations
```java
@EnableWebSecurity              // Enable Spring Security
@EnableMethodSecurity           // Enable method-level security
@PreAuthorize("hasRole('ADMIN')")  // Method security
@PostAuthorize("returnObject.owner == authentication.name")
@Secured("ROLE_ADMIN")          // Simple role check
```

### Common Configuration Patterns
```java
// URL-based authorization
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated()
)

// Form login
.formLogin(form -> form
    .loginPage("/login")
    .defaultSuccessUrl("/dashboard")
    .permitAll()
)

// Logout
.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessUrl("/login?logout")
)
```

### Getting Current User
```java
// In controller
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
String username = auth.getName();

// In Thymeleaf
<span th:text="${#authentication.name}">Username</span>

// Method parameter injection
public String dashboard(@AuthenticationPrincipal UserDetails user) {
    return "Welcome " + user.getUsername();
}
```

---

## Additional Resources

### Official Documentation
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Spring Security API Docs](https://docs.spring.io/spring-security/site/docs/current/api/)

### Security Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Tools for Testing
- OWASP ZAP - Security testing tool
- Burp Suite - Web vulnerability scanner
- Postman - API testing

---

## Practice Projects

After studying these notes, try building:
1. **Basic Blog Application** with user authentication
2. **E-commerce Platform** with role-based access (Admin, Customer)
3. **Banking Application** with MFA and transaction authorization
4. **Social Media App** with permission-based content access

---

## Notes

- All code examples are based on **Spring Boot 3.x** and **Spring Security 6.x**
- Examples use **Java 17+** features
- Database examples use **JPA/Hibernate**
- Template examples use **Thymeleaf**

---

## Feedback and Updates

These notes are designed to be comprehensive yet practical. As you progress through implementation, you may want to add:
- Your own examples and use cases
- Troubleshooting notes for issues you encounter
- Performance optimization tips
- Integration with other technologies (OAuth2, JWT, etc.)

---

**Happy Learning! 🚀**

Next: [Start with Authentication vs Authorization →](02-authentication-vs-authorization.md)
