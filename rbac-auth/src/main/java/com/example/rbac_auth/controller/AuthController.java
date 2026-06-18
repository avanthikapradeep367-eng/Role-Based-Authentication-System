package com.example.rbac_auth.controller;

import java.security.Principal;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.rbac_auth.dto.LoginRequest;
import com.example.rbac_auth.dto.RegisterRequest;
import com.example.rbac_auth.model.Role;
import com.example.rbac_auth.model.User;
import com.example.rbac_auth.repo.UserRepository;
import com.example.rbac_auth.security.JwtService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepo;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public AuthController(UserRepository userRepo, JwtService jwtService) {
        this.userRepo = userRepo;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest req) {
        if (userRepo.existsByUsername(req.username)) {
            return Map.of("error", "Username already exists");
        }

        // 🛡️ Always assign ROLE_USER by default. Role selection during signup is disabled.
        User user = new User(
                req.username,
                encoder.encode(req.password),
                Role.USER
        );

        userRepo.save(user);

        return Map.of(
                "message", "User registered successfully",
                "username", user.getUsername(),
                "role", user.getRole().name()
        );
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest req) {
        var userOpt = userRepo.findByUsername(req.username);

        if (userOpt.isEmpty()) {
            return Map.of("error", "Invalid credentials");
        }

        User user = userOpt.get();

        if (!encoder.matches(req.password, user.getPassword())) {
            return Map.of("error", "Invalid credentials");
        }

        // 🔑 Generate JWT token containing the verified username and role
        String token = jwtService.generateToken(user.getUsername(), user.getRole().name());

        return Map.of(
                "message", "Login successful",
                "token", token,
                "username", user.getUsername(),
                "role", user.getRole().name()
        );
    }

    @GetMapping("/profile")
    public Object profile(Principal principal) {
        if (principal == null) {
            return Map.of("error", "Unauthorized");
        }
        var userOpt = userRepo.findByUsername(principal.getName());
        if (userOpt.isEmpty()) {
            return Map.of("error", "User not found");
        }
        User user = userOpt.get();
        return Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "role", user.getRole().name()
        );
    }

    @PostMapping("/profile/update")
    public Object updateProfile(@RequestBody Map<String, String> req, Principal principal) {
        if (principal == null) {
            return Map.of("error", "Unauthorized");
        }
        var userOpt = userRepo.findByUsername(principal.getName());
        if (userOpt.isEmpty()) {
            return Map.of("error", "User not found");
        }
        User user = userOpt.get();
        String newPassword = req.get("password");
        if (newPassword != null && !newPassword.trim().isEmpty()) {
            user.setPassword(encoder.encode(newPassword));
            userRepo.save(user);
            return Map.of("message", "Profile updated successfully");
        }
        return Map.of("error", "Invalid password details");
    }

    @GetMapping("/users")
    public Object listUsers(Authentication auth) {
        if (auth == null) {
            return Map.of("error", "Access Denied: Insufficient credentials");
        }
        boolean hasPermission = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") || a.getAuthority().equals("ROLE_MANAGER"));
        if (!hasPermission) {
            return Map.of("error", "Access Denied: Insufficient permissions");
        }
        return userRepo.findAll();
    }

    @DeleteMapping("/users/{id}")
    public Object deleteUser(@PathVariable Long id, Authentication auth) {
        if (auth == null) {
            return Map.of("error", "Access Denied: Insufficient credentials");
        }
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!isAdmin) {
            return Map.of("error", "Access Denied: Admin role required");
        }
        if (!userRepo.existsById(id)) {
            return Map.of("error", "User not found");
        }
        userRepo.deleteById(id);
        return Map.of("message", "User deleted successfully");
    }

    @PostMapping("/users/promote/{id}")
    public Object promoteUser(@PathVariable Long id, Authentication auth) {
        if (auth == null) {
            return Map.of("error", "Access Denied: Insufficient credentials");
        }
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!isAdmin) {
            return Map.of("error", "Access Denied: Admin role required");
        }
        
        var userOpt = userRepo.findById(id);
        if (userOpt.isEmpty()) {
            return Map.of("error", "User not found");
        }
        
        User user = userOpt.get();
        if (user.getRole() == Role.USER) {
            user.setRole(Role.MANAGER);
        } else if (user.getRole() == Role.MANAGER) {
            user.setRole(Role.ADMIN);
        } else {
            return Map.of("error", "User is already at the highest clearance level (ADMIN)");
        }
        
        userRepo.save(user);
        return Map.of("message", "User promoted successfully", "newRole", user.getRole().name());
    }

    @PostMapping("/users/demote/{id}")
    public Object demoteUser(@PathVariable Long id, Authentication auth) {
        if (auth == null) {
            return Map.of("error", "Access Denied: Insufficient credentials");
        }
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!isAdmin) {
            return Map.of("error", "Access Denied: Admin role required");
        }
        
        var userOpt = userRepo.findById(id);
        if (userOpt.isEmpty()) {
            return Map.of("error", "User not found");
        }
        
        User user = userOpt.get();
        if (user.getRole() == Role.ADMIN) {
            user.setRole(Role.MANAGER);
        } else if (user.getRole() == Role.MANAGER) {
            user.setRole(Role.USER);
        } else {
            return Map.of("error", "User is already at the lowest clearance level (USER)");
        }
        
        userRepo.save(user);
        return Map.of("message", "User demoted successfully", "newRole", user.getRole().name());
    }
}


