package in.nineteen96.jwt_demo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class AuthController {

    @GetMapping("/auth/login")
    public String allowUserToLogin() {
        System.out.println("login success");
        return "user login successfully";
    }

    @GetMapping("/v1/bookings")
    @PreAuthorize("hasRole('Employee')")
    public String bookingsWithLogin() {
        System.out.println("login not success");
        return "user booking success";
    }
}
