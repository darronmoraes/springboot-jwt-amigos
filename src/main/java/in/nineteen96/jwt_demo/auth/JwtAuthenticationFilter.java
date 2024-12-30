package in.nineteen96.jwt_demo.auth;

import in.nineteen96.jwt_demo.service.UserService;
import in.nineteen96.jwt_demo.utils.Constants;
import in.nineteen96.jwt_demo.utils.EndpointUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.websocket.Endpoint;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private final JwtTokenProvider tokenProvider;

    private final UserService userService;

    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider, UserService userService) {
        this.tokenProvider = tokenProvider;
        this.userService = userService;
    }


    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        System.out.println("request url: " + requestURI);

        if (EndpointUtils.isPermittedEndpoint(requestURI, Constants.permittedUri)) {
            System.out.println("Request to permitted endpoint. Bypassing authentication.");
            filterChain.doFilter(request, response);
            return;
        }

        System.out.println("getting authorization header");
//        log.info("attempt to get authorization header");
        final String authorizationHeader = request.getHeader("Authorization");
        final String token;

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            System.out.println("authorization header not found");
//            filterChain.doFilter(request, response);

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 Unauthorized
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Authorization header not found or invalid\"}");
            return;
        }

        token = authorizationHeader.substring(7);
        final String userEmail;

         userEmail = tokenProvider.extractUserEmail(token);
        // todo extract the user email from jwt token

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            System.out.println("username found in token and security context is null...");
            System.out.println("loading user by username");
            UserDetails userDetails = this.userService.loadUserByUsername(userEmail);
            System.out.println("validating token...");
            if (tokenProvider.isTokenValid(token, userDetails)) {
                System.out.println("token is valid");
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
                System.out.println("security context updated");
            }
        }

        filterChain.doFilter(request, response);
    }
}
