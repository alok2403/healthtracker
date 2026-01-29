package health_tracker.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                // ❗ Disabled for simplicity (as discussed)
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/login",
                                "/register",
                                "/forgot-password",
                                "/reset-password",
                                "/css/**",
                                "/js/**",
                                "/uploads/**"   // ✅ allow profile images
                        ).permitAll()

                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        .requestMatchers(
                                "/dashboard/**",
                                "/charts/**",
                                "/report/**",
                                "/profile/**"
                        ).hasRole("USER")

                        .anyRequest().authenticated()
                )

                .formLogin(form -> form
                        .loginPage("/login")
                        .usernameParameter("email")
                        .passwordParameter("password")

                        .successHandler((request, response, authentication) -> {
                            String roles = authentication.getAuthorities().toString();
                            if (roles.contains("ROLE_ADMIN")) {
                                response.sendRedirect("/admin");   // ✅ FIXED
                            } else {
                                response.sendRedirect("/dashboard");
                            }
                        })

                        .failureUrl("/login?error")
                        .permitAll()
                )

                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                );

        return http.build();
    }
}
