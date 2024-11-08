package io.security.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(form -> form
                        // 사용자가 정의한 커스텀 로그인 페이지 경로, 경로를 지정하면 기본 제공 로그인 페이지는 무시.
//                        .loginPage("/loginPage")
                        // username, password 를 검증할 경로, form 태그의 action 속성에 정의
                        .loginProcessingUrl("/loginProc")
                        // 인증 성공 시 이동할 페이지 경로
                        // alwaysUser true: 지정 경로로 무조건 이동, false(default): 인증 전 접근 경로로 리다이렉트
                        .defaultSuccessUrl("/", true)
                        // 인증 실패 시 이동할 페이지 경로, default: /login?error
                        .failureUrl("/failed")
                        // 인증에 사용될 username 매개변수 설정, input username 태그의 name 속성에 정의, default: username
                        .usernameParameter("userId")
                        // 인증에 사용될 password 매개변수 설정, input password 태그의 name 속성에 정의 , default: password
                        .passwordParameter("userPw")
                        // 인증 성공 시 사용할 AuthenticationSuccessHandler 지정
                        // default: SavedRequestAwareAuthenticationSuccessHandler
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                System.out.println("authentication = " + authentication);
                                response.sendRedirect("/home");
                            }
                        })
                        // 인증 실패 시 사용할 AuthenticationFailureHandler 지정
                        // default: SimpleUrlAuthenticationFailureHandler -> /login?error 리다이렉트
                        .failureHandler(new AuthenticationFailureHandler() {
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                System.out.println("exception.getMessage() = " + exception.getMessage());
                                response.sendRedirect("/login");
                            }
                        })
                        // 위에 설정된 경로에 대한 모든 사용자 접근 허용
                        .permitAll());
        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withUsername("admin")
                .password("{noop}admin$$")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }
}
