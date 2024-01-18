package com.hello.springsecurityjwt.config;

import com.hello.springsecurityjwt.jwt.JWTFilter;
import com.hello.springsecurityjwt.jwt.JWTUtil;
import com.hello.springsecurityjwt.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // cors custom setting
        http.cors((cors) -> cors.configurationSource(apiConfigurationSource()));

        // 세션방식에서는 세션이 항상 고정되므로 csrf공격에 대해 방어해줘야 함.
        // but, jwt방식에서는 csrf에 대한 공격을 방어하지 않아도 됨.
        http.csrf((auth) -> auth.disable());

        // jwt 로그인 방식을 선택할것임.
        http.formLogin((auth) -> auth.disable());
        http.httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/login", "/", "/join").permitAll()
//                .requestMatchers("/admin").hasRole("ADMIN_")
                .anyRequest().authenticated()); //나머지 요청은 로그인한 사용자만 처리할 수 있음.

        //LoginFilter 앞에 JWTFilter를 넣어준다.
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        //UsernamePasswordAuthenticationFilter의 자리를 우리의 커스텀 필터로 대체한다.
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // jwt방식에서는 세션을 stateless하게 관리한다.
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    public CorsConfigurationSource apiConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(Arrays.asList("https://api.example.com"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST"));
        configuration.addExposedHeader("Authorization");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

}
