package com.dico.customercomplaint.user.config;


import com.dico.customercomplaint.user.repository.UserRepository;
import com.dico.customercomplaint.user.service.CustomerUserDetailsService;
import net.bytebuddy.utility.nullability.AlwaysNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
//
//    @Autowired
//    private BasicAuthenticationEntryPoint basicAuthenticationEntryPoint;
    @Autowired
     private  UserRepository userRepository;
     @Bean
    public UserDetailsService userDetailsService(){
        return new CustomerUserDetailsService();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder (){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider (){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(bCryptPasswordEncoder());
        return provider;
    }

    @Bean
    public SecurityFilterChain FilterChain(HttpSecurity http) throws Exception {
          authenticationProvider();
          http.csrf(auth-> auth.disable())
                  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                  .and()
                  .addFilter(new JwtAuthenticationFilter(authentication -> (Authentication) authenticationProvider()))
                  .addFilter(new JwtAuthorizationFilter(authentication -> (Authentication) authenticationProvider(), this.userRepository))
                  .authorizeRequests()
                  .antMatchers("/login").permitAll()

                  .antMatchers("/api/public/admin/*").hasRole("ADMINISTRATOR")
                  .antMatchers("/api/public/customer/");
        return http.build();
    }


}
