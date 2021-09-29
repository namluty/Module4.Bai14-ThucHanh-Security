package com.apple.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //Xác thực bộ nhớ với thông tin đăng nhập và vai trò của người dùng
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("stings").password("{noop}12345").roles("STING")
                .and()
                .withUser("admin").password("{noop}namluty").roles("ADMIN")
                .and()
                .withUser("boadmin").password("{noop}namluty1").roles("BOADMIN");
        //noop để mã hóa password
    }

    //Phân quyền, cấu hình bảo mật dựa trên request, có thể bị hạn chế bằng cách sử dụng requestMatcher
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .and()
                .authorizeRequests().antMatchers("/admin**").hasAnyRole("ADMIN","BOADMIN")
                .and()
                .authorizeRequests().antMatchers("/stings**").permitAll()
                .and()
                .authorizeRequests().antMatchers("/boadmin**").hasRole("BOADMIN")
                .and()
                .formLogin()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
    }
}
