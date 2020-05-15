package com.example.demo.config;

import com.example.demo.pojo.GithubOAuth2User;
import com.example.demo.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import javax.annotation.Resource;
import java.util.*;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private UserService userService;

    @Bean
    public PasswordEncoder initPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin().loginPage("/login/github").loginProcessingUrl("/login/form")
                .and()
                .authorizeRequests()
                .antMatchers("/hello").hasAnyAuthority("ROLE_USER")
                .antMatchers("/**").permitAll()
                .and()
                .logout().deleteCookies("JSESSIONID")
                .logoutSuccessUrl("/").permitAll();

        http.oauth2Login().loginPage("/login/github");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(initPasswordEncoder());
    }

    @Bean
    public GrantedAuthoritiesMapper initGrantedAuthoritiesMapper(){
        return collection -> {
            collection.forEach(authority->{

                System.out.println(authority.getClass().getName());

                if (authority instanceof OidcUserAuthority){
                    OidcUserAuthority oidcUserAuthority=(OidcUserAuthority) authority;

                    OidcIdToken oidcIdToken=oidcUserAuthority.getIdToken();
                    OidcUserInfo oidcUserInfo=oidcUserAuthority.getUserInfo();

                    printMap(oidcIdToken.getClaims());
                    printMap(oidcUserInfo.getClaims());
                }else if (authority instanceof OAuth2UserAuthority){
                    OAuth2UserAuthority oAuth2UserAuthority=(OAuth2UserAuthority) authority;

                    Map<String,Object> attributes=oAuth2UserAuthority.getAttributes();
                    printMap(attributes);
                }
            });

            Set<GrantedAuthority> authorities=new HashSet<>();

            //authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            //authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

            return collection;
        };
    }

    private void printMap(Map<String,Object> map){
        for (Map.Entry<String,Object> entry:map.entrySet()){
            System.out.println(entry.getKey()+" ==> "+entry.getValue());
        }
    }
}
