package Java_BrainsSecurity.Java_BrainsSecurity.AllSecurityConfiguarations;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import Java_BrainsSecurity.Java_BrainsSecurity.UserRepository;
import Java_BrainsSecurity.Java_BrainsSecurity.jwt.JwtAuthenticationFilter;
import Java_BrainsSecurity.Java_BrainsSecurity.jwt.JwtAuthorizationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

//@Autowired
private UserPrincipalDetailsService userPrincipleDetailsService;
private UserRepository userRepository;
//private BasicAuthenticationEntryPoint authenticationEntryPoint;
//private Object basicAuthenticationEntryPoint;

public SecurityConfiguration(UserPrincipalDetailsService userPrincipleDetailsService, UserRepository userRepository) {
	this.userPrincipleDetailsService=userPrincipleDetailsService;
	this.userRepository=userRepository;
	
}
	
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider()); //the bean below
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        
    	 http
         // remove csrf and state in session because in jwt we do not need them
         .csrf().disable()
         .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
         .and()
         // add jwt filters (1. authentication, 2. authorization)
         .addFilter(new JwtAuthenticationFilter(authenticationManager()))
         .addFilter(new JwtAuthorizationFilter(authenticationManager(),  this.userRepository))
         .authorizeRequests()
         // configure access rules
         .antMatchers(HttpMethod.POST, "/login").permitAll()
         .antMatchers("/api/public/management/*").hasRole("MANAGER")
         .antMatchers("/api/public/admin/*").hasRole("ADMIN")
         .anyRequest().authenticated();
    }
    
   

    @Bean
    DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(this.userPrincipleDetailsService);

        return daoAuthenticationProvider;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}