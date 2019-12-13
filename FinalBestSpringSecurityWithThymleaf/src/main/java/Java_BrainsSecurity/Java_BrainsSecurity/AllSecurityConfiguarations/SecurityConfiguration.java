package Java_BrainsSecurity.Java_BrainsSecurity.AllSecurityConfiguarations;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

//@Autowired
private UserPrincipalDetailsService userPrincipleDetailsService;

public SecurityConfiguration(UserPrincipalDetailsService userPrincipleDetailsService) {
	this.userPrincipleDetailsService=userPrincipleDetailsService;
}
	
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider()); //the bean below
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        
    	http.authorizeRequests()
    	.antMatchers("/index.html").permitAll()//START WITH THE LEAST PRIVILLEGED COZ EVERY ROLE CAN ACCESS EVERYTHING ABOVE IT eg ADMIN CAN ACCESS /profile/index and /index.html
    	.antMatchers("/profile/**").authenticated() //No html extension coz its the only file in the folder admin
    	.antMatchers("/admin/**").hasRole("ADMIN") //MEANS ANY FILE WITHIN THE admin folder
    	.antMatchers("/management/**").hasAnyRole("ADMIN","MANAGER")//MEANS ANY FILE WITHIN THE management folder
    	.antMatchers("/api/public/test1").hasAnyAuthority("ACCESS_TEST1")
    	.antMatchers("/api/public/test2").hasAnyAuthority("ACCESS_TEST2")
    	.antMatchers("/api/public/users").hasRole("ADMIN")
    	.and()
    	.formLogin()
    	//.loginProcessingUrl("/signin")
    	//.usernameParameter("txtUsername") //SET THIS PARAMETERS IF THE FORM NAMES ARE NOT CALLED AS REQUIRED BY SPRING ..SO WE CAN CONFIGURE TO CHANGE THE DEFAULTS
    	//.passwordParameter("txtPassword")
    	.loginPage("/login").permitAll()  //since everybody needs to access the Login page
    	.and()
    	.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/index") //NB /logout is the path in the logout button
    	.and()																								//we dont have to add the request mapping in the controller spring will handle the logout out of the box as long as the path in the logout btn is /logout
    	.rememberMe().tokenValiditySeconds(2592000);  //nothing else needs to be done as long as the id and name in the remember me check box is "remember-me"
    									  //30 days in seconds is 2592000
    	//.rememberMe().tokenValiditySeconds(2592000).rememberMeParameter("anything");      
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