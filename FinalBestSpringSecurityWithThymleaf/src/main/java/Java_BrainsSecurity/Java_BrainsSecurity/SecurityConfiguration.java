package Java_BrainsSecurity.Java_BrainsSecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
//    private UserPrincipalDetailsService userPrincipalDetailsService;
//
//    public SecurityConfiguration(UserPrincipalDetailsService userPrincipalDetailsService) {
//        this.userPrincipalDetailsService = userPrincipalDetailsService;
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)throws Exception {
        auth.inMemoryAuthentication()
        	 .withUser("admin").password(passwordEncoder().encode("admin123")).roles("ADMIN").authorities("ACCESS_TEST1","ACCESS_TEST2")
        	 .and()
        	 .withUser("dan").password(passwordEncoder().encode("dan123")).roles("USER")
             .and()
   	         .withUser("manager").password(passwordEncoder().encode("manager123")).roles("MANAGER").authorities("ACCESS_TEST1");
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
    	.and()
    	.httpBasic();
               
    }

//    @Bean
//    DaoAuthenticationProvider authenticationProvider(){
//        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
//        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
//        daoAuthenticationProvider.setUserDetailsService(this.userPrincipalDetailsService);
//
//        return daoAuthenticationProvider;
//    }
//
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
