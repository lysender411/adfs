/**
 * 
 */
package ca.toronto.api.oidc.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	private static Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);
	
	@Value("${spring.security.oauth2.client.registration.adfs.success_url}")
	private String successUrl;
	
	@Value("${spring.security.oauth2.client.registration.adfs.failure_url}")
	private String failureUrl;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests()

        	// all other requests
        	.anyRequest().permitAll()

        	.and().logout().invalidateHttpSession(true).clearAuthentication(true).deleteCookies("JSESSIONID").permitAll()

        	// enable OAuth2/OIDC
        	.and().oauth2Login()//.redirectionEndpoint().baseUri("/oauth2/callback/adfs").and()
        	//.successHandler(successHandler()).failureHandler(failureHandler())
        	
        	.and().csrf().csrfTokenRepository(new CookieCsrfTokenRepository())
			.requireCsrfProtectionMatcher(httpServletRequest -> httpServletRequest.getMethod().equals("DELETE"));
		
			http.headers().frameOptions().disable();
//		http.addFilterAfter(new RespFilter(), BasicAuthenticationFilter.class);
		
		
	}


	@Bean
    SimpleUrlAuthenticationSuccessHandler successHandler() {
        return new SimpleUrlAuthenticationSuccessHandler(successUrl);
    }
    
    @Bean
    SimpleUrlAuthenticationFailureHandler failureHandler() {
        return new SimpleUrlAuthenticationFailureHandler(failureUrl);
    }

	
}
