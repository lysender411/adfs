package ca.toronto.api.oidc;

import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import ca.toronto.api.oidc.utils.SSLUtils;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@ComponentScan 
@EnableCaching
public class Application  extends SpringBootServletInitializer {
	/* This method and the class 'extends SpringBootServletInitializer' are necessities for bootWar */
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(Application.class);
    }
    

 
    public static void main(String[] args) throws KeyManagementException, NoSuchAlgorithmException {
//    	SSLUtils.turnOffSslChecking();
        SpringApplication.run(Application.class, args);
    }
  
}
