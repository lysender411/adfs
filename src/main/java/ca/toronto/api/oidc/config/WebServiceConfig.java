/**
 * 
 */
package ca.toronto.api.oidc.config;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.TrustStrategy;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


@Configuration
@ConfigurationProperties("http.setting")
public class WebServiceConfig {
	
	private static String TRUST_STORE = "javax.net.ssl.trustStore";
	private static String TRUST_PASSWORD = "javax.net.ssl.trustStorePassword";

	private String trustStore;
	private String trustStorePassword;
	private String allowedOrigin;
	
	public String getTrustStore() {
		return trustStore;
	}
	public void setTrustStore(String trustStore) {
		this.trustStore = trustStore;
	}
	public String getTrustStorePassword() {
		return trustStorePassword;
	}
	public void setTrustStorePassword(String trustStorePassword) {
		this.trustStorePassword = trustStorePassword;
	}	
	public String getAllowedOrigin() {
		return allowedOrigin;
	}
	public void setAllowedOrigin(String allowedOrigin) {
		this.allowedOrigin = allowedOrigin;
	}
	
	@Bean
	public RequestContextListener requestContextListener() {

		// load trust store if it is set in properties file, otherwise, system setting
		// for trust store is used

		if (trustStore!=null && trustStore.length()>0) {
			System.setProperty(TRUST_STORE, trustStore);
			System.setProperty(TRUST_PASSWORD, trustStorePassword);
		}

		return new RequestContextListener();
	}
	
	@Bean
	public RestTemplate restTemplate() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
    		TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
 
    		SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
                    		.loadTrustMaterial(null, acceptingTrustStrategy)
                    		.build();
 
    		SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);
 
    		CloseableHttpClient httpClient = HttpClients.custom()
                    		.setSSLSocketFactory(csf)
                    		.build();
 
    		HttpComponentsClientHttpRequestFactory requestFactory =
                    		new HttpComponentsClientHttpRequestFactory();
 
    		requestFactory.setHttpClient(httpClient);
    		RestTemplate restTemplate = new RestTemplate(requestFactory);
   		return restTemplate;
 	}

	


}
