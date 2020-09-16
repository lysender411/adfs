/**
 * 
 */
package ca.toronto.api.oidc.controller;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.google.gson.JsonObject;

import ca.toronto.api.oidc.config.WebServiceConfig;
import ca.toronto.api.oidc.model.ADFSTokens;
import ca.toronto.api.oidc.service.ADFSTokenService;
import ca.toronto.api.oidc.utils.CookieUtils;


@RestController
@RequestMapping(value = { "/oauth2/callback" }) 
public class ADFSController {
	private static Logger log = LoggerFactory.getLogger(ADFSController.class);
	
	@Autowired
	ADFSTokenService tokenService;
	
	@Autowired
	RestTemplate restTemplate;
	
	@Autowired
	private WebServiceConfig webConfig;
	
	@Value("${spring.security.oauth2.client.provider.adfs.logout}")
    private String logoutUrl;
	
	@CrossOrigin(origins = "*", maxAge = 3600)
	@GetMapping(value="/adfs", produces = MediaType.TEXT_HTML_VALUE)
	public ResponseEntity<Object> authorize(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
            @AuthenticationPrincipal OAuth2User oauth2User, HttpServletRequest request) throws URISyntaxException {
		
		String cookiesValue = CookieUtils.getCookieValue(request, "JSESSIONID");
		
		log.info(">>>session cookie>>> "+cookiesValue);
		log.info(">>>authorize>>> "+oauth2User);
		log.info(">>>client>>> "+authorizedClient);
		
		String upn = oauth2User.getAttribute("upn");
		
		String clientId = authorizedClient.getClientRegistration().getClientId();
		
		String principleName = authorizedClient.getPrincipalName();
		
		log.info("clientID === "+clientId+"       principleName === "+principleName);
        
		log.info(authorizedClient.getAccessToken() + " --- "+ authorizedClient.getRefreshToken());
		
		ADFSTokens adfsToken = new ADFSTokens(upn, clientId);
		
		String errorMsg = "";
        OAuth2AccessToken at = authorizedClient.getAccessToken();
        if(at==null){
        	errorMsg = "no access_token in authorizedClient. ";
        }else{	
        	log.info("accessToken : "+at.getTokenValue());
        }
        
        OAuth2RefreshToken rt = authorizedClient.getRefreshToken();
        if(rt==null){
        	errorMsg += "The refresh_token is expired. please login again.";
        		
    		restTemplate.getForEntity(logoutUrl, String.class);
        }else{	
        	log.info("refresh token : "+ rt.getTokenValue());  
        	adfsToken.setRefreshToken(rt.getTokenValue());        	        	
        }
        
        if(errorMsg.length()==0){
        	tokenService.evictSingleToken(cookiesValue);
        	tokenService.getToken(cookiesValue,adfsToken);		//save token in cache
        }else{
        	log.info("error: "+errorMsg); 
        }
        
 //       log.info("TOKEN SIZE === "+tokenService.getCacheSize());
        
        String redirectUrl = null;
        
        if (!request.getParameterMap().containsKey("noRedirect")) {        
        	redirectUrl = request.getHeader("Referer");
        	if(redirectUrl==null){
        		redirectUrl = request.getParameter("redirect");
        	}	
        }	
        
        if(redirectUrl!=null && redirectUrl.length()>0){ 
        
	        URI url = new URI(redirectUrl);
	        if(errorMsg.length()>0){
	        	url = new URI(redirectUrl+"?error="+errorMsg);
	        }
	        HttpHeaders httpHeaders = new HttpHeaders();
	        httpHeaders.setLocation(url);
	        
	        String sessionid = ((HttpServletRequest) request).getSession().getId();
			String cookieFlags = "; HttpOnly;SameSite=None;Secure";
	        httpHeaders.set("Set-Cookie", "JSESSIONID=" + sessionid + cookieFlags );
	        	        
	        return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
        }else{
        	String result = "Logged in ADFS successfully. <br/><br/>User:"+upn+"<hr/> "+"(session:"+cookiesValue+")";
        	if(errorMsg.length()>0){
        		result = "Log in failed. Please try later. \n"+errorMsg;
        	}
        	return ResponseEntity.accepted().body(result);
        }
        
    } 
	
	@GetMapping(value="/status", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<String> checkStatus(HttpServletRequest request) {
		
		HttpHeaders headers = new HttpHeaders();
		
		headers.add("Access-Control-Allow-Origin", webConfig.getAllowedOrigin());	
		headers.add("Access-Control-Allow-Credentials", "true");
		headers.add("Access-Control-Allow-Methods", "*");
		
		JsonObject result = new JsonObject();
		
		String cookiesValue = CookieUtils.getCookieValue(request, "JSESSIONID");
		if(cookiesValue==null || cookiesValue.length()==0){
			result.addProperty("error", "No session cookie in the request."); 
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.BAD_REQUEST);
		}
		
		ADFSTokens tokens = tokenService.getToken(cookiesValue, null);
		
		if(tokens==null){
			result.addProperty("error", "No adfs token available in this session ("+cookiesValue+")"); 
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.UNAUTHORIZED);
		}if(tokens.getRefreshToken()==null){
			result.addProperty("error", "The refresh_token is expired. please login again.");
        			
    		restTemplate.getForEntity(logoutUrl, String.class);
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.UNAUTHORIZED);
		}else{
			
			result.addProperty("upn", tokens.getUpn());
			result.addProperty("client", tokens.getResource());
			result.addProperty("session", cookiesValue);
		
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.OK);
		}	
	}
	
	@GetMapping(value="/refresh", produces = MediaType.TEXT_PLAIN_VALUE)
	public ResponseEntity<String> getIdToken(HttpServletRequest request) {
		
		HttpHeaders headers = new HttpHeaders();
		headers.add("Access-Control-Allow-Origin", webConfig.getAllowedOrigin());	
		headers.add("Access-Control-Allow-Credentials", "true");
		headers.add("Access-Control-Allow-Methods", "*");
		
		String cookiesValue = CookieUtils.getCookieValue(request, "JSESSIONID");
		log.info(">>>session cookie>>> "+cookiesValue);
		String result = "";
		
		if(cookiesValue==null || cookiesValue.length()==0){
			result = "error : No session cookie in the request."; 
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.BAD_REQUEST);
		}
		ADFSTokens tokens = tokenService.getToken(cookiesValue, null);
		
		if(tokens==null){
			result = "error : No adfs token available in this session ("+cookiesValue+")"; 
			return new ResponseEntity<>(result, headers, HttpStatus.BAD_REQUEST);
		}else if(tokens.getRefreshToken()==null){
			result = "error : The refresh_token is expired. please login again.";
        			
    		restTemplate.getForEntity(logoutUrl, String.class);
			return new ResponseEntity<>(result, headers, HttpStatus.BAD_REQUEST);
		}else{
		
			log.info("tokens >>> "+tokens+"   "+tokens.getRefreshToken());
		
			String idToken = tokenService.refreshIdToken(tokens.getRefreshToken());
		
			log.info("idToken == "+idToken);
		
			return new ResponseEntity<>(idToken.toString(), headers, HttpStatus.OK);

		}	

	}
	
	@GetMapping(value="/forward")
	public void forwardRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		response.setHeader("Access-Control-Allow-Origin", webConfig.getAllowedOrigin());	
		response.setHeader("Access-Control-Allow-Credentials", "true");
		response.setHeader("Access-Control-Allow-Methods", "*");
		
		String newUrl = request.getParameter("target");
    	String method = request.getParameter("method");
    	
		String cookiesValue = CookieUtils.getCookieValue(request, "JSESSIONID");
		log.info(">>>session cookie>>> "+cookiesValue);
		
		if(cookiesValue==null || cookiesValue.length()==0){
			response.setContentType(MediaType.TEXT_PLAIN_VALUE);
    		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getOutputStream().write("The 'target' header is mandatory.".getBytes());
    		return; 
		}
				
		String adfsToken = null;
		ADFSTokens tokens = tokenService.getToken(cookiesValue, null);
    	
    	if(newUrl == null){
    		response.setContentType(MediaType.TEXT_PLAIN_VALUE);
    		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			response.getOutputStream().write("The 'target' header is mandatory.".getBytes());
    		return; 
    	}
    	if(method == null){
    		response.setContentType(MediaType.TEXT_PLAIN_VALUE);
    		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			response.getOutputStream().write("The 'method' header is mandatory.".getBytes());
    		return; 
    	}
				
		if(tokens==null){
			log.info("error : There is not adfs token available for in this session "+cookiesValue); 
		}else if(tokens.getRefreshToken()==null){
			log.info("error : The refresh_token is expired. please login again."); 
					
    		restTemplate.getForEntity(logoutUrl, String.class);
		}else{
		
			log.info("tokens >>> "+tokens+"   "+tokens.getRefreshToken());
		
			adfsToken = tokenService.refreshIdToken(tokens.getRefreshToken());
		
			log.info("idToken == "+adfsToken);
		}	
		
		if(adfsToken == null ){
			response.setContentType(MediaType.TEXT_PLAIN_VALUE);
    		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getOutputStream().write("error : The refresh_token is expired. please login again.".getBytes());
			return;
		}
		
		
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer "+adfsToken);
				
	    HttpEntity <String> entity = new HttpEntity<String>(headers);
	    
	    ResponseEntity<Resource> responseEntity = restTemplate.exchange( newUrl, HttpMethod.GET, entity, Resource.class );

	    MediaType contentType = responseEntity.getHeaders().getContentType();
	    
	    
	    
	    InputStream responseInputStream;
	    try {
	        responseInputStream = responseEntity.getBody().getInputStream();
	    }
	    catch (IOException e) {
	    	response.setContentType(MediaType.TEXT_PLAIN_VALUE);
    		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			response.getOutputStream().write(("Get Remote Resource Error."+e.getMessage()).getBytes());
			return;
	    }
	      
	    response.setContentType(contentType.getType());
		response.setStatus(HttpServletResponse.SC_OK);
		IOUtils.copy(responseInputStream, response.getOutputStream());
	
	}
	
	@GetMapping(value="/invalidate", produces = MediaType.TEXT_HTML_VALUE)
	public ResponseEntity<Object> invalidate(HttpServletRequest request) throws URISyntaxException {
		
		String cookiesValue = CookieUtils.getCookieValue(request, "JSESSIONID");
		
		if(cookiesValue!=null){
			tokenService.evictSingleToken(cookiesValue);
		}
			
		restTemplate.getForEntity(logoutUrl, String.class);
		
		String redirectUrl = null;
		
		if (!request.getParameterMap().containsKey("noRedirect")) {        
        	redirectUrl = request.getHeader("Referer");
        	if(redirectUrl==null){
        		redirectUrl = request.getParameter("redirect");
        	}	
        }	
        
        if(redirectUrl!=null && redirectUrl.length()>0){ 
        
	        URI url = new URI(redirectUrl);
	        
	        HttpHeaders httpHeaders = new HttpHeaders();
	        httpHeaders.setLocation(url);
	        	        
	        return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
        
        }else{
        	String message = "Logged out ADFS. <br/><hr/> "+"session:("+cookiesValue+")";
        	return ResponseEntity.accepted().body(message);
        }
	}	
	


}

