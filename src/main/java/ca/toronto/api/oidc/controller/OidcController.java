/**
 * 
 */
package ca.toronto.api.oidc.controller;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ca.toronto.api.oidc.config.WebServiceConfig;
import ca.toronto.api.oidc.model.ADFSTokens;
import ca.toronto.api.oidc.model.UserInfo;
import ca.toronto.api.oidc.service.ADFSTokenService;
import ca.toronto.api.oidc.utils.CookieUtils;

@SuppressWarnings("deprecation")
@RestController
@RequestMapping(value = { "/oidc" }) 
public class OidcController {
	private static Logger log = LoggerFactory.getLogger(OidcController.class);
	
	@Autowired
	ADFSTokenService tokenService;
	
	@Autowired
	RestTemplate restTemplate;
	
	@Autowired
	private WebServiceConfig webConfig;
	
	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;

	@GetMapping(value = { "/token" }, produces = MediaType.TEXT_PLAIN_VALUE)
	public String auth(){

		return "token ...";
	}
	
	@GetMapping(value = { "/redirect1" }, produces = MediaType.TEXT_PLAIN_VALUE)
	public void redirect1(HttpServletResponse response) throws IOException{
		
		try {
            String ip = InetAddress.getLocalHost().getHostAddress();
            System.out.printf("%s", ip);
        } catch (Exception e) {
            log.error("redirect error",e);
        }
		
		response.sendRedirect("token");
	}
	
	@GetMapping(value = { "/redirect2" }, produces = MediaType.TEXT_PLAIN_VALUE)
	public void redirect2(HttpServletResponse response) throws IOException{
		response.sendRedirect("https://config.cc.toronto.ca/eis_oidc/oidc/token");
	}


	@PostMapping(value = { "/token" }, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getToken(@RequestBody(required = true) UserInfo userInfo) throws JsonProcessingException {
		
		String result = null;
		
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-Type", "application/x-www-form-urlencoded");

		MultiValueMap<String, String> map= new LinkedMultiValueMap<>();
		map.add("grant_type", "password");
		map.add("username", "child\\"+userInfo.getUser());
		map.add("password", userInfo.getPwd());
		map.add("client_id", tokenService.getClientId());
		map.add("response_mode", "fragment");
		map.add("client_secret", tokenService.getClientSecret());
		
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

		ResponseEntity<String> res = null;
		String authUrl = tokenService.getTokenUrl();
		if (authUrl != null && request != null) {
			try {
				res = restTemplate.postForEntity(authUrl, request, String.class);

			} catch (Exception e) {
				log.error(e.getLocalizedMessage());
			}
		}
		if (res != null && (res.getStatusCodeValue() >= 200 && res.getStatusCodeValue() < 300)) {
			result = res.getBody();
		} else {
			log.error(String.format("Failed to retrieve from %s", authUrl));
			log.error("fail "+tokenService.getTokenUrl());
		}

		return result;
		
	}
	
	@SuppressWarnings("unchecked")
	@PostMapping(value = { "/id_token" }, produces = MediaType.TEXT_PLAIN_VALUE)
	public String getIdToken(@RequestBody(required = true) UserInfo userInfo) throws JsonProcessingException {
		
		String result = null;
		
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-Type", "application/x-www-form-urlencoded");

		MultiValueMap<String, String> map= new LinkedMultiValueMap<>();
		map.add("grant_type", "password");
		map.add("username", "child\\"+userInfo.getUser());
		map.add("password", userInfo.getPwd());
		map.add("client_id", tokenService.getClientId());
		map.add("response_mode", "fragment");
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

		ResponseEntity<String> res = null;
		try {
			res = restTemplate.postForEntity(tokenService.getTokenUrl(), request, String.class);

		} catch (Exception e) {
			log.error(e.getLocalizedMessage());
		}

		if (res != null && (res.getStatusCodeValue() >= 200 && res.getStatusCodeValue() < 300)) {
			result = res.getBody();
			
			Map<String,String> tokens = new HashMap<String,String>();
			tokens = new Gson().fromJson(result, tokens.getClass());
			
			result = tokens.get("id_token");
			
			String refreshToken = tokens.get("refresh_token");
			String cid = tokens.get("resource");
			
//			tokenService.updateToken(result, refreshToken, cid);
			
			
		} else {
			log.error(String.format("Failed to retrieve from %s", tokenService.getTokenUrl()));
		}

		return result;
		
	}

	@SuppressWarnings("unchecked")
	@PostMapping(value = { "/user_claims" }, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getUserClaim(@RequestBody(required = true) UserInfo userInfo) throws JsonProcessingException {
		
		String result = null;
		
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-Type", "application/x-www-form-urlencoded");

		MultiValueMap<String, String> map= new LinkedMultiValueMap<>();
		map.add("grant_type", "password");
		map.add("username", "child\\"+userInfo.getUser());
		map.add("password", userInfo.getPwd());
		map.add("client_id", tokenService.getClientId());
		map.add("response_mode", "fragment");
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

		String authUrl = tokenService.getTokenUrl();
		ResponseEntity<String> res = null;
		if (authUrl != null && request != null) {
			try {
				res = restTemplate.postForEntity(authUrl, request, String.class);
			} catch (Exception e) {
				log.error(e.getLocalizedMessage());
			}
		}
		if (res != null && (res.getStatusCodeValue() >= 200 && res.getStatusCodeValue() < 300)) {
			result = res.getBody();
			
			Map<String,String> tokens = new HashMap<String,String>();
			tokens = new Gson().fromJson(result, tokens.getClass());
			
			result = tokens.get("id_token");
			
			String[] claims = result.split("\\.");
			result = StringEscapeUtils.unescapeJava(new String(Base64.decodeBase64(claims[1]), Charsets.UTF_8));

			
		} else {
			log.error(String.format("Failed to retrieve from %s", authUrl));
		}

		return result;
		
	}
	
	@GetMapping(value = { "/user_claims/{id_token}" }, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getUserClaimFromToken(@PathVariable String id_token) throws JsonProcessingException {
		
		String result = null;
	
		String[] claims = id_token.split("\\.");
		result = StringEscapeUtils.unescapeJava(new String(Base64.decodeBase64(claims[1]), Charsets.UTF_8));

		return result;		
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
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.BAD_REQUEST);
		}else if(tokens.getRefreshToken()==null){
			result = "error : No refresh token available in this session ("+cookiesValue+")";
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.BAD_REQUEST);
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
			log.info("error : There is not refresh token available in this session "+cookiesValue); 
		}else{
		
			log.info("tokens >>> "+tokens+"   "+tokens.getRefreshToken());
		
			adfsToken = tokenService.refreshIdToken(tokens.getRefreshToken());
		
			log.info("idToken == "+adfsToken);
		}	
		
		if(adfsToken == null ){
			response.setContentType(MediaType.TEXT_PLAIN_VALUE);
    		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getOutputStream().write("No ADFS token available.".getBytes());
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
			result.addProperty("error", "No refresh token available in this session ("+cookiesValue+")");
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.UNAUTHORIZED);
		}else{
			
			result.addProperty("upn", tokens.getUpn());
			result.addProperty("client", tokens.getResource());
			result.addProperty("session", cookiesValue);
		
			return new ResponseEntity<>(result.toString(), headers, HttpStatus.OK);
		}	
	}
/*	
	@RequestMapping(value = "/proxy/**")
    public String proxy(@RequestBody(required = false) String body, HttpMethod method, HttpServletRequest request, HttpServletResponse response,
                        @RequestHeader HttpHeaders headers) throws ServletException, IOException, URISyntaxException {

        body = body == null ? "" : body;
        String path = request.getRequestURI();
        String query = request.getQueryString(); 
        path = path.replaceAll("proxy", "");
        StringBuffer urlBuilder = new StringBuffer("gatewayUrl");
        if (path != null) {
            urlBuilder.append(path);
        }
        if (query != null) {
            urlBuilder.append('?');
            urlBuilder.append(query);
        }
        URI url = new URI(urlBuilder.toString());
        if (log.isInfoEnabled()) {
            log.info("url: {} ", url);
            log.info("method: {} ", method);
            log.info("body: {} ", body);
            log.info("headers: {} ", headers);
        }
        ResponseEntity<String> responseEntity
                = oAuth2RestTemplate.exchange(url, method, new HttpEntity<String>(body, headers), String.class);
        return responseEntity.getBody();
    }
*/		
	@GetMapping(value="/authorize", produces = MediaType.TEXT_HTML_VALUE)
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
        	errorMsg += "no refresh_token in authorizedClient. ";
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
        
        String redirectUrl = null;
        
        redirectUrl = request.getHeader("Referer");
        if(redirectUrl==null){
        	redirectUrl = request.getParameter("redirect");
        }	
        
        if(redirectUrl!=null && redirectUrl.length()>0){ 
        
	        URI url = new URI(redirectUrl);

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

}

