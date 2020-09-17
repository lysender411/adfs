package ca.toronto.api.oidc.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import ca.toronto.api.oidc.model.ADFSTokens;
import ca.toronto.api.oidc.service.ADFSTokenService;
import ca.toronto.api.oidc.utils.CookieUtils;

@CrossOrigin(origins = "*", maxAge = 3600)
@Controller
@RequestMapping(value = { "/client" }) 
public class ClientController {
	private static Logger log = LoggerFactory.getLogger(ClientController.class);
	
	@Autowired
	ADFSTokenService tokenService;

	@GetMapping(value="/login", produces=MediaType.TEXT_HTML_VALUE)
	public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String referrer = request.getHeader("Referer");
	    request.getSession().setAttribute("referrer", referrer);
		
		response.sendRedirect("http://d1xd0146797.wkstn.toronto.ca:9018/join/oauth2/authorization/adfs");
    } 
	
	@GetMapping("/logout")
    public String exit(HttpServletRequest request, HttpServletResponse response) {
        new SecurityContextLogoutHandler().logout(request, null, null);
        return "logged out.";
    }
	
	@GetMapping(value="/refresh", produces = MediaType.TEXT_PLAIN_VALUE)
	public String getIdToken(HttpServletRequest request) {
		
		String cookiesValue = CookieUtils.getCookieValue(request, "JSESSIONID");
		log.info(">>>session cookie>>> "+cookiesValue);
		
		return cookiesValue;
/*		
		ADFSTokens tokens = tokenService.getToken(cookiesValue, null);
		
		if(tokens==null){
			return "error : There is not adfs token available for "+cookiesValue; 
		}if(tokens.getRefreshToken()==null){
			return "error : There is not refresh token available for "+cookiesValue; 
		}else{
		
			log.info("tokens >>> "+tokens+"   "+tokens.getRefreshToken());
		
			String idToken = tokenService.refreshIdToken(tokens.getRefreshToken());
		
			log.info("idToken == "+idToken);
		
			return idToken+"  "+cookiesValue;
		}	
*/
	}
    
}
