package ca.toronto.api.oidc.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OauthRequestWrapper extends HttpServletRequestWrapper{
	
	private static Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);
	
	private final String path = "https://config.cc.toronto.ca/eis_upload/";
	
	private String redirectUrl = "";

	public OauthRequestWrapper(HttpServletRequest request) {
		super(request);
		redirectUrl = path+request.getRequestURI();
		
	}
	
	@Override
	public StringBuffer getRequestURL() {
		String uri = super.getRequestURI();
log.info("requestURI >>> "+redirectUrl+"    "+uri);
        return new StringBuffer(redirectUrl);
    }	        	
        	
}
