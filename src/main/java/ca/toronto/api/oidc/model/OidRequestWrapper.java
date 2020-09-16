package ca.toronto.api.oidc.model;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;


public class OidRequestWrapper extends HttpServletRequestWrapper{
	
	private String newUrl = null;
	private String method = null;
    private String adfsToken = null;

    
    public OidRequestWrapper(final HttpServletRequest request, String at){
    	super(request);
    	newUrl = request.getHeader("target");
    	method = request.getHeader("method");
    	adfsToken = at;
    	
    }
   
    @Override
	public StringBuffer getRequestURL() {		
		return new StringBuffer(newUrl);
	}
    
    @Override
    public String getMethod(){
    	return method;
    }
    
    @Override
    public String getHeader(String name){
    	if("Authorization".equalsIgnoreCase(name)){
    		return "Bearer "+adfsToken;
    	}else{
    		return super.getHeader(name);
    	}
    }
}