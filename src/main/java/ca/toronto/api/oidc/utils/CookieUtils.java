package ca.toronto.api.oidc.utils;

import java.util.Arrays;
import java.util.stream.Collectors;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class CookieUtils {
	
	public static String getCookieValue(HttpServletRequest request, String cookieName){
		
		String cookieValue = null;
		
		Cookie[] cookies = request.getCookies();
		
		if(cookies != null){
		
			for(int i=0; i<cookies.length; i++){
				if(cookies[i].getName().equalsIgnoreCase(cookieName)){
					cookieValue = cookies[i].getValue();
				}
			}
		}	

	    return cookieValue;		
	}
	
	public static String getAllCookies(HttpServletRequest request){
		
		Cookie[] cookies = request.getCookies();
		
	    if (cookies != null) {
	        return Arrays.stream(cookies)
	                .map(c -> c.getName() + "=" + c.getValue())
	                .collect(Collectors.joining(", "));
	    }

	    return "No preferences found!";
		
	}

}
