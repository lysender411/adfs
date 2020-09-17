package ca.toronto.api.oidc.utils;

import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HeaderLogUtil {

	public static Map<String, String> getHeaderAttributesMap(HttpServletRequest request) {
		Map<String, String> headerMap = new HashMap<>();
		Enumeration<?> requestHeaderNames = request.getHeaderNames();
		while (requestHeaderNames.hasMoreElements()) {
			String requestHeaderName = (String) requestHeaderNames.nextElement();
			String requestParamValue = request.getHeader(requestHeaderName);
			;
			headerMap.put(requestHeaderName, requestParamValue);
		}
		return headerMap;
	}

	public static Map<String, String> getHeaderAttributesMap(HttpServletResponse response) {
		Map<String, String> headerMap = new HashMap<>();
		Collection<String> responseHeaderNames = response.getHeaderNames();
		for (String headerName : responseHeaderNames) {
			String headerValue = response.getHeader(headerName);
			headerMap.put(headerName, headerValue);
		}
		return headerMap;
	}

}
