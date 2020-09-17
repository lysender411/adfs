package ca.toronto.api.oidc.utils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

public class RequestLoggingFilter extends OncePerRequestFilter {

	private boolean includeResponsePayload = true;
	private boolean includeRequestHeader = true;
	private boolean includeResponseHeader = true;

	private int maxPayloadLength = 8192;
	private static Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);

	public void setPayloadSizeLimit(int payloadLogLimit) {
		this.maxPayloadLength = payloadLogLimit;
	}

	public int getPayloadSizeLimit() {
		return maxPayloadLength;
	}

	private String getContentAsString(byte[] buf, int maxLength, String charsetName) {
		if (buf == null || buf.length == 0)
			return "";
		int length = Math.min(buf.length, this.maxPayloadLength);
		try {
			return new String(buf, 0, length, charsetName);
		} catch (UnsupportedEncodingException ex) {
			return "Unsupported Encoding";
		}
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!logger.isInfoEnabled()) {
			filterChain.doFilter(request, response); 
			return;
		}
		long startTime = System.currentTimeMillis();
		StringBuilder reqInfo = new StringBuilder().append("[").append(startTime % 10000) // request ID
				.append("] ").append(request.getMethod()).append(" ").append(request.getRequestURL());

		String queryString = request.getQueryString();
		if (queryString != null) {
			reqInfo.append("?").append(queryString);
		}

		logger.info("Incoming request START PROCESSING: {}", reqInfo.toString());

		ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request);
		ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);

		try {
			filterChain.doFilter(wrappedRequest, wrappedResponse);
		} finally {
			try {
				long duration = System.currentTimeMillis() - startTime;
				if (logger.isInfoEnabled() && !logger.isDebugEnabled()) {
					logger.info("Incoming request PROCESSED: {} STATUS={} IN {} ms. ", reqInfo.toString(),
							response.getStatus(), duration);
				}
				if (logger.isDebugEnabled()) {
					String requestHeaders = "Omitted...";
					if (includeRequestHeader) {
						requestHeaders = String.valueOf(HeaderLogUtil.getHeaderAttributesMap(request));
					}
					String responseHeaders = "Omitted...";
					if (includeResponseHeader) {
						responseHeaders = String.valueOf(HeaderLogUtil.getHeaderAttributesMap(response));
					}
					String requestBody = getContentAsString(wrappedRequest.getContentAsByteArray(),
							this.maxPayloadLength, request.getCharacterEncoding());
					if (requestBody.length() <= 0) {
						requestBody = "Not available";
					}
					String responseBody = "Omitted...";
					if (includeResponsePayload) {
						byte[] buf = wrappedResponse.getContentAsByteArray();
						responseBody = getContentAsString(buf, this.maxPayloadLength, response.getCharacterEncoding());
						if (responseBody.length() <= 0) {
							responseBody = "Not available";
						}
					}
					logger.debug(
							"Incoming request PROCESSED: \"{}\" STATUS={} IN {} ms. \nREQUEST HEADERS: {}\nREQUEST BODY:\n{}\nRESPONSE HEADERS: {}\nRESPONSE BODY:\n{}",
							reqInfo.toString(), response.getStatus(), duration, requestHeaders, requestBody,
							responseHeaders, responseBody);
				}
			} finally {
				wrappedResponse.copyBodyToResponse(); 
			}
		}
	}

}
