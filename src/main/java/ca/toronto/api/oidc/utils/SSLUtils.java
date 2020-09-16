/**
 * 
 */
package ca.toronto.api.oidc.utils;


import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public final class SSLUtils {

	private static final HostnameVerifier jvmHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();

	private static final HostnameVerifier trivialHostnameVerifier = new HostnameVerifier() {
		public boolean verify(String hostname, SSLSession sslSession) {
			return hostname.equalsIgnoreCase(sslSession.getPeerHost());
		}
	};
/*
	private static final TrustManager[] UNQUESTIONING_TRUST_MANAGER = new TrustManager[] { new X509TrustManager() {
		@edu.umd.cs.findbugs.annotations.SuppressWarnings("WEAK_TRUST_MANAGER")
		public java.security.cert.X509Certificate[] getAcceptedIssuers() {
			return null;
		}
		@edu.umd.cs.findbugs.annotations.SuppressWarnings("WEAK_TRUST_MANAGER")
		public void checkClientTrusted(X509Certificate[] certs, String authType) {
		}
		@edu.umd.cs.findbugs.annotations.SuppressWarnings("WEAK_TRUST_MANAGER")
		public void checkServerTrusted(X509Certificate[] certs, String authType) {
		}
	} };

	public static void turnOffSslChecking() throws NoSuchAlgorithmException, KeyManagementException {
		HttpsURLConnection.setDefaultHostnameVerifier(trivialHostnameVerifier);
		// Install the all-trusting trust manager
		SSLContext sc = SSLContext.getInstance("TLSv1.2");
		sc.init(null, UNQUESTIONING_TRUST_MANAGER, null);
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	}

	public static void turnOnSslChecking() throws KeyManagementException, NoSuchAlgorithmException {
		HttpsURLConnection.setDefaultHostnameVerifier(jvmHostnameVerifier);
		// Return it to the initial state (discovered by reflection, now hardcoded)
		SSLContext sc = SSLContext.getInstance("TLSv1.2");
		sc.init(null, null, null);
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	}

	private SSLUtils() {
		throw new UnsupportedOperationException("Do not instantiate libraries.");
	}
*/	
}