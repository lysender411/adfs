package ca.toronto.api.oidc.model;

public class ADFSTokens {

//	private String authCode;
//	private String accessToken;
	private String upn;
//	private String idToken;
	private String refreshToken;
	private String resource;
//	private int expireIn;
	
	public ADFSTokens(String upn, String clientId){
		this.upn = upn;
		this.resource = clientId;
		refreshToken = null;
	}
  
	public ADFSTokens(String upn, String refreshToken, String resource) {
//		this.authCode = authCode;
//		this.accessToken = accessToken;
//		this.idToken = idToken;
		this.upn = upn;
		this.refreshToken = refreshToken;
		this.resource = resource;
//		this.expireIn = expireIn;
	}
/*
	public String getAuthCode() {
		return authCode;
	}
	public void setAuthCode(String authCode) {
		this.authCode = authCode;
	}
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	
	public String getIdToken() {
		return idToken;
	}
	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}
*/
	public String getUpn() {
		return upn;
	}
	public void setUpn(String upn) {
		this.upn = upn;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}	
	public String getResource() {
		return resource;
	}
	public void setResource(String resource) {
		this.resource = resource;
	}
/*	
	public int getExpireIn() {
		return expireIn;
	}
	public void setExpireIn(int expireIn) {
		this.expireIn = expireIn;
	}
*/
  

}