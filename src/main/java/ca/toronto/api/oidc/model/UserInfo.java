/**
 * 
 */
package ca.toronto.api.oidc.model;


public class UserInfo {
	private String user;
	private String pwd;
	private String app;
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	public String getPwd() {
		return pwd;
	}
	public void setPwd(String pwd) {
		this.pwd = pwd;
	}
	public String getApp() {
		return app;
	}
	public void setApp(String app) {
		this.app = app;
	}

	
}
