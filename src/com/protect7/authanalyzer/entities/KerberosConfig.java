package com.protect7.authanalyzer.entities;

/**
 * Holds the Kerberos / SPNEGO configuration for a single session.
 *
 * When enabled, Auth Analyzer does not statically replace the "Authorization"
 * header of the repeated request. Instead a fresh "Authorization: Negotiate ..."
 * token is minted per request through the GSS-API (see
 * {@link com.protect7.authanalyzer.util.KerberosTokenMinter}). This makes the
 * plugin usable against applications that expect pure per-request Kerberos
 * Negotiate authentication, where a static token would be rejected (one-time,
 * timestamp bound) and auto-extraction from responses is impossible (the token
 * is generated client side and never returned by the server).
 *
 * @author Auth Analyzer
 */
public class KerberosConfig {

	public enum CredentialSource {
		PASSWORD, CCACHE, KEYTAB
	}

	private boolean enabled = false;
	private CredentialSource credentialSource = CredentialSource.PASSWORD;
	// Username / password (credentialSource == PASSWORD). The realm is taken from the domain / krb5 settings.
	private String username = "";
	private String password = "";
	// Persist the password in the Burp configuration. When false the password is kept in memory only.
	private boolean savePassword = false;
	// Path to the Kerberos credential cache (ccache) when credentialSource == CCACHE
	private String ccachePath = "";
	// Path to the keytab file when credentialSource == KEYTAB
	private String keytabPath = "";
	// Client (user) principal, e.g. lowpriv@EXAMPLE.COM. Optional for ccache, required for keytab.
	private String principal = "";
	// Derive the service principal name from the target host (HTTP@<host>) instead of using a fixed SPN.
	private boolean deriveSpnFromHost = true;
	// Service class used to build the host based SPN (defaults to HTTP).
	private String serviceClass = "HTTP";
	// Fixed service principal name used when deriveSpnFromHost == false, e.g. HTTP/host.example.com@EXAMPLE.COM
	private String servicePrincipalName = "";
	// Wrap the Kerberos AP-REQ in a SPNEGO token (standard for HTTP Negotiate). If false a raw Kerberos token is sent.
	private boolean useSpnego = true;
	private boolean requestMutualAuth = false;
	private boolean requestCredDeleg = false;
	// Send the repeated request over a fresh, dedicated connection (Connection: close), bypassing
	// Burp's connection pool and Platform Authentication. Required for per-connection Negotiate (IIS /
	// Windows Integrated Auth), where a pooled connection stays authenticated as the first identity.
	private boolean directConnection = true;
	// Optional overrides so the extension works without a system wide krb5.conf.
	private String krb5ConfPath = "";
	private String realm = "";
	private String kdc = "";
	// Re-acquire the Subject (log in again) after this many seconds. <= 0 disables periodic re-login.
	private int reloginIntervalSeconds = 300;

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public CredentialSource getCredentialSource() {
		return credentialSource == null ? CredentialSource.PASSWORD : credentialSource;
	}

	public void setCredentialSource(CredentialSource credentialSource) {
		this.credentialSource = credentialSource;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public boolean isSavePassword() {
		return savePassword;
	}

	public void setSavePassword(boolean savePassword) {
		this.savePassword = savePassword;
	}

	public String getCcachePath() {
		return ccachePath;
	}

	public void setCcachePath(String ccachePath) {
		this.ccachePath = ccachePath;
	}

	public String getKeytabPath() {
		return keytabPath;
	}

	public void setKeytabPath(String keytabPath) {
		this.keytabPath = keytabPath;
	}

	public String getPrincipal() {
		return principal;
	}

	public void setPrincipal(String principal) {
		this.principal = principal;
	}

	public boolean isDeriveSpnFromHost() {
		return deriveSpnFromHost;
	}

	public void setDeriveSpnFromHost(boolean deriveSpnFromHost) {
		this.deriveSpnFromHost = deriveSpnFromHost;
	}

	public String getServiceClass() {
		return (serviceClass == null || serviceClass.trim().isEmpty()) ? "HTTP" : serviceClass;
	}

	public void setServiceClass(String serviceClass) {
		this.serviceClass = serviceClass;
	}

	public String getServicePrincipalName() {
		return servicePrincipalName;
	}

	public void setServicePrincipalName(String servicePrincipalName) {
		this.servicePrincipalName = servicePrincipalName;
	}

	public boolean isUseSpnego() {
		return useSpnego;
	}

	public void setUseSpnego(boolean useSpnego) {
		this.useSpnego = useSpnego;
	}

	public boolean isRequestMutualAuth() {
		return requestMutualAuth;
	}

	public void setRequestMutualAuth(boolean requestMutualAuth) {
		this.requestMutualAuth = requestMutualAuth;
	}

	public boolean isRequestCredDeleg() {
		return requestCredDeleg;
	}

	public void setRequestCredDeleg(boolean requestCredDeleg) {
		this.requestCredDeleg = requestCredDeleg;
	}

	public boolean isDirectConnection() {
		return directConnection;
	}

	public void setDirectConnection(boolean directConnection) {
		this.directConnection = directConnection;
	}

	public String getKrb5ConfPath() {
		return krb5ConfPath;
	}

	public void setKrb5ConfPath(String krb5ConfPath) {
		this.krb5ConfPath = krb5ConfPath;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public String getKdc() {
		return kdc;
	}

	public void setKdc(String kdc) {
		this.kdc = kdc;
	}

	public int getReloginIntervalSeconds() {
		return reloginIntervalSeconds;
	}

	public void setReloginIntervalSeconds(int reloginIntervalSeconds) {
		this.reloginIntervalSeconds = reloginIntervalSeconds;
	}

	/**
	 * @return a deep copy of this configuration (used when cloning a session).
	 */
	public KerberosConfig copy() {
		KerberosConfig copy = new KerberosConfig();
		copy.enabled = this.enabled;
		copy.credentialSource = this.getCredentialSource();
		copy.username = this.username;
		copy.password = this.password;
		copy.savePassword = this.savePassword;
		copy.ccachePath = this.ccachePath;
		copy.keytabPath = this.keytabPath;
		copy.principal = this.principal;
		copy.deriveSpnFromHost = this.deriveSpnFromHost;
		copy.serviceClass = this.serviceClass;
		copy.servicePrincipalName = this.servicePrincipalName;
		copy.useSpnego = this.useSpnego;
		copy.requestMutualAuth = this.requestMutualAuth;
		copy.requestCredDeleg = this.requestCredDeleg;
		copy.directConnection = this.directConnection;
		copy.krb5ConfPath = this.krb5ConfPath;
		copy.realm = this.realm;
		copy.kdc = this.kdc;
		copy.reloginIntervalSeconds = this.reloginIntervalSeconds;
		return copy;
	}
}
