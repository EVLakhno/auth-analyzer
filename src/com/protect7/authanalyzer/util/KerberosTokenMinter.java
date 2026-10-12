package com.protect7.authanalyzer.util;

import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.protect7.authanalyzer.entities.KerberosConfig;

import burp.BurpExtender;

/**
 * Mints a fresh "Authorization: Negotiate ..." header per request through the
 * GSS-API, using a Subject obtained from a Kerberos credential cache (ccache)
 * or keytab.
 *
 * This is the piece that lets Auth Analyzer work against applications that use
 * pure per-request Kerberos Negotiate authentication. A static token cannot be
 * replayed (it is one time and timestamp bound) and the token is never returned
 * in a response (it is generated client side via GSS), so neither the static
 * header replacement nor the auto-extract feature of the plugin can produce it.
 * This class produces a new AP-REQ (optionally SPNEGO wrapped) on every call.
 *
 * JDK note: Burp 2+ ships with a bundled JRE that has parts of the Kerberos
 * stack stripped out. Run Burp on a full JDK (java -jar burp.jar) so that the
 * {@code com.sun.security.auth.module.Krb5LoginModule} and the GSS mechanisms
 * are available. This is the same gotcha that affected the Berserko extension.
 *
 * @author Auth Analyzer
 */
public class KerberosTokenMinter {

	private static final String KRB5_MECH_OID = "1.2.840.113554.1.2.2";
	private static final String SPNEGO_MECH_OID = "1.3.6.1.5.5.2";
	// Referenced by name so the extension still compiles on non Sun/Oracle JDKs.
	private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

	private final KerberosConfig config;
	private Subject subject = null;
	private long subjectAcquiredAt = 0;
	private volatile String lastError = null;

	public KerberosTokenMinter(KerberosConfig config) {
		this.config = config;
	}

	/**
	 * @return a value for the Authorization header ("Negotiate &lt;base64&gt;")
	 *         or {@code null} if the token could not be minted. On failure the
	 *         reason is available through {@link #getLastError()}.
	 */
	public synchronized String mintNegotiateHeader(String host) {
		if (config == null || !config.isEnabled()) {
			return null;
		}
		if (host == null || host.trim().isEmpty()) {
			lastError = "No target host available to build the service principal name.";
			return null;
		}
		try {
			applySystemProperties();
			final Subject loginSubject = getSubject();
			final String spn = resolveSpn(host);
			final boolean hostBased = config.isDeriveSpnFromHost();
			final Oid mech = new Oid(config.isUseSpnego() ? SPNEGO_MECH_OID : KRB5_MECH_OID);
			final boolean mutualAuth = config.isRequestMutualAuth();
			final boolean credDeleg = config.isRequestCredDeleg();

			byte[] token = Subject.doAs(loginSubject, new PrivilegedExceptionAction<byte[]>() {
				@Override
				public byte[] run() throws Exception {
					GSSManager manager = GSSManager.getInstance();
					GSSName serverName = manager.createName(spn,
							hostBased ? GSSName.NT_HOSTBASED_SERVICE : GSSName.NT_USER_NAME, mech);
					GSSContext context = manager.createContext(serverName, mech, (GSSCredential) null,
							GSSContext.DEFAULT_LIFETIME);
					context.requestMutualAuth(mutualAuth);
					context.requestCredDeleg(credDeleg);
					byte[] out = context.initSecContext(new byte[0], 0, 0);
					context.dispose();
					return out;
				}
			});

			if (token == null || token.length == 0) {
				lastError = "GSS-API returned an empty token.";
				return null;
			}
			lastError = null;
			return "Negotiate " + Base64.getEncoder().encodeToString(token);
		} catch (Exception e) {
			// Force a fresh login on the next attempt (e.g. expired ticket).
			subject = null;
			lastError = rootMessage(e);
			BurpExtender.callbacks.printError("[" + Globals.EXTENSION_NAME + "] Kerberos token minting failed: " + lastError);
			return null;
		}
	}

	private Subject getSubject() throws Exception {
		long now = System.currentTimeMillis();
		long ttlMillis = (long) config.getReloginIntervalSeconds() * 1000L;
		boolean stale = ttlMillis > 0 && (now - subjectAcquiredAt) > ttlMillis;
		if (subject == null || stale) {
			LoginContext loginContext = new LoginContext("AuthAnalyzerKerberos", null, null, buildConfiguration());
			loginContext.login();
			subject = loginContext.getSubject();
			subjectAcquiredAt = now;
		}
		return subject;
	}

	private String resolveSpn(String host) {
		if (config.isDeriveSpnFromHost()) {
			return config.getServiceClass() + "@" + host;
		}
		return config.getServicePrincipalName();
	}

	private void applySystemProperties() {
		if (notEmpty(config.getKrb5ConfPath())) {
			System.setProperty("java.security.krb5.conf", config.getKrb5ConfPath().trim());
		}
		if (notEmpty(config.getRealm())) {
			System.setProperty("java.security.krb5.realm", config.getRealm().trim());
		}
		if (notEmpty(config.getKdc())) {
			System.setProperty("java.security.krb5.kdc", config.getKdc().trim());
		}
	}

	private Configuration buildConfiguration() {
		final Map<String, String> options = new HashMap<String, String>();
		options.put("doNotPrompt", "true");
		options.put("refreshKrb5Config", "true");
		options.put("isInitiator", "true");
		if (notEmpty(config.getPrincipal())) {
			options.put("principal", config.getPrincipal().trim());
		}
		if (config.getCredentialSource() == KerberosConfig.CredentialSource.KEYTAB) {
			options.put("useKeyTab", "true");
			options.put("storeKey", "true");
			if (notEmpty(config.getKeytabPath())) {
				options.put("keyTab", config.getKeytabPath().trim());
			}
		} else {
			options.put("useTicketCache", "true");
			options.put("renewTGT", "true");
			if (notEmpty(config.getCcachePath())) {
				options.put("ticketCache", config.getCcachePath().trim());
			}
		}
		final AppConfigurationEntry entry = new AppConfigurationEntry(KRB5_LOGIN_MODULE,
				AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
		return new Configuration() {
			@Override
			public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
				return new AppConfigurationEntry[] { entry };
			}
		};
	}

	public String getLastError() {
		return lastError;
	}

	public synchronized void invalidate() {
		subject = null;
		subjectAcquiredAt = 0;
	}

	private static boolean notEmpty(String s) {
		return s != null && !s.trim().isEmpty();
	}

	private static String rootMessage(Throwable t) {
		Throwable cause = t;
		while (cause.getCause() != null && cause.getCause() != cause) {
			cause = cause.getCause();
		}
		String message = cause.getMessage();
		return message == null ? cause.getClass().getName() : (cause.getClass().getSimpleName() + ": " + message);
	}
}
