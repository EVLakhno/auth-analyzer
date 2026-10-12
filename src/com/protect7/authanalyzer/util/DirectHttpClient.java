package com.protect7.authanalyzer.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import burp.IHttpService;

/**
 * Sends a raw HTTP request over a fresh, dedicated TCP connection and reads the
 * full response, bypassing Burp's connection pool and Platform Authentication.
 *
 * This is required for per-connection Kerberos Negotiate (IIS / Windows
 * Integrated Authentication): once a pooled keep-alive connection has been
 * authenticated as one identity, the server answers every further request on
 * that connection as that identity and ignores a different Authorization
 * header. Opening a new connection with "Connection: close" guarantees that the
 * minted low-privileged token is the identity the server actually sees.
 *
 * TLS certificates are not validated (same stance as Burp's own interception);
 * this tool is used for authorized security testing.
 *
 * @author Auth Analyzer
 */
public class DirectHttpClient {

	private static volatile SSLSocketFactory trustAllFactory;

	public static byte[] send(IHttpService service, byte[] request, int timeoutMillis) throws IOException {
		String host = service.getHost();
		int port = service.getPort();
		boolean https = "https".equalsIgnoreCase(service.getProtocol());
		Socket socket = null;
		try {
			if (https) {
				SSLSocket sslSocket = (SSLSocket) getTrustAllFactory().createSocket();
				// Set SNI so name based virtual hosts / IIS bindings resolve correctly.
				SSLParameters params = sslSocket.getSSLParameters();
				try {
					params.setServerNames(Collections.singletonList(new SNIHostName(host)));
					sslSocket.setSSLParameters(params);
				} catch (IllegalArgumentException ignored) {
					// Host not valid as SNI (e.g. an IP) - continue without it.
				}
				sslSocket.connect(new InetSocketAddress(host, port), timeoutMillis);
				sslSocket.setSoTimeout(timeoutMillis);
				sslSocket.startHandshake();
				socket = sslSocket;
			} else {
				socket = new Socket();
				socket.connect(new InetSocketAddress(host, port), timeoutMillis);
				socket.setSoTimeout(timeoutMillis);
			}

			OutputStream out = socket.getOutputStream();
			out.write(request);
			out.flush();

			InputStream in = socket.getInputStream();
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			byte[] chunk = new byte[8192];
			int read;
			while ((read = in.read(chunk)) != -1) {
				buffer.write(chunk, 0, read);
			}
			return buffer.toByteArray();
		} finally {
			if (socket != null) {
				try {
					socket.close();
				} catch (IOException ignored) {
				}
			}
		}
	}

	private static SSLSocketFactory getTrustAllFactory() throws IOException {
		SSLSocketFactory factory = trustAllFactory;
		if (factory == null) {
			synchronized (DirectHttpClient.class) {
				factory = trustAllFactory;
				if (factory == null) {
					try {
						TrustManager[] trustAll = new TrustManager[] { new X509TrustManager() {
							@Override
							public void checkClientTrusted(X509Certificate[] chain, String authType) {
							}

							@Override
							public void checkServerTrusted(X509Certificate[] chain, String authType) {
							}

							@Override
							public X509Certificate[] getAcceptedIssuers() {
								return new X509Certificate[0];
							}
						} };
						SSLContext context = SSLContext.getInstance("TLS");
						context.init(null, trustAll, new SecureRandom());
						factory = context.getSocketFactory();
						trustAllFactory = factory;
					} catch (Exception e) {
						throw new IOException("Cannot initialize TLS socket factory: " + e.getMessage(), e);
					}
				}
			}
		}
		return factory;
	}
}
