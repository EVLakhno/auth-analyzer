package com.protect7.authanalyzer.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

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
		Socket socket = null;
		try {
			socket = openSocket(service, timeoutMillis);
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
			closeQuietly(socket);
		}
	}

	/** Result of an NTLM handshake: the final (Type 3) request and the server response. */
	public static class NtlmExchange {
		public final byte[] finalRequest;
		public final byte[] response;

		public NtlmExchange(byte[] finalRequest, byte[] response) {
			this.finalRequest = finalRequest;
			this.response = response;
		}
	}

	/**
	 * Performs a full per-request NTLM handshake over a single kept-alive
	 * connection (Type1 -> 401/Type2 -> Type3 -> response) and returns the final
	 * request and response.
	 */
	public static NtlmExchange sendNtlm(IHttpService service, List<String> baseHeaders, byte[] body, String domain,
			String user, String password, String workstation, int timeoutMillis) throws Exception {
		NtlmClient ntlm = new NtlmClient();
		byte[] type1 = ntlm.createType1Message();
		Socket socket = null;
		try {
			socket = openSocket(service, timeoutMillis);
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();

			byte[] req1 = buildRequest(baseHeaders, body, "NTLM " + Base64.getEncoder().encodeToString(type1), true);
			out.write(req1);
			out.flush();
			HttpResponse resp1 = readResponse(in);

			if (resp1.status != 401 || resp1.ntlmChallenge == null) {
				// No NTLM challenge returned (already authorized or scheme not offered).
				return new NtlmExchange(req1, resp1.raw);
			}
			byte[] type2 = Base64.getDecoder().decode(resp1.ntlmChallenge);
			byte[] type3 = ntlm.createType3Message(type1, type2, domain, user, password, workstation);
			byte[] req3 = buildRequest(baseHeaders, body, "NTLM " + Base64.getEncoder().encodeToString(type3), true);
			out.write(req3);
			out.flush();
			HttpResponse resp3 = readResponse(in);
			return new NtlmExchange(req3, resp3.raw);
		} finally {
			closeQuietly(socket);
		}
	}

	private static Socket openSocket(IHttpService service, int timeoutMillis) throws IOException {
		String host = service.getHost();
		int port = service.getPort();
		boolean https = "https".equalsIgnoreCase(service.getProtocol());
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
			return sslSocket;
		}
		Socket socket = new Socket();
		socket.connect(new InetSocketAddress(host, port), timeoutMillis);
		socket.setSoTimeout(timeoutMillis);
		return socket;
	}

	private static void closeQuietly(Socket socket) {
		if (socket != null) {
			try {
				socket.close();
			} catch (IOException ignored) {
			}
		}
	}

	private static byte[] buildRequest(List<String> baseHeaders, byte[] body, String authorizationValue,
			boolean keepAlive) {
		List<String> headers = new ArrayList<String>(baseHeaders);
		setHeader(headers, "Authorization", authorizationValue);
		setHeader(headers, "Connection", keepAlive ? "keep-alive" : "close");
		removeHeader(headers, "Proxy-Connection");
		StringBuilder sb = new StringBuilder();
		for (String header : headers) {
			sb.append(header).append("\r\n");
		}
		sb.append("\r\n");
		byte[] head = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
		if (body == null || body.length == 0) {
			return head;
		}
		byte[] message = new byte[head.length + body.length];
		System.arraycopy(head, 0, message, 0, head.length);
		System.arraycopy(body, 0, message, head.length, body.length);
		return message;
	}

	private static void setHeader(List<String> headers, String name, String value) {
		String full = name + ": " + value;
		for (int i = 1; i < headers.size(); i++) {
			int colon = headers.get(i).indexOf(":");
			if (colon != -1 && headers.get(i).substring(0, colon).trim().equalsIgnoreCase(name)) {
				headers.set(i, full);
				return;
			}
		}
		headers.add(full);
	}

	private static void removeHeader(List<String> headers, String name) {
		for (int i = headers.size() - 1; i >= 1; i--) {
			int colon = headers.get(i).indexOf(":");
			if (colon != -1 && headers.get(i).substring(0, colon).trim().equalsIgnoreCase(name)) {
				headers.remove(i);
			}
		}
	}

	private static class HttpResponse {
		int status = -1;
		byte[] raw;
		String ntlmChallenge;
	}

	/** Reads exactly one HTTP response from a (possibly kept-alive) stream. */
	private static HttpResponse readResponse(InputStream in) throws IOException {
		ByteArrayOutputStream headerBuffer = new ByteArrayOutputStream();
		int state = 0; // matches \r \n \r \n
		int b;
		while ((b = in.read()) != -1) {
			headerBuffer.write(b);
			if ((state == 0 || state == 2) && b == '\r') {
				state++;
			} else if ((state == 1 || state == 3) && b == '\n') {
				state++;
				if (state == 4) {
					break;
				}
			} else {
				state = 0;
			}
		}
		byte[] headerBytes = headerBuffer.toByteArray();
		if (headerBytes.length == 0) {
			throw new IOException("Empty response (connection closed during NTLM handshake).");
		}
		String headerText = new String(headerBytes, StandardCharsets.ISO_8859_1);
		String[] lines = headerText.split("\r\n");

		HttpResponse response = new HttpResponse();
		if (lines.length > 0) {
			String[] statusParts = lines[0].split(" ");
			if (statusParts.length >= 2) {
				try {
					response.status = Integer.parseInt(statusParts[1]);
				} catch (NumberFormatException ignored) {
				}
			}
		}
		int contentLength = -1;
		boolean chunked = false;
		for (int i = 1; i < lines.length; i++) {
			String line = lines[i];
			int colon = line.indexOf(":");
			if (colon == -1) {
				continue;
			}
			String key = line.substring(0, colon).trim();
			String value = line.substring(colon + 1).trim();
			if (key.equalsIgnoreCase("Content-Length")) {
				try {
					contentLength = Integer.parseInt(value.trim());
				} catch (NumberFormatException ignored) {
				}
			} else if (key.equalsIgnoreCase("Transfer-Encoding") && value.toLowerCase().contains("chunked")) {
				chunked = true;
			} else if (key.equalsIgnoreCase("WWW-Authenticate") && value.regionMatches(true, 0, "NTLM", 0, 4)) {
				if (value.length() > 5) {
					response.ntlmChallenge = value.substring(5).trim();
				}
			}
		}

		ByteArrayOutputStream body = new ByteArrayOutputStream();
		if (chunked) {
			readChunkedBody(in, body);
		} else if (contentLength > 0) {
			readFixedBody(in, body, contentLength);
		}
		// else: no body (e.g. 401 with Content-Length: 0 or absent)

		ByteArrayOutputStream full = new ByteArrayOutputStream();
		full.write(headerBytes, 0, headerBytes.length);
		byte[] bodyBytes = body.toByteArray();
		full.write(bodyBytes, 0, bodyBytes.length);
		response.raw = full.toByteArray();
		return response;
	}

	private static void readFixedBody(InputStream in, ByteArrayOutputStream body, int length) throws IOException {
		byte[] buffer = new byte[8192];
		int remaining = length;
		while (remaining > 0) {
			int read = in.read(buffer, 0, Math.min(buffer.length, remaining));
			if (read == -1) {
				break;
			}
			body.write(buffer, 0, read);
			remaining -= read;
		}
	}

	private static void readChunkedBody(InputStream in, ByteArrayOutputStream body) throws IOException {
		while (true) {
			String sizeLine = readLine(in, body);
			if (sizeLine == null) {
				break;
			}
			int semicolon = sizeLine.indexOf(';');
			String hex = (semicolon == -1 ? sizeLine : sizeLine.substring(0, semicolon)).trim();
			int size;
			try {
				size = Integer.parseInt(hex, 16);
			} catch (NumberFormatException e) {
				break;
			}
			if (size == 0) {
				// Trailer (if any) up to the final CRLF.
				readLine(in, body);
				break;
			}
			readFixedBody(in, body, size);
			readLine(in, body); // trailing CRLF after the chunk data
		}
	}

	/** Reads a line terminated by \n, echoing the raw bytes into {@code sink}. */
	private static String readLine(InputStream in, ByteArrayOutputStream sink) throws IOException {
		ByteArrayOutputStream line = new ByteArrayOutputStream();
		int b;
		boolean any = false;
		while ((b = in.read()) != -1) {
			any = true;
			sink.write(b);
			if (b == '\n') {
				break;
			}
			if (b != '\r') {
				line.write(b);
			}
		}
		if (!any) {
			return null;
		}
		return new String(line.toByteArray(), StandardCharsets.ISO_8859_1);
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
