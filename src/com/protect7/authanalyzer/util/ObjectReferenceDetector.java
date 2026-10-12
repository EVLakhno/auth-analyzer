package com.protect7.authanalyzer.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import burp.BurpExtender;
import burp.IParameter;
import burp.IRequestInfo;

/**
 * Detects direct object references (candidate IDOR / BOLA identifiers) in a
 * request: numeric path segments, UUID / GUID, Mongo ObjectId, and parameters
 * whose name looks like an identifier.
 *
 * Tuned for precision over recall so the "IDOR candidates" filter stays useful
 * and is not flooded by static resources, pagination or anti-CSRF tokens.
 *
 * @author Auth Analyzer
 */
public class ObjectReferenceDetector {

	private static final Pattern UUID = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
	private static final Pattern MONGO_ID = Pattern.compile("^[0-9a-fA-F]{24}$");
	private static final Pattern HEX32 = Pattern.compile("^[0-9a-fA-F]{32}$");
	private static final Pattern NUMERIC = Pattern.compile("^[0-9]+$");

	// Parameter names that strongly indicate an object identifier.
	private static final Set<String> ID_NAMES = new HashSet<String>(Arrays.asList("id", "uid", "uuid", "guid", "gid",
			"pid", "oid", "sid", "ref", "refid", "fid", "no", "num", "number", "account", "accountid", "acct", "order",
			"orderid", "invoice", "invoiceid", "document", "documentid", "docid", "file", "fileid", "object", "objectid",
			"record", "recordid", "item", "itemid", "customer", "customerid", "member", "memberid", "profile",
			"profileid", "group", "groupid", "role", "roleid", "user", "userid", "username", "email"));

	// Names that must never be flagged by their value alone (tokens, pagination, timing, ...).
	private static final Set<String> DENY_VALUE_NAMES = new HashSet<String>(Arrays.asList("csrf", "csrftoken",
			"csrf_token", "token", "antiforgery", "nonce", "state", "code", "hash", "sig", "signature", "captcha",
			"session", "sessionid", "jsessionid", "time", "timestamp", "ts", "date", "expires", "exp", "iat", "nbf",
			"page", "pagesize", "per_page", "perpage", "limit", "offset", "start", "size", "count", "length", "max",
			"min", "version", "ver", "v", "utm_source", "utm_medium", "utm_campaign", "_ga"));

	/**
	 * @return a short human readable description of the detected object
	 *         reference(s), or an empty string if none were found.
	 */
	public static String describe(byte[] request) {
		if (request == null) {
			return "";
		}
		try {
			IRequestInfo info = BurpExtender.callbacks.getHelpers().analyzeRequest(request);
			List<String> refs = new ArrayList<String>();

			// Path segments (strong IDOR signal: /users/1234, /doc/<uuid>).
			String path = info.getUrl() == null ? "" : info.getUrl().getPath();
			if (path != null) {
				for (String segment : path.split("/")) {
					if (isStrongIdentifier(segment) && !refs.contains("/" + segment)) {
						refs.add("/" + segment);
					}
				}
			}

			// Parameters (URL, body, JSON). Cookies are skipped (session noise).
			for (IParameter parameter : info.getParameters()) {
				if (parameter.getType() == IParameter.PARAM_COOKIE) {
					continue;
				}
				String name = parameter.getName();
				String value = parameter.getValue();
				if (name == null || value == null || value.isEmpty()) {
					continue;
				}
				String lowerName = name.toLowerCase();
				boolean flag = false;
				if (isIdLikeName(lowerName)) {
					flag = true;
				} else if (isStrongValueOnly(value) && !DENY_VALUE_NAMES.contains(lowerName)) {
					flag = true;
				}
				if (flag) {
					String entry = name + "=" + trim(value);
					if (!refs.contains(entry)) {
						refs.add(entry);
					}
				}
				if (refs.size() >= 6) {
					break;
				}
			}

			StringBuilder sb = new StringBuilder();
			for (String ref : refs) {
				if (sb.length() > 0) {
					sb.append(", ");
				}
				sb.append(ref);
			}
			return sb.toString();
		} catch (Exception e) {
			return "";
		}
	}

	public static boolean hasObjectReference(byte[] request) {
		return !describe(request).isEmpty();
	}

	private static boolean isIdLikeName(String lowerName) {
		if (ID_NAMES.contains(lowerName)) {
			return true;
		}
		// foo_id, fooId, foo-id, fooid
		return lowerName.endsWith("id") && lowerName.length() > 2;
	}

	// Value formats that are almost always object references on their own.
	private static boolean isStrongValueOnly(String value) {
		return UUID.matcher(value).matches() || MONGO_ID.matcher(value).matches();
	}

	// Path segment identifiers (numeric or structured ids).
	private static boolean isStrongIdentifier(String value) {
		if (value == null || value.isEmpty()) {
			return false;
		}
		if (UUID.matcher(value).matches() || MONGO_ID.matcher(value).matches()) {
			return true;
		}
		if (NUMERIC.matcher(value).matches()) {
			return true;
		}
		// 32 hex chars in a path (e.g. a hashed id) - still a likely object reference.
		return HEX32.matcher(value).matches();
	}

	private static String trim(String value) {
		String single = value.replace("\r", " ").replace("\n", " ");
		if (single.length() > 24) {
			return single.substring(0, 24) + "…";
		}
		return single;
	}
}
