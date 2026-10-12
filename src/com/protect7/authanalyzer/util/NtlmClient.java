package com.protect7.authanalyzer.util;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal NTLMv2 client (MS-NLMP): builds the Type 1 (NEGOTIATE) and Type 3
 * (AUTHENTICATE) messages and parses the Type 2 (CHALLENGE), so Auth Analyzer
 * can perform a per-request NTLM handshake for a low privileged user.
 *
 * NTLM is a connection oriented, challenge/response scheme, so the handshake
 * must run over a single kept-alive connection (see {@link DirectHttpClient}).
 * The NTLMv2 response is computed with a Message Integrity Code (MIC).
 *
 * MD4 is implemented here because it is not exposed through the standard JCE.
 *
 * @author Auth Analyzer
 */
public class NtlmClient {

	private static final Charset UTF16LE = Charset.forName("UTF-16LE");
	private static final byte[] SIGNATURE = new byte[] { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0 };

	private static final int NEGOTIATE_UNICODE = 0x00000001;
	private static final int REQUEST_TARGET = 0x00000004;
	private static final int NEGOTIATE_NTLM = 0x00000200;
	private static final int NEGOTIATE_ALWAYS_SIGN = 0x00008000;
	private static final int NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000;
	private static final int NEGOTIATE_TARGET_INFO = 0x00800000;
	private static final int NEGOTIATE_VERSION = 0x02000000;
	private static final int NEGOTIATE_128 = 0x20000000;
	private static final int NEGOTIATE_56 = 0x80000000;

	private static final int AV_EOL = 0x0000;
	private static final int AV_TIMESTAMP = 0x0007;
	private static final int AV_FLAGS = 0x0006;

	private static final byte[] VERSION = new byte[] { 6, 1, (byte) 0xB1, 0x1D, 0, 0, 0, 0x0F };

	private final SecureRandom random = new SecureRandom();

	public byte[] createType1Message() {
		int flags = NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN
				| NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_VERSION | NEGOTIATE_128 | NEGOTIATE_56;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(SIGNATURE, 0, SIGNATURE.length);
		writeInt(out, 1); // message type
		writeInt(out, flags);
		// DomainNameFields (empty), WorkstationFields (empty) - offset points past the header.
		writeShort(out, 0);
		writeShort(out, 0);
		writeInt(out, 40);
		writeShort(out, 0);
		writeShort(out, 0);
		writeInt(out, 40);
		out.write(VERSION, 0, VERSION.length);
		return out.toByteArray();
	}

	/**
	 * Builds the Type 3 (AUTHENTICATE) message answering the given Type 2
	 * challenge, including a MIC over the three messages.
	 */
	public byte[] createType3Message(byte[] type1, byte[] type2, String domain, String user, String password,
			String workstation) throws Exception {
		byte[] serverChallenge = new byte[8];
		System.arraycopy(type2, 24, serverChallenge, 0, 8);
		int tiLen = readShort(type2, 40);
		int tiOff = readInt(type2, 44);
		byte[] targetInfo = new byte[tiLen];
		System.arraycopy(type2, tiOff, targetInfo, 0, tiLen);

		long timestamp = extractTimestamp(targetInfo);
		byte[] targetInfoWithMic = withMicFlag(targetInfo);
		byte[] clientChallenge = new byte[8];
		random.nextBytes(clientChallenge);

		byte[] ntlmHash = md4(toUnicode(password));
		byte[] ntlmv2Hash = hmacMd5(ntlmHash, toUnicode(user.toUpperCase() + (domain == null ? "" : domain)));

		// temp = 0x01 0x01 00*6 timestamp(8) clientChallenge(8) 00*4 targetInfo 00*4
		ByteArrayOutputStream temp = new ByteArrayOutputStream();
		temp.write(1);
		temp.write(1);
		temp.write(new byte[6], 0, 6);
		writeLong(temp, timestamp);
		temp.write(clientChallenge, 0, 8);
		writeInt(temp, 0);
		temp.write(targetInfoWithMic, 0, targetInfoWithMic.length);
		writeInt(temp, 0);
		byte[] tempBytes = temp.toByteArray();

		byte[] ntProof = hmacMd5(ntlmv2Hash, concat(serverChallenge, tempBytes));
		byte[] ntChallengeResponse = concat(ntProof, tempBytes);
		byte[] lmChallengeResponse = concat(hmacMd5(ntlmv2Hash, concat(serverChallenge, clientChallenge)), clientChallenge);
		byte[] sessionBaseKey = hmacMd5(ntlmv2Hash, ntProof);
		byte[] exportedSessionKey = sessionBaseKey; // no key exchange

		byte[] domainBytes = toUnicode(domain == null ? "" : domain);
		byte[] userBytes = toUnicode(user);
		byte[] workstationBytes = toUnicode(workstation == null ? "" : workstation);
		byte[] encryptedRandomSessionKey = new byte[0];

		int flags = NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN
				| NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_TARGET_INFO | NEGOTIATE_VERSION | NEGOTIATE_128
				| NEGOTIATE_56;

		// Header is 64 bytes + 8 (version) + 16 (MIC) = 88 bytes, then the payload.
		int offset = 88;
		int lmOffset = offset;
		int ntOffset = lmOffset + lmChallengeResponse.length;
		int domainOffset = ntOffset + ntChallengeResponse.length;
		int userOffset = domainOffset + domainBytes.length;
		int workstationOffset = userOffset + userBytes.length;
		int sessionKeyOffset = workstationOffset + workstationBytes.length;

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(SIGNATURE, 0, SIGNATURE.length);
		writeInt(out, 3); // message type
		writeField(out, lmChallengeResponse.length, lmOffset);
		writeField(out, ntChallengeResponse.length, ntOffset);
		writeField(out, domainBytes.length, domainOffset);
		writeField(out, userBytes.length, userOffset);
		writeField(out, workstationBytes.length, workstationOffset);
		writeField(out, encryptedRandomSessionKey.length, sessionKeyOffset);
		writeInt(out, flags);
		out.write(VERSION, 0, VERSION.length);
		int micIndex = out.size();
		out.write(new byte[16], 0, 16); // MIC placeholder
		out.write(lmChallengeResponse, 0, lmChallengeResponse.length);
		out.write(ntChallengeResponse, 0, ntChallengeResponse.length);
		out.write(domainBytes, 0, domainBytes.length);
		out.write(userBytes, 0, userBytes.length);
		out.write(workstationBytes, 0, workstationBytes.length);

		byte[] type3 = out.toByteArray();
		// MIC = HMAC_MD5(exportedSessionKey, type1 || type2 || type3-with-zeroed-MIC)
		byte[] mic = hmacMd5(exportedSessionKey, concat(concat(type1, type2), type3));
		System.arraycopy(mic, 0, type3, micIndex, 16);
		return type3;
	}

	private long extractTimestamp(byte[] targetInfo) {
		int pos = 0;
		while (pos + 4 <= targetInfo.length) {
			int id = readShort(targetInfo, pos);
			int len = readShort(targetInfo, pos + 2);
			if (id == AV_EOL) {
				break;
			}
			if (id == AV_TIMESTAMP && len == 8) {
				long value = 0;
				for (int i = 7; i >= 0; i--) {
					value = (value << 8) | (targetInfo[pos + 4 + i] & 0xFFL);
				}
				return value;
			}
			pos += 4 + len;
		}
		return (System.currentTimeMillis() + 11644473600000L) * 10000L;
	}

	/** Returns the target info with the MsvAvFlags 'MIC present' bit (0x2) set. */
	private byte[] withMicFlag(byte[] targetInfo) {
		List<int[]> order = new ArrayList<int[]>(); // {id, offset, len}
		int pos = 0;
		boolean hasFlags = false;
		while (pos + 4 <= targetInfo.length) {
			int id = readShort(targetInfo, pos);
			int len = readShort(targetInfo, pos + 2);
			if (id == AV_EOL) {
				break;
			}
			if (id == AV_FLAGS) {
				hasFlags = true;
			}
			order.add(new int[] { id, pos + 4, len });
			pos += 4 + len;
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (int[] pair : order) {
			int id = pair[0];
			int off = pair[1];
			int len = pair[2];
			writeShort(out, id);
			writeShort(out, len);
			if (id == AV_FLAGS && len == 4) {
				int value = readInt(targetInfo, off) | 0x00000002;
				writeInt(out, value);
			} else {
				out.write(targetInfo, off, len);
			}
		}
		if (!hasFlags) {
			writeShort(out, AV_FLAGS);
			writeShort(out, 4);
			writeInt(out, 0x00000002);
		}
		writeShort(out, AV_EOL);
		writeShort(out, 0);
		return out.toByteArray();
	}

	private static byte[] toUnicode(String s) {
		return s.getBytes(UTF16LE);
	}

	private static byte[] hmacMd5(byte[] key, byte[] data) throws Exception {
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(new SecretKeySpec(key, "HmacMD5"));
		return mac.doFinal(data);
	}

	private static byte[] concat(byte[] a, byte[] b) {
		byte[] result = new byte[a.length + b.length];
		System.arraycopy(a, 0, result, 0, a.length);
		System.arraycopy(b, 0, result, a.length, b.length);
		return result;
	}

	private static void writeShort(ByteArrayOutputStream out, int value) {
		out.write(value & 0xFF);
		out.write((value >> 8) & 0xFF);
	}

	private static void writeInt(ByteArrayOutputStream out, int value) {
		out.write(value & 0xFF);
		out.write((value >> 8) & 0xFF);
		out.write((value >> 16) & 0xFF);
		out.write((value >> 24) & 0xFF);
	}

	private static void writeLong(ByteArrayOutputStream out, long value) {
		for (int i = 0; i < 8; i++) {
			out.write((int) ((value >> (8 * i)) & 0xFF));
		}
	}

	private static void writeField(ByteArrayOutputStream out, int len, int offset) {
		writeShort(out, len);
		writeShort(out, len);
		writeInt(out, offset);
	}

	private static int readShort(byte[] data, int offset) {
		return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
	}

	private static int readInt(byte[] data, int offset) {
		return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8) | ((data[offset + 2] & 0xFF) << 16)
				| ((data[offset + 3] & 0xFF) << 24);
	}

	// ---------------------------------------------------------------------
	// MD4 (RFC 1320) - not available through the standard JCE.
	// ---------------------------------------------------------------------
	private static byte[] md4(byte[] message) {
		int a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
		int originalLength = message.length;
		int paddedLength = ((originalLength + 8) / 64 + 1) * 64;
		byte[] padded = new byte[paddedLength];
		System.arraycopy(message, 0, padded, 0, originalLength);
		padded[originalLength] = (byte) 0x80;
		long bitLength = (long) originalLength * 8;
		for (int i = 0; i < 8; i++) {
			padded[paddedLength - 8 + i] = (byte) ((bitLength >> (8 * i)) & 0xFF);
		}
		int[] x = new int[16];
		for (int i = 0; i < paddedLength / 64; i++) {
			for (int j = 0; j < 16; j++) {
				int base = i * 64 + j * 4;
				x[j] = (padded[base] & 0xFF) | ((padded[base + 1] & 0xFF) << 8) | ((padded[base + 2] & 0xFF) << 16)
						| ((padded[base + 3] & 0xFF) << 24);
			}
			int aa = a, bb = b, cc = c, dd = d;
			// Round 1
			int[] s1 = { 3, 7, 11, 19 };
			for (int k = 0; k < 16; k += 4) {
				a = rotl(a + f(b, c, d) + x[k], s1[0]);
				d = rotl(d + f(a, b, c) + x[k + 1], s1[1]);
				c = rotl(c + f(d, a, b) + x[k + 2], s1[2]);
				b = rotl(b + f(c, d, a) + x[k + 3], s1[3]);
			}
			// Round 2
			int[] s2 = { 3, 5, 9, 13 };
			int[] k2 = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
			for (int k = 0; k < 16; k += 4) {
				a = rotl(a + g(b, c, d) + x[k2[k]] + 0x5a827999, s2[0]);
				d = rotl(d + g(a, b, c) + x[k2[k + 1]] + 0x5a827999, s2[1]);
				c = rotl(c + g(d, a, b) + x[k2[k + 2]] + 0x5a827999, s2[2]);
				b = rotl(b + g(c, d, a) + x[k2[k + 3]] + 0x5a827999, s2[3]);
			}
			// Round 3
			int[] s3 = { 3, 9, 11, 15 };
			int[] k3 = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
			for (int k = 0; k < 16; k += 4) {
				a = rotl(a + h(b, c, d) + x[k3[k]] + 0x6ed9eba1, s3[0]);
				d = rotl(d + h(a, b, c) + x[k3[k + 1]] + 0x6ed9eba1, s3[1]);
				c = rotl(c + h(d, a, b) + x[k3[k + 2]] + 0x6ed9eba1, s3[2]);
				b = rotl(b + h(c, d, a) + x[k3[k + 3]] + 0x6ed9eba1, s3[3]);
			}
			a += aa;
			b += bb;
			c += cc;
			d += dd;
		}
		byte[] digest = new byte[16];
		intToLE(a, digest, 0);
		intToLE(b, digest, 4);
		intToLE(c, digest, 8);
		intToLE(d, digest, 12);
		return digest;
	}

	private static int f(int x, int y, int z) {
		return (x & y) | (~x & z);
	}

	private static int g(int x, int y, int z) {
		return (x & y) | (x & z) | (y & z);
	}

	private static int h(int x, int y, int z) {
		return x ^ y ^ z;
	}

	private static int rotl(int value, int shift) {
		return (value << shift) | (value >>> (32 - shift));
	}

	private static void intToLE(int value, byte[] out, int offset) {
		out[offset] = (byte) (value & 0xFF);
		out[offset + 1] = (byte) ((value >> 8) & 0xFF);
		out[offset + 2] = (byte) ((value >> 16) & 0xFF);
		out[offset + 3] = (byte) ((value >> 24) & 0xFF);
	}
}
