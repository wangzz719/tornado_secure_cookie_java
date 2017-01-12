package tornado_secure_cookie;

import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TornadoSecureCookie {
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

	private static final String SINGED_VALUE_VERSION_RE = "^([1-9][0-9]*)\\|(.*)$";
	private static final int COOKIE_V2_LENGHT = 5;

	public static String hexDigest(byte[] bytes) {
		/**
		 * create hex digest
		 */
		StringBuffer str = new StringBuffer();
		for (byte b : bytes) {
			str.append(String.format("%02x", b));
		}
		return str.toString();
	}

	public static boolean timeIndependentEquals(String a, String b) {
		/**
		 * use same time to judge whether two string is equal
		 */
		if (a.length() != b.length()) {
			return false;
		}
		int len = a.length();
		boolean result = true;
		for (int i = 0; i < len; i++) {
			if (a.charAt(i) != b.charAt(i)) {
				result = false;
			}
		}
		return result;
	}

	public static ArrayList<String> decodeCookieFieldsV2(String value) throws Exception {
		/**
		 * decode fields of tornado secure cookie version 2
		 */
		String restCookieValue = value.substring(2);
		String[] parts = restCookieValue.split("\\|");
		ArrayList<String> result = new ArrayList<String>();
		if (parts.length != COOKIE_V2_LENGHT) {
			throw new Exception("malformed v2 signed value field");
		}
		for (int j = 0; j < COOKIE_V2_LENGHT - 1; j++) {
			String[] subFields = parts[j].split(":");
			int length = Integer.valueOf(subFields[0]);
			if (subFields[1].length() != length) {
				throw new Exception("malformed v2 signed value field");
			}
			result.add(subFields[1]);
		}
		result.add(parts[COOKIE_V2_LENGHT - 1]);
		return result;
	}

	public static String formatField(String s) {
		return String.join(":", String.valueOf(s.length()), s);
	}

	public static String calculateSignature(String secret, String data, String hashAlgorithm)
			throws SignatureException {
		/**
		 * calculate signature of data using given secret and hash algorithm
		 */
		try {
			SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(), hashAlgorithm);

			Mac mac = Mac.getInstance(hashAlgorithm);
			mac.init(signingKey);

			byte[] rawHmac = mac.doFinal(data.getBytes());
			return hexDigest(rawHmac);

		} catch (Exception e) {
			throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
		}
	}

	public static String createSignatureV1(String cookieSecret, String cookieName, String[] parts)
			throws SignatureException {
		/**
		 * create signature of tornado secure cookie version 1 using hash sha1
		 * algorithm
		 */
		String subParts = String.join("", cookieName, parts[0], parts[1]);
		return calculateSignature(cookieSecret, subParts, HMAC_SHA1_ALGORITHM);
	}

	public static String createSignatureV2(String cookieSecret, String data) throws SignatureException {
		/***
		 * create signature of tornado secure cookie version 2 using hash sha256
		 * algorithm
		 */
		return calculateSignature(cookieSecret, data, HMAC_SHA256_ALGORITHM);
	}

	public static String decodeSignedValueV1(String cookieSecret, String cookieName, String cookieValue, int clock,
			int maxAgeDays) throws SignatureException {
		/**
		 * decode tornado secure cookie version 1 with cookie secret instance of
		 * string
		 */
		String[] parts = cookieValue.split("\\|");
		if (parts.length != 3) {
			return null;
		}
		String signature = createSignatureV1(cookieSecret, cookieName, parts);
		if (!timeIndependentEquals(signature, parts[2])) {
			return null;
		}
		int timestamp = Integer.valueOf(parts[1]);
		if (timestamp < (clock - maxAgeDays * 86400)) {
			return null;
		}
		if (timestamp > (clock + 31 * 86400)) {
			return null;
		}
		try {
			String cookie = new String(Base64.getDecoder().decode(parts[0]));
			return cookie;
		} catch (Exception e) {
			return null;
		}
	}

	public static String decodeSignedValueV2(String cookieSecret, String cookieName, String cookieValue, int clock,
			int maxAgeDays) {
		/**
		 * decode tornado secure cookie version 2 with cookie secret instance of
		 * string
		 */
		try {
			ArrayList<String> fields = decodeCookieFieldsV2(cookieValue);
			String passedSig = fields.get(COOKIE_V2_LENGHT - 1);
			String signedString = cookieValue.substring(0, cookieValue.length() - passedSig.length());
			String expectedSignature = createSignatureV2(cookieSecret, signedString);
			if (!timeIndependentEquals(passedSig, expectedSignature)) {
				return null;
			}
			int timeStamp = Integer.valueOf(fields.get(1));
			String nameField = fields.get(2);
			String valueField = fields.get(3);
			if (!nameField.equals(cookieName)) {
				return null;
			}
			if (timeStamp < (clock - maxAgeDays * 86400)) {
				return null;
			}
			try {
				String cookie = new String(Base64.getDecoder().decode(valueField));
				return cookie;
			} catch (Exception e) {
				return null;
			}
		} catch (Exception e) {
			return null;
		}
	}

	public static String decodeSignedValueV2(Map<String, String> cookieSecret, String cookieName, String cookieValue,
			int clock, int maxAgeDays) {
		/**
		 * decode tornado secure cookie version 2 with cookie secret instance of
		 * map
		 */
		try {
			ArrayList<String> fields = decodeCookieFieldsV2(cookieValue);
			String passedSig = fields.get(COOKIE_V2_LENGHT - 1);
			String signedString = cookieValue.substring(0, cookieValue.length() - passedSig.length());
			String keyVersion = fields.get(0);
			String secret = cookieSecret.get(keyVersion);
			String expectedSignature = createSignatureV2(secret, signedString);
			if (!timeIndependentEquals(passedSig, expectedSignature)) {
				return null;
			}
			int timeStamp = Integer.valueOf(fields.get(1));
			String nameField = fields.get(2);
			String valueField = fields.get(3);
			if (!nameField.equals(cookieName)) {
				return null;
			}
			if (timeStamp < (clock - maxAgeDays * 86400)) {
				return null;
			}
			try {
				String cookie = new String(Base64.getDecoder().decode(valueField));
				return cookie;
			} catch (Exception e) {
				return null;
			}
		} catch (Exception e) {
			return null;
		}
	}

	public static int getCookieVersion(String cookieValue) {
		/**
		 * get version of tornado secure cookie
		 */
		Pattern r = Pattern.compile(SINGED_VALUE_VERSION_RE);
		Matcher m = r.matcher(cookieValue);
		int version = 1;
		if (m.find()) {
			try {
				version = Integer.valueOf(m.group(1));
				if (version > 999) {
					version = 1;
				}
			} catch (Exception e) {
				version = 1;
			}
		} else {
			version = 1;
		}
		return version;
	}

	public static String decodeSecureCookie(String cookieSecret, String cookieName, String cookieValue)
			throws Exception {
		/***
		 * decode secure cookie using current time milliseconds, and maxAgeDays
		 * default 31, minVersion default 1
		 */
		int clock = (int) (System.currentTimeMillis() / 1000);
		int maxAgeDays = 31;
		int minVersion = 1;
		return decodeSecureCookie(cookieSecret, cookieName, cookieValue, clock, maxAgeDays, minVersion);
	}

	public static String decodeSecureCookie(String cookieSecret, String cookieName, String cookieValue,
			Map<String, Integer> cookieControl) throws Exception {
		/***
		 * decode secure cookie with cookie secret instance of string
		 * cookieControl may contains clock, maxAgeDays, minVersion
		 */
		int clock = (int) (System.currentTimeMillis() / 1000);
		int maxAgeDays = 31;
		int minVersion = 1;
		if (cookieControl.containsKey("clock")) {
			clock = cookieControl.get("clock");
		}
		if (cookieControl.containsKey("maxAgeDays")) {
			maxAgeDays = cookieControl.get("maxAgeDays");
		}
		if (cookieControl.containsKey("minVersion")) {
			minVersion = cookieControl.get("minVersion");
		}
		return decodeSecureCookie(cookieSecret, cookieName, cookieValue, clock, maxAgeDays, minVersion);
	}

	public static String decodeSecureCookie(String cookieSecret, String cookieName, String cookieValue, int clock,
			int maxAgeDays, int minVersion) throws Exception {
		/**
		 * decode tornado secure cookie with cookieSecret instance of string
		 * 
		 */
		if (minVersion > 2) {
			throw new Exception("Unsupported minVesion");
		}
		if (cookieValue.length() == 0) {
			return null;
		}
		int version = getCookieVersion(cookieValue);
		if (version < minVersion) {
			return null;
		}
		if (version == 1) {
			return decodeSignedValueV1(cookieSecret, cookieName, cookieValue, clock, maxAgeDays);
		} else if (version == 2) {
			return decodeSignedValueV2(cookieSecret, cookieName, cookieValue, clock, maxAgeDays);
		} else {
			return null;
		}
	}

	public static String decodeSecureCookie(Map<String, String> cookieSecret, String cookieName, String cookieValue)
			throws Exception {
		/***
		 * decode secure cookie using current time milliseconds, and maxAgeDays
		 * default 31, minVersion default 1 and cookieSecret is instance of map
		 */
		int clock = (int) (System.currentTimeMillis() / 1000);
		int maxAgeDays = 31;
		int minVersion = 1;
		return decodeSecureCookie(cookieSecret, cookieName, cookieValue, clock, maxAgeDays, minVersion);
	}

	public static String decodeSecureCookie(Map<String, String> cookieSecret, String cookieName, String cookieValue,
			Map<String, Integer> cookieControl) throws Exception {
		/***
		 * decode secure cookie with cookieSecret is instance of map
		 * cookieControl may contains clock, maxAgeDays, minVersion
		 */
		int clock = (int) (System.currentTimeMillis() / 1000);
		int maxAgeDays = 31;
		int minVersion = 1;
		if (cookieControl.containsKey("clock")) {
			clock = cookieControl.get("clock");
		}
		if (cookieControl.containsKey("maxAgeDays")) {
			maxAgeDays = cookieControl.get("maxAgeDays");
		}
		if (cookieControl.containsKey("minVersion")) {
			minVersion = cookieControl.get("minVersion");
		}
		return decodeSecureCookie(cookieSecret, cookieName, cookieValue, clock, maxAgeDays, minVersion);
	}

	public static String decodeSecureCookie(Map<String, String> cookieSecret, String cookieName, String cookieValue,
			int clock, int maxAgeDays, int minVersion) throws Exception {
		/**
		 * decode tornado secure cookie with cookie secret instance of map
		 * 
		 */
		if (minVersion > 2) {
			throw new Exception("Unsupported minVesion");
		}
		if (cookieValue.length() == 0) {
			return null;
		}
		int version = getCookieVersion(cookieValue);
		if (version < minVersion) {
			return null;
		}
		if (version == 1) {
			throw new Exception("Vesion 1 not support dict cookie secret");
		} else if (version == 2) {
			return decodeSignedValueV2(cookieSecret, cookieName, cookieValue, clock, maxAgeDays);
		} else {
			return null;
		}
	}

	public static String createSecureCookie(String cookieSecret, String cookieName, String cookieValue)
			throws Exception {
		/**
		 * create signed value with version default 1, clock default current
		 * time, keyVersion default 0, and cookieSecret is instance of string
		 */
		int version = 1;
		int clock = (int) (System.currentTimeMillis() / 1000);
		int keyVersion = 0;
		return createSecureCookie(cookieSecret, cookieName, cookieValue, version, clock, keyVersion);
	}

	public static String createSecureCookie(String cookieSecret, String cookieName, String cookieValue,
			Map<String, Integer> cookieControl) throws Exception {
		/**
		 * create signed value with cookieSecret is instance of string
		 * cookieControl may contains version, clock, keyVersion
		 */
		int version = 1;
		int clock = (int) (System.currentTimeMillis() / 1000);
		int keyVersion = 0;
		if (cookieControl.containsKey("version")) {
			version = cookieControl.get("version");
		}
		if (cookieControl.containsKey("clock")) {
			clock = cookieControl.get("clock");
		}
		if (cookieControl.containsKey("keyVersion")) {
			keyVersion = cookieControl.get("keyVersion");
		}
		return createSecureCookie(cookieSecret, cookieName, cookieValue, version, clock, keyVersion);
	}

	public static String createSecureCookie(Map<String, String> cookieSecret, String cookieName, String cookieValue,
			int keyVersion) throws Exception {
		/**
		 * create signed value with cookieSecret is instance of map, clock is
		 * system current time and cookie version must be set to 2
		 */
		String secret = cookieSecret.get(String.valueOf(keyVersion));
		int version = 2;
		int clock = (int) (System.currentTimeMillis() / 1000);
		return createSecureCookie(secret, cookieName, cookieValue, version, clock, keyVersion);
	}

	public static String createSecureCookie(Map<String, String> cookieSecret, String cookieName, String cookieValue,
			int clock, int keyVersion) throws Exception {
		/**
		 * create signed value with cookieSecret is instance of map
		 */
		String secret = cookieSecret.get(String.valueOf(keyVersion));
		int version = 2;
		return createSecureCookie(secret, cookieName, cookieValue, version, clock, keyVersion);
	}

	public static String createSecureCookie(String cookieSecret, String cookieName, String cookieValue, int version,
			int clock, int keyVersion) throws Exception {
		/**
		 * create signed value with cookieSecret is instance of string
		 */
		String signedValue = Base64.getEncoder().encodeToString(cookieValue.getBytes());
		if (version == 1) {
			String[] parts = { signedValue, String.valueOf(clock) };
			String signature = createSignatureV1(cookieSecret, cookieName, parts);
			String signedCookie = String.join("|", signedValue, String.valueOf(clock), signature);
			return signedCookie;
		} else if (version == 2) {
			String toSign = String.join("|", "2", formatField(String.valueOf(keyVersion)),
					formatField(String.valueOf(clock)), formatField(cookieName), formatField(signedValue), "");
			String signature = createSignatureV2(cookieSecret, toSign);
			return toSign + signature;
		} else {
			throw new Exception("Unsupported version: " + version);
		}
	}
}
