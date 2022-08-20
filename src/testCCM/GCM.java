package testCCM;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class GCM {

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	// Pre-configured Encryption Parameters
	public static int NonceBitSize = 128;
	public static int MacBitSize = 128;

	/* Convert a string representation in its hexadecimal string */
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes()));
	}

	/*
	 * Transform an hexadecimal string in byte array (It works if the string only
	 * contains the hexadecimal characters)
	 */
	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/* Perform SHA256 and return the result */
	private static byte[] sha256(byte[] data) {
		SHA256Digest digest = new SHA256Digest();
		byte[] hash = new byte[digest.getDigestSize()];
		digest.update(data, 0, data.length);
		digest.doFinal(hash, 0);
		return hash;
	}
	
	public static byte[] NewIv() {
		byte[] iv = new byte[NonceBitSize / 8];
		SECURE_RANDOM.nextBytes(iv);
		return iv;
	}

	public static byte[] HexToByte(String hexStr) {
		int len = hexStr.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
					+ Character.digit(hexStr.charAt(i + 1), 16));
		}
		return data;
	}

	public static String toHex(byte[] data) {
		final StringBuilder builder = new StringBuilder();
		for (byte b : data) {
			builder.append(Integer.toString(b, 16));
		}
		return builder.toString();
	}

	public static String encrypt(String PlainText, byte[] key, byte[] iv) {
		String sR = "";
		try {
			byte[] plainBytes = PlainText.getBytes("UTF-8");

			GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
			AEADParameters parameters = new AEADParameters(new KeyParameter(key), MacBitSize, iv, null);

			cipher.init(true, parameters);

			byte[] encryptedBytes = new byte[cipher.getOutputSize(plainBytes.length)];
			int retLen = cipher.processBytes(plainBytes, 0, plainBytes.length, encryptedBytes, 0);
			cipher.doFinal(encryptedBytes, retLen);
			sR = Base64.getEncoder().encodeToString(encryptedBytes);
		} catch (UnsupportedEncodingException | IllegalArgumentException | IllegalStateException | DataLengthException
				| InvalidCipherTextException ex) {
			System.out.println(ex.getMessage());
		}

		return sR;
	}

	public static String decrypt(String EncryptedText, byte[] key, byte[] iv) {
		String sR = "";
		try {
			byte[] encryptedBytes = Base64.getDecoder().decode(EncryptedText);

			GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
			AEADParameters parameters = new AEADParameters(new KeyParameter(key), MacBitSize, iv, null);

			cipher.init(false, parameters);
			byte[] plainBytes = new byte[cipher.getOutputSize(encryptedBytes.length)];
			int retLen = cipher.processBytes(encryptedBytes, 0, encryptedBytes.length, plainBytes, 0);
			cipher.doFinal(plainBytes, retLen);

			sR = new String(plainBytes, Charset.forName("UTF-8"));
		} catch (IllegalArgumentException | IllegalStateException | DataLengthException
				| InvalidCipherTextException ex) {
			System.out.println(ex.getMessage());
		}

		return sR;
	}

	public static void main(String[] args) {

		// using above code these key and iv was generated
//		String hexKey = "2192B39425BBD08B6E8E61C5D1F1BC9F428FC569FBC6F78C0BC48FCCDB0F42AE";
		String kzz = "5f5e1f20b4a333f8cdf1f04251ac0f93300bf1a9ce5b5436cd4b47b0c6a1ffab";
		byte[] kz = hexStringToByteArray(kzz);
		byte[] Kz = sha256(kz);
		
//		String hexIV = "E1E592E87225847C11D948684F3B070D";
//		String nonces = "bf782587a8672d2e6ce0d161";
//		byte[] nonce = sha256(hexStringToByteArray(nonces));
//		System.out.println("nonce : " + toHex(nonce));
		SecureRandom random = new SecureRandom();
		byte[] nonce = new byte[12];
		random.nextBytes(nonce); // Fill the nonce with random bytes
		
		String plainText = "12345";
		System.out.println("Plain Text: " + plainText);
		
		long nano_startTime = System.nanoTime();
		
		// encrypt - result base64 encoded string
		String encryptedText = encrypt(plainText, Kz, nonce);
		
		long nano_endTime = System.nanoTime();
		System.out.println("Time taken in nano seconds encrypt: "
                + (nano_endTime - nano_startTime));
		
		//System.out.println("Encrypted base64 encoded: " + encryptedText);

		long nano_startTime1 = System.nanoTime();
		
		// decrypt - result plain string
		String decryptedText = decrypt(encryptedText, Kz, nonce);

		long nano_endTime1 = System.nanoTime();
		System.out.println("Time taken in nano seconds decrypt: "
                + (nano_endTime1 - nano_startTime1));
		
		System.out.println("Decrypted Text: " + decryptedText);
		
		if (plainText.equals(decryptedText)) {
			System.out.println("Test Passed");
		} else {
			System.out.println("Test Failed");
		}
	}
}
