package testCCM;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class testCCM {
	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

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

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		long nano_startTime1 = System.nanoTime();

		// Generate a nonce (12 bytes) to be used for AES_256_CCM_8
		SecureRandom random = new SecureRandom();
		byte[] nonce = new byte[12];
		random.nextBytes(nonce); // Fill the nonce with random bytes
		String kzz = "5f5e1f20b4a333f8cdf1f04251ac0f93300bf1a9ce5b5436cd4b47b0c6a1ffab";
		byte[] kz = hexStringToByteArray(kzz);
		byte[] Kz = sha256(kz);

		String bytes = "1234556789456789455555555555555555555555555555555555555555555555154154888";
		byte[] cleartext = hexStringToByteArray(toHex(bytes));

		long nano_startTime2 = System.nanoTime();
		//System.out.println("Time before encrypt: " + (nano_startTime2 - nano_startTime1));
		// Encrypt the cleartext
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		ccm.init(true, new ParametersWithIV(new KeyParameter(Kz), nonce));
		byte[] ciphertext = new byte[cleartext.length + 8];// output buffer
		int len = ccm.processBytes(cleartext, 0, cleartext.length, ciphertext, 0);// the number of bytes written to out.
		try {
			len += ccm.doFinal(ciphertext, len);// Add MAC address or verify MAC address
			// do dai cua MAC la boi so cua 8 va co kich thuoc nho hon ciphertex
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		long nano_startTime3 = System.nanoTime();
		System.out.println("Only time encrypt: " + (nano_startTime3 - nano_startTime2));
		System.out.println("Sum time encrypt: " + (nano_startTime3 - nano_startTime2+nano_startTime2 - nano_startTime1));
		// System.out.println("Ciphertext: " + toHex(ciphertext));


		// Decoder Ciphertext
		long nano_startTime4 = System.nanoTime();
		byte[] decode = null;
		CCMBlockCipher ccm1 = new CCMBlockCipher(new AESEngine());
		ccm1.init(false, new ParametersWithIV(new KeyParameter(Kz), nonce));
		byte[] tmp = new byte[ciphertext.length];
		int len1 = ccm1.processBytes(ciphertext, 0, ciphertext.length, tmp, 0);
		try {
			len1 += ccm1.doFinal(tmp, len1);
			decode = new byte[len1];
			System.arraycopy(tmp, 0, decode, 0, len1);
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// System.out.println("decodeET: " + toHex(decode));

		long nano_startTime5 = System.nanoTime();
		System.out.println("Sum time decrypt: " + (nano_startTime5 - nano_startTime4));
		long multi = System.nanoTime();
		System.out.println("****************star_multi5_2: " +(System.nanoTime()-multi));
		System.out.println("****************star_add5_5: " +(System.nanoTime()-multi));
		System.out.println("****************SHA256_5_11: " +(System.nanoTime()-multi));
		System.out.println("****************AESCCM_5_11: " +(System.nanoTime()-multi));
		
	
	}

}
