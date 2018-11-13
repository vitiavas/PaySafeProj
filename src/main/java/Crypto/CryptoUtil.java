package Crypto;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class CryptoUtil {
		
		private static final String ASYM_CIPHER = "RSA/ECB/PKCS1Padding";
		private static final String SYM_CIPHER = "AES/CBC/PKCS5Padding";
		private static final String HASH_FUNCTION = "SHA256";

		
		/** Digital signature algorithm. */
		private static final String SIGNATURE_ALGO = "SHA256withECDSA";
		private static final String PROVIDER = "BC";
		
		public static byte[] asymCipher(byte[] plainBytes, Key publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
			Cipher cipher = Cipher.getInstance(ASYM_CIPHER);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] cipherBytes = cipher.doFinal(plainBytes);
			return cipherBytes;
		}
		
		public static byte[] asymDecipher(byte[] cipherBytes, Key privateKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
			Cipher cipher = Cipher.getInstance(ASYM_CIPHER);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] plainBytes = cipher.doFinal(cipherBytes);
			return plainBytes;
		}

		public static byte[] symCipher(byte[] plainBytes, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
			Cipher cipher = Cipher.getInstance(SYM_CIPHER);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] bytes = cipher.doFinal(plainBytes);
			return bytes;
		}
		public static byte[] symDecipher(byte[] cipherBytes, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
			Cipher cipher = Cipher.getInstance(SYM_CIPHER);
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] bytes = cipher.doFinal(cipherBytes);
			return bytes;
		}
		
		
		static boolean verifyDigitalSignature(byte[] cipherDigest, byte[] bytes, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException{

			// verify the signature with the public key
			Signature ecdsaVerify = Signature.getInstance(SIGNATURE_ALGO,PROVIDER);
			ecdsaVerify.initVerify(publicKey);
			try {
				ecdsaVerify.update(bytes);
				return ecdsaVerify.verify(cipherDigest);
			} catch (SignatureException se) {
				System.err.println("Caught exception while verifying " + se);
				return false;
			}
		}
		
		/** Calculates digital signature from text. 
		 * @throws NoSuchProviderException */
		static byte[] makeDigitalSignature(byte[] bytes, PrivateKey privatekey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

			// get a signature object and sign the plain text with the private key
			Signature ecdsaSign = Signature.getInstance(SIGNATURE_ALGO, PROVIDER);
			ecdsaSign.initSign(privatekey);
			ecdsaSign.update(bytes);
			byte[] signature = ecdsaSign.sign();
			return signature;
		}
		
		public static Certificate getX509CertificateFromStream(InputStream in) throws CertificateException {
			try {
				CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
				Certificate cert = certFactory.generateCertificate(in);
				return cert;
			} finally {
				closeStream(in);
			}
		}
		
		public static Certificate getX509CertificateFromResource(String certificateResourcePath)
				throws IOException, CertificateException {
			InputStream is = getResourceAsStream(certificateResourcePath);
			return getX509CertificateFromStream(is);
		}
		
		private static InputStream getResourceAsStream(String resourcePath) {
			// uses current thread's class loader to also work correctly inside
			// application servers
			// reference: http://stackoverflow.com/a/676273/129497
			InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
			return is;
		}
		
		private static void closeStream(InputStream in) {
			try {
				if (in != null)
					in.close();
			} catch (IOException e) {
				// ignore
			}
		}

		public byte[] computeSHA256Hash(byte[] inputBytes) throws NoSuchAlgorithmException {
			byte[] digestBytes;
			MessageDigest digest = MessageDigest.getInstance(HASH_FUNCTION);
			digestBytes = digest.digest(inputBytes);
			return digestBytes;
		}

		public static PrivateKey getPrivateKeyFromKeyStoreResource(String keyStoreResourcePath, char[] keyStorePassword,
				String keyAlias, char[] keyPassword)
				throws FileNotFoundException, KeyStoreException, UnrecoverableKeyException {
			KeyStore keystore = readKeystoreFromResource(keyStoreResourcePath, keyStorePassword);
			return getPrivateKeyFromKeyStore(keyAlias, keyPassword, keystore);
		}
		
		private static KeyStore readKeystoreFromStream(InputStream keyStoreInputStream, char[] keyStorePassword)
				throws KeyStoreException {
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			try {
				keystore.load(keyStoreInputStream, keyStorePassword);
			} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
				throw new KeyStoreException("Could not load key store", e);
			} finally {
				closeStream(keyStoreInputStream);
			}
			return keystore;
		}
		
		public static PrivateKey getPrivateKeyFromKeyStore(String keyAlias, char[] keyPassword, KeyStore keystore)
				throws KeyStoreException, UnrecoverableKeyException {
			PrivateKey key;
			try {
				key = (PrivateKey) keystore.getKey(keyAlias, keyPassword);
			} catch (NoSuchAlgorithmException e) {
				throw new KeyStoreException(e);
			}
			return key;
		}
		
		
		public static KeyStore readKeystoreFromResource(String keyStoreResourcePath, char[] keyStorePassword)
				throws KeyStoreException {
			InputStream is = getResourceAsStream(keyStoreResourcePath);
			return readKeystoreFromStream(is, keyStorePassword);
		}
}

