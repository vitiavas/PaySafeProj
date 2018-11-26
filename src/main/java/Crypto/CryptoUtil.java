package Crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class CryptoUtil {
		
		public static final String ASYM_CIPHER = "RSA/ECB/PKCS1Padding";
		public static final String SYM_CIPHER = "AES/CBC/PKCS5Padding";
		public static final String HASH_FUNCTION = "SHA256";

		
		/** Digital signature algorithm. */
		public static final String SIGNATURE_ALGO = "SHA256withECDSA";
		public static final String BOUNCY_CASTLE_PROVIDER = "BC";
		
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

		public static byte[] symCipher(byte[] plainBytes, byte[] IV, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
			Cipher cipher = Cipher.getInstance(SYM_CIPHER);
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
			byte[] bytes = cipher.doFinal(plainBytes);
			return bytes;
		}
		public static byte[] symDecipher(byte[] cipherBytes, byte[] IV, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
			Cipher cipher = Cipher.getInstance(SYM_CIPHER);
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
			byte[] bytes = cipher.doFinal(cipherBytes);
			return bytes;
		}
		
		
		public static boolean verifyDigitalSignature(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException{

			// verify the signature with the public key
			Signature ecdsaVerify = Signature.getInstance(SIGNATURE_ALGO, BOUNCY_CASTLE_PROVIDER);
			ecdsaVerify.initVerify(publicKey);
			try {
				ecdsaVerify.update(signature);
				return ecdsaVerify.verify(data);
			} catch (SignatureException se) {
				System.err.println("Caught exception while verifying " + se);
				return false;
			}
		}
		
		public static KeyPair GenerateKeys()
		    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("B-571");
		    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", BOUNCY_CASTLE_PROVIDER);
		    g.initialize(ecSpec, new SecureRandom());
		    return g.generateKeyPair();
		}
		
		/** Calculates digital signature from text. 
		 * @throws NoSuchProviderException */
		public static byte[] makeDigitalSignature(byte[] bytes, PrivateKey privatekey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

			// get a signature object and sign the plain text with the private key
			Signature ecdsaSign = Signature.getInstance(SIGNATURE_ALGO, BOUNCY_CASTLE_PROVIDER);
			ecdsaSign.initSign(privatekey);
			ecdsaSign.update(bytes);
			byte[] signature = ecdsaSign.sign();
			return signature;
		}
	    public static X509Certificate getCertificate() throws CertificateException, NoSuchProviderException, FileNotFoundException {
	    	CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BOUNCY_CASTLE_PROVIDER);
			X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream("Certificate.cer"));
			return certificate;    	
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
	    public static byte[] encryptDataWithPrivateKey(byte[] data, X509Certificate encryptionCertificate, PrivateKey privateKey) throws CertificateEncodingException, CMSException, IOException, OperatorCreationException {
		    byte[] encryptedData = null;
		    if (null != data && null != encryptionCertificate) {
		    	
		    	  CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		          CMSTypedData msg = new CMSProcessableByteArray(data);
		    	  ContentSigner shaSigner = new JcaContentSignerBuilder("SHA1withECDSA").setProvider(CryptoUtil.BOUNCY_CASTLE_PROVIDER).build(privateKey);
		    	  gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
		    	    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
		    	    .build(shaSigner, encryptionCertificate));
		    	  return gen.generate(msg, false).getEncoded();
		    }
		    return encryptedData;
		}
	    public static byte[] encryptDataWithPublicKey(byte[] data, X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException {
		    byte[] encryptedData = null;
		    if (null != data && null != encryptionCertificate) {
		    			    	    
		    	CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
		        JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
		        generator.addRecipientInfoGenerator(jceKey);
		        CMSTypedData msg = new CMSProcessableByteArray(data);
		        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(CryptoUtil.BOUNCY_CASTLE_PROVIDER).build();
		        CMSEnvelopedData cmsEnvelopedData = generator.generate(msg,encryptor);
		        encryptedData = cmsEnvelopedData.getEncoded();
		    }
		    return encryptedData;
		}
	    
	    public static byte[] decryptDataWithPrivateKey(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {
		    byte[] decryptedData = null;
		    if (null != encryptedData && null != decryptionKey) {
		        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
		        @SuppressWarnings("unchecked")
				Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
		        KeyTransRecipientInformation recipientInfo  = (KeyTransRecipientInformation) recipients.iterator().next();
		        JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);
		        return recipientInfo.getContent(recipient);
		    }
		    return decryptedData;
		}
}

