package com.bigint;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeyEncrDecr extends AbstractMediator {

	private static final Log log = LogFactory.getLog(RSAKeyPairGenerator.class);

	public static String fpathPublic;
	public static String fpathPrivate;
	public static String strExec;
	public static String typeExec;

	private static String publicKey = "";
	private static String privateKey = "";

	public boolean mediate(MessageContext context) {

		fpathPublic = (String) context.getProperty("fpathPublic");
		fpathPrivate = (String) context.getProperty("fpathPrivate");
		strExec = (String) context.getProperty("strExec");
		typeExec = (String) context.getProperty("typeExec");
		log.info("------ JAVA Mediator RSAKeyEncrDecr ------");

		if (typeExec.equals("")) {

			log.info("Type of Exec Function is empty");

		} else if (typeExec.equals("encrypte")) {

			if (fpathPublic != "") {
				// File tempFilePublicKey = new File(fpathPublic);
				// boolean existsPublic = tempFilePublicKey.exists();

				BufferedReader reader;
				try {
					reader = new BufferedReader(new FileReader(fpathPublic));
					publicKey = reader.readLine();
					reader.close();
				} catch (FileNotFoundException e) {
					log.info(e.getStackTrace());
				} catch (IOException e) {
					log.info(e.getStackTrace());
				}

			} else {
				log.info("Path of PublicKey is Empty");
			}

		} else if (typeExec.equals("decrypte")) {

			if (fpathPrivate != "") {
				// File tempFilePrivateKey = new File(fpathPrivate);
				// boolean existsPrivate = tempFilePrivateKey.exists();

				BufferedReader reader;
				try {
					reader = new BufferedReader(new FileReader(fpathPrivate));
					privateKey = reader.readLine();
					reader.close();
				} catch (FileNotFoundException e) {
					log.info(e.getStackTrace());
				} catch (IOException e) {
					log.info(e.getStackTrace());
				}

			} else {

				log.info("FilePath of PrivateKey is Empty");

			}

		} else {

			log.info("Type of Exec Function = "+ typeExec +" is not encrypte or decrypte");

		}

		if (publicKey != "") {

			String encryptedString;
			try {
				encryptedString = Base64.getEncoder().encodeToString(encrypt(strExec, publicKey));
				context.setProperty("result", encryptedString);
				log.info(encryptedString);
			} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException
					| NoSuchAlgorithmException e) {
				log.info(e.getStackTrace());
			}

		} else if (privateKey != "") {

			String decryptedString;
			try {
				log.info(strExec);
				decryptedString = RSAKeyEncrDecr.decrypt(strExec, privateKey);
				context.setProperty("result", decryptedString);
				log.info(decryptedString);
			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
					| NoSuchPaddingException e) {
				log.info(e.getStackTrace());
			}

		} else {

			log.info("Something went wrong");

		}

		return true;
	}

	public static PublicKey getPublicKey(String base64PublicKey) {
		PublicKey publicKey = null;
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (NoSuchAlgorithmException e) {
			log.info(e.getStackTrace());
		} catch (InvalidKeySpecException e) {
			log.info(e.getStackTrace());
		}
		return publicKey;
	}

	public static PrivateKey getPrivateKey(String base64PrivateKey) {
		PrivateKey privateKey = null;
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			log.info(e.getStackTrace());
		}
		try {
			privateKey = keyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			log.info(e.getStackTrace());
		}
		return privateKey;
	}

	public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException,
			InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
		return cipher.doFinal(data.getBytes());
	}

	public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return new String(cipher.doFinal(data));
	}

	public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException,
			InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
	}

}
