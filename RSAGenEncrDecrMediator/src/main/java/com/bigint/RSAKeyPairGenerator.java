package com.bigint;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext; 
import org.apache.synapse.mediators.AbstractMediator;

public class RSAKeyPairGenerator extends AbstractMediator {
	
	private static final Log log = LogFactory.getLog(RSAKeyPairGenerator.class);
	
	public static String fpathPublic;
    public static String fpathPrivate;
    public static String sizeKeyS = "1024";
    //public static Integer sizeKey = Integer.parseInt(sizeKeyS);
    private PrivateKey privateKey;
    private PublicKey publicKey;

	public boolean mediate(MessageContext context) { 
		
		log.info("------ JAVA Mediator RSAKeyPairGenerator ------");
		fpathPublic = (String)context.getProperty("fpathPublic");
		fpathPrivate = (String)context.getProperty("fpathPrivate");
		sizeKeyS = (String)context.getProperty("sizeKeyS");
		
		if (fpathPublic == "" || fpathPrivate == "" || sizeKeyS == "") {
			log.info("Empty paramentr fpathPublic = " + fpathPublic +
                    " fpathPrivate = " + fpathPrivate +
                    "sizeKeyS = " + sizeKeyS);
        } else {
        	
            RSAKeyPairGenerator keyPairGenerator = null;
			try {
				keyPairGenerator = new RSAKeyPairGenerator();
			} catch (NoSuchAlgorithmException e) {
				log.info(e.getStackTrace());
			}

            String pubKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded());
            byte[] pubKeyB = pubKey.getBytes();
            try {
				keyPairGenerator.writeToFile(fpathPublic, pubKeyB);
			} catch (IOException e) {
				log.info(e.getStackTrace());
			}

            String privKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded());
            byte[] privKeyB = privKey.getBytes();
            try {
				keyPairGenerator.writeToFile(fpathPrivate, privKeyB);
			} catch (IOException e) {
				log.info(e.getStackTrace());
			}

            log.info(pubKey);
            log.info(privKey);
        }
		
		return true;
	}
	
	public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
		Integer sizeKey = Integer.parseInt(sizeKeyS);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(sizeKey);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
	
}
