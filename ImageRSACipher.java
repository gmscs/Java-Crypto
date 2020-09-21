package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.*;
import java.security.spec.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.*;

public class ImageRSACipher {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, Exception, InvalidKeyException {

        if(args.length != 3) {
            System.err.println("This program encrypts an image file with RSA.");
            System.err.println("Usage: ImageRSACipher [inputFile.png] [RSAKeyFile] [outputFile.png]");
            return;
        }

        final String inputFile = args[0];
        final String keyFile = args[1];
        final String outputFile = args[2];

        //get key
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFile));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, kf.generatePublic(spec));

        try (
            FileInputStream in = new FileInputStream(inputFile);
            FileOutputStream out = new FileOutputStream(outputFile)) {
                byte[] inputBuffer = new byte[117];
                int len = in.read(inputBuffer);
                while(len >= 0) {
                    byte[] outputBuffer = cipher.update(inputBuffer, 0, len);
                    out.write(outputBuffer);
                    len = in.read(inputBuffer);
                }
            }
    }
}
