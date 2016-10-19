package org.eluder.jadcrypt.kms;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import org.eluder.jadcrypt.Encoding;

import java.util.*;

public class JadcryptKmsCli {

    public static void main(String[] args) {
        Regions region = null;
        String keyId = null;
        Encoding encoding = Encoding.HEX;
        Map<String, String> context = new HashMap<>();
        List<String> arguments = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-r":
                case "--region":
                    region = Regions.fromName(args[++i]);
                    break;

                case "-k":
                case "--keyId":
                    keyId = args[++i];
                    break;

                case "-c":
                case "--context":
                    String[] params = args[++i].split(":");
                    context.put(params[0], params[1]);
                    break;

                case "-e":
                case "--encoding":
                    encoding = Encoding.of(args[++i]);
                    break;

                default:
                    arguments.add(args[i]);
                    break;

            }
        }
        AWSKMSClient client = new AWSKMSClient();
        Optional.ofNullable(region).ifPresent(client::withRegion);

        JadcryptKms jadcrypt = new JadcryptKmsImpl(client, encoding);

        if ("encrypt".equalsIgnoreCase(arguments.get(0))) {
            String encrypted = jadcrypt.encrypt(arguments.get(1), keyId, context);
            System.out.println("Encrypted data:\n" + encrypted);
        } else if ("decrypt".equalsIgnoreCase(arguments.get(0))) {
            String decrypted = jadcrypt.decrypt(arguments.get(1), context);
            System.out.println("Decrypted data:\n" + decrypted);
        }
    }
}
