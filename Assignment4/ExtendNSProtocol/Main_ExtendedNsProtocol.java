package Assignment4.ExtendNSProtocol;

import Assignment4.ExtendNSProtocol.ExtendNeedhamSchroederUtil;

import javax.crypto.SecretKey;

public class Main_ExtendedNsProtocol {

    public static void main(String[] args) throws Exception {
        // Initialize the utilities and secret keys
        ExtendNeedhamSchroederUtil util = new ExtendNeedhamSchroederUtil();
        SecretKey keyAlice = util.generateSecretKey();
        SecretKey keyBob = util.generateSecretKey();

        // Start the Bob server in its own thread
        new Thread(() -> {
            try {
                ExtendBobServer bobServer = new ExtendBobServer(8888, keyBob);
                bobServer.listen();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        new Thread(() -> {
            try {
                ExtendKDCServer kdcServer = new ExtendKDCServer(9999, keyAlice, keyBob);
                kdcServer.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        // Run the Alice client in the main thread (or could also be in a new thread)
        ExtendAliceClient extendAliceClient = new ExtendAliceClient(keyAlice, "localhost", 8888, 9999);
        extendAliceClient.requestCommunicationWithBob();
    }
}
