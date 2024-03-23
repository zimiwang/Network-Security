package Assignment4.OriginalNSProtocol.CBC;

import javax.crypto.SecretKey;

public class Main_OriginalNsProtocol_CBC {

    public static void main(String[] args) throws Exception {
        // Initialize the utilities and secret keys
        OriginalNeedhamSchroederUtil util = new OriginalNeedhamSchroederUtil();
        SecretKey keyAlice = util.generateSecretKey();
        SecretKey keyBob = util.generateSecretKey();

        // Start the Bob server in its own thread
        new Thread(() -> {
            try {
                OriginalBobServer bobServer = new OriginalBobServer(3456, keyBob);
                bobServer.listen();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        new Thread(() -> {
            try {
                OriginalKDCServer kdcServer = new OriginalKDCServer(3636, keyAlice, keyBob);
                kdcServer.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        // Run the Alice client in the main thread (or could also be in a new thread)
        OriginalAliceClient extendAliceClient = new OriginalAliceClient(keyAlice, "localhost", 3456, 3636);
        extendAliceClient.requestCommunicationWithBob();
//        System.out.println("\n " +
//                "--------Then we will simulate the reflect attack: ");
        extendAliceClient.ReflectionAttack();
    }
}
