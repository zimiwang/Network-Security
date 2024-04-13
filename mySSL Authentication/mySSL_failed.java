public class mySSL_failed {

    public static void main(String[] args) throws Exception{
        // Start the Bob server in its own thread
        new Thread(() -> {
            try{
                BobServer bobServer = new BobServer(1233);
                bobServer.listen();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        AliceClient aliceClient = new AliceClient();
        aliceClient.filedMutualAuthentication("localhost", 1233);
    }
}
