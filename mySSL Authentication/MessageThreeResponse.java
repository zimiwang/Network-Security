import java.security.cert.X509Certificate;

public class MessageThreeResponse {
    private X509Certificate certificate;
    private byte[] encryptedNonce;
    private byte[] nonce;

    public MessageThreeResponse(X509Certificate certificate, byte[] encryptedNonce, byte[] nonce) {
        this.certificate = certificate;
        this.encryptedNonce = encryptedNonce;
        this.nonce = nonce;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public byte[] getEncryptedNonce() {
        return encryptedNonce;
    }

    public byte[] getNonce() {
        return nonce;
    }
}
