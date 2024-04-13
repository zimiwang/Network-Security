# SSL Handshake Structure

## Message Sequence
1. **Client to Server:**
   - **Message 1:** `client_name` (String), `cipherSuits` (String[])
   - **Message 3:** Alice’s certificate, KB+{Nonce_Alice}
   - **Message 5:** HMAC[all messages above + CLIENT] encrypted by session key

2. **Server to Client:**
   - **Message 2:** `cipher_choose` (String), Bob’s certificate
   - **Message 4:** KA+{Nonce_Bob}
   - **Message 6:** HMAC[all messages above + SERVER] encrypted by session key

## Compilation Instructions

Ensure you have Java installed on your system. This program uses the Java Random class for generating substitution tables and does not require any external libraries. It has been tested on the CADE lab machines.

### Compile the Java files
```bash
javac mySSL_failed.java
javac mySSL_successful.java
