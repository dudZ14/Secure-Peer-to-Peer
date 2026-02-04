package node;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * P2PClient represents a client for peer-to-peer communication over SSL/TLS.
 * This client connects to a specified host and port to send commands and
 * retrieve responses from a peer server.
 * 
 * The client supports two main operations:
 * 1. Sending general commands and receiving string responses
 * 2. Fetching all synchronized data from a peer for synchronization purposes
 * 
 * @see CryptoUtil for SSL context configuration
 */
public class P2PClient {
	
	/** The hostname or IP address of the peer server */
    private final String host;
    
    /** The port number of the peer server */
    private final int port;

    /**
     * Constructs a new P2PClient with the specified host and port.
     * 
     * @param host the hostname or IP address of the peer server
     * @param port the port number of the peer server
     */
    public P2PClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    /**
     * Sends a command to the peer server and returns the response as a string.
     * The method establishes an SSL connection, sends the command, and reads
     * the response until a termination marker is received.
     * 
     * Response termination markers are: "END", lines starting with "OK", 
     * or lines starting with "ERROR".
     * 
     * @param command the command to send to the server
     * @return the response from the server as a trimmed string
     * @throws Exception if connection fails or any I/O error occurs
     */
    public String sendCommand(String command) throws Exception {
        try {
            SSLContext sc = CryptoUtil.getSSLContext();
            SSLSocketFactory ssf = sc.getSocketFactory();

            try (SSLSocket socket = (SSLSocket) ssf.createSocket(host, port);
                    BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

                String[] parts = command.split(" ");
                String cmd = parts[0].toLowerCase();
                System.out.println("[Client] Sending command: " + cmd);

                out.write(command + "\n");
                out.flush();

                // Now read the response
                StringBuilder response = new StringBuilder();
                System.out.println("[Client] Awaiting response...");
                String line;
                while ((line = in.readLine()) != null) {
                    System.out.println("[Client] Received line: " + line);
                    if (line.equals("END") || line.startsWith("OK") || line.startsWith("ERROR")) {
                        System.out.println("[Client] End of response.");
                        break;
                    }
                    response.append(line).append("\n");
                    System.out.println("[Client] Appended line to response.");
                }
                System.out.println("[Client] Response received: " + response.toString().trim());

                return response.toString().trim();
            }
        } catch (ConnectException ce) {
            System.out.println("[Client] Connection refused to " + host + ":" + port);
            throw ce;
        } catch (Exception e) {
            System.out.println("[Client] Error sending command to " + host + ":" + port + " - " + e.getMessage());
            throw e;
        }
    }


    /**
     * Fetches all synchronized data from the peer server.
     * This method is used for synchronization between peers in the P2P network.
     * It sends a "SYNC" command and parses the response into a structured format.
     * 
     * The response format is expected to be:
     * tableName key plaintextBase64 timestamp originId originSignatureBase64 originCertBase64
     * 
     * Each entry is parsed and stored in a nested map structure:
     * Map<tableName, Map<key, Map<attribute, value>>>
     * 
     * @return a nested map containing all synchronized data from the peer
     * @throws Exception if connection fails or any I/O error occurs
     */
    public Map<String, Map<String, Map<String, String>>> fetchAllData() throws Exception {
        Map<String, Map<String, Map<String, String>>> allData = new ConcurrentHashMap<>();

        try (BufferedReader in = sendCommandWithReader("SYNC")) {
            String line;
            while ((line = in.readLine()) != null) {
                if ("END".equals(line))
                    break;

                String[] parts = line.split(" ", 7);
                if (parts.length != 7)
                    continue;

                String tableName = parts[0];
                String key = parts[1];
                String plaintextBase64 = parts[2];
                long timestamp = Long.parseLong(parts[3]);
                String originId = parts[4];
                String originSignatureBase64 = parts[5];
                String originCertBase64 = parts[6];

                String plaintext = new String(Base64.getDecoder().decode(plaintextBase64), StandardCharsets.UTF_8);

                Map<String, String> entry = new HashMap<>();
                entry.put("value", plaintext);
                entry.put("timestamp", String.valueOf(timestamp));
                entry.put("originId", originId);
                entry.put("originSignatureBase64", originSignatureBase64);
                entry.put("originCertBase64", originCertBase64);

                allData.computeIfAbsent(tableName, _ -> new ConcurrentHashMap<>()).put(key, entry);
            }
        }

        return allData;
    }

    
    /**
     * Sends a command to the peer server and returns a BufferedReader
     * for reading the response stream.
     * 
     * This method is used internally by fetchAllData() and should be used
     * when the response needs to be processed as a stream rather than
     * read entirely into memory.
     * 
     * Note: The caller is responsible for closing the returned BufferedReader
     * and the underlying socket connection.
     * 
     * @param command the command to send to the server
     * @return a BufferedReader for reading the server's response
     * @throws Exception if connection fails or any I/O error occurs
     */
    public BufferedReader sendCommandWithReader(String command) throws Exception {
        SSLContext sc = CryptoUtil.getSSLContext();
        SSLSocketFactory ssf = sc.getSocketFactory();

        SSLSocket socket = (SSLSocket) ssf.createSocket(host, port);
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        out.write(command + "\n");
        out.flush();
        return in;
    }

}