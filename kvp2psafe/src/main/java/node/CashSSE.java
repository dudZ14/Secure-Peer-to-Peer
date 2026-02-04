package node;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CashSSE adaptado das práticas
 */
public class CashSSE {

    private static final String HMAC_ALG = "HmacSHA256";
    private static final String CIPHER_ALG = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final SecretKeySpec MASTER_KEY;

    static {
        try {
            byte[] keyBytes = new byte[20];
            RANDOM.nextBytes(keyBytes);
            MASTER_KEY = new SecretKeySpec(keyBytes, HMAC_ALG); // usar para HMAC
        } catch (Exception e) {
            throw new RuntimeException("Error initializing master key", e);
        }
    }

    /**
     * Deriva uma subchave específica para uma keyword e propósito.
     */
    private static byte[] deriveSubKey(String keyword, int purpose)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance(HMAC_ALG);
        // usamos MASTER_KEY bytes como chave HMAC (compatível com SecretKeySpec)
        SecretKeySpec mkspec = new SecretKeySpec(MASTER_KEY.getEncoded(), HMAC_ALG);
        hmac.init(mkspec);

        byte[] keywordBytes = keyword.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(keywordBytes.length + 4);
        buffer.put(keywordBytes);
        buffer.putInt(purpose);

        return hmac.doFinal(buffer.array());
    }

    /**
     * Wrapper para arrays de bytes com hashCode e equals adequados.
     */
    public static class ByteArray {
        private final byte[] arr;

        public ByteArray(byte[] array) {
            this.arr = array;
        }

        public byte[] getArr() {
            return arr;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(arr);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null || getClass() != obj.getClass())
                return false;
            ByteArray other = (ByteArray) obj;
            return Arrays.equals(arr, other.arr);
        }
    }

    /**
     * Cliente do CashSSE (sem SearchToken). Agora update aceita docId String.
     * O client conhece o servidor local (no nó).
     */
    public static class Client {

        // Contadores por keyword para garantir labels únicos
        private final Map<String, Integer> keywordCounters;
        private final Server server; // referência ao servidor local

        public Client(Server server) {
            this.keywordCounters = new ConcurrentHashMap<>();
            this.server = server;
        }

        /**
         * Atualiza índice: gera label l e valor d e envia ao servidor.
         * docId é String (ex: "tableName").
         */
        public void update(String keyword, String docId) throws Exception {
            int counter = keywordCounters.getOrDefault(keyword, 0);

            // Deriva K1 e K2 (GLOBAL - mesmo em todos os nós)
            byte[] k1 = deriveSubKey(keyword, 1);
            byte[] k2 = deriveSubKey(keyword, 2);

            // label = PRF(K1, c)
            SecretKeySpec k1Spec = new SecretKeySpec(k1, HMAC_ALG);
            Mac hmac = Mac.getInstance(HMAC_ALG);
            hmac.init(k1Spec);
            byte[] cbytes = ByteBuffer.allocate(4).putInt(counter).array();
            byte[] labelBytes = hmac.doFinal(cbytes);
            ByteArray label = new ByteArray(labelBytes);

            // value d = Enc_{K2}(docId) using AES-GCM with random IV and prefix IV to ciphertext
            // derive AES key from k2 (use 16 bytes for AES-128)
            byte[] k2_aes = Arrays.copyOf(k2, 16);
            SecretKeySpec k2Spec = new SecretKeySpec(k2_aes, CIPHER_ALG);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

            byte[] iv = new byte[GCM_IV_LENGTH];
            RANDOM.nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, k2Spec, gcmSpec);

            byte[] docBytes = docId.getBytes(StandardCharsets.UTF_8);
            byte[] cipherText = cipher.doFinal(docBytes);

            // store IV || ciphertext
            ByteBuffer out = ByteBuffer.allocate(iv.length + cipherText.length);
            out.put(iv);
            out.put(cipherText);
            ByteArray encryptedValue = new ByteArray(out.array());

            // send to server (local index)
            server.addToIndex(label, encryptedValue);

            // increment counter
            keywordCounters.put(keyword, counter + 1);
        }

        /**
         * Procura por keyword: gera k1,k2 e chama server.search(keyword).
         */
        public List<String> search(String keyword) throws Exception {
            return server.search(keyword);
        }
    }

    /**
     * Servidor do CashSSE P2P.
     */
    public static class Server {

        private final Map<ByteArray, List<ByteArray>> index;

        public Server() {
            this.index = new ConcurrentHashMap<>();
        }

        /**
         * Adiciona entrada ao índice (múltiplos valores por label possíveis).
         */
        public void addToIndex(ByteArray label, ByteArray encryptedValue) {
            index.computeIfAbsent(label, k -> new CopyOnWriteArrayList<>()).add(encryptedValue);
        }

        /**
         * Busca por keyword: deriva k1,k2 localmente e faz o loop c=0.. até não encontrar.
         * Retorna lista de docId strings (por exemplo "tableName:key").
         */
        public List<String> search(String keyword) throws Exception {
            // Derivar subchaves
            byte[] k1 = deriveSubKey(keyword, 1);
            byte[] k2 = deriveSubKey(keyword, 2);

            // Reuse internal function
            return search(k1, k2);
        }

        /**
         * Busca por pares k1,k2 (método interno): itera labels PRF(k1,c) e decifra com k2.
         */
        private List<String> search(byte[] k1, byte[] k2) throws Exception {
            LinkedList<String> results = new LinkedList<>();

            SecretKeySpec k1Spec = new SecretKeySpec(k1, HMAC_ALG);
            Mac hmac = Mac.getInstance(HMAC_ALG);
            hmac.init(k1Spec);

            byte[] k2_aes = Arrays.copyOf(k2, 16); // same sizing as in client
            SecretKeySpec k2Spec = new SecretKeySpec(k2_aes, CIPHER_ALG);

            int c = 0;
            while (true) {
                byte[] cbytes = ByteBuffer.allocate(4).putInt(c).array();
                byte[] labelBytes = hmac.doFinal(cbytes);
                ByteArray label = new ByteArray(labelBytes);

                List<ByteArray> stored = index.get(label);
                if (stored == null || stored.isEmpty()) {
                    break; // stop when label not found
                }

                for (ByteArray enc : stored) {
                    try {
                        String docId = decryptDocString(k2Spec, enc.getArr());
                        results.add(docId);
                    } catch (Exception e) {
                        // descriptografia falhou para este valor -> ignorar
                        System.err.println("[Server] Failed to decrypt entry for label c=" + c + ": " + e.getMessage());
                    }
                }

                c++;
            }

            return results;
        }

        /**
         * Descriptografa um valor (IV || ciphertext) e retorna a String docId.
         */
        private String decryptDocString(SecretKeySpec key, byte[] encryptedData) throws Exception {
            if (encryptedData.length < GCM_IV_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted data");
            }

            byte[] iv = Arrays.copyOfRange(encryptedData, 0, GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(encryptedData, GCM_IV_LENGTH, encryptedData.length);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            byte[] plain = cipher.doFinal(ciphertext);
            return new String(plain, StandardCharsets.UTF_8);
        }
    }
}
