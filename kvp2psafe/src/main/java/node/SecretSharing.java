package node;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * SecretSharing implements Shamir's Secret Sharing scheme for splitting a
 * secret into multiple shares and later reconstructing it from a subset
 * of those shares.
 * 
 * This implementation uses a finite field for mathematical operations
 * and supports threshold-based secret sharing where:
 * - A secret is split into n shares
 * - Any k shares (where k = polynomial degree + 1) can reconstruct the secret
 * - Fewer than k shares reveal no information about the secret
 * 
 * The class uses Horner's method for polynomial evaluation and
 * Lagrange interpolation for secret reconstruction.
 */
public class SecretSharing {
    private static final BigInteger field = new BigInteger("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16);
    private static final SecureRandom rndGenerator = new SecureRandom();

    /**
     * Splits a secret into multiple shares using Shamir's Secret Sharing scheme.
     * Creates a random polynomial of specified degree where the constant term
     * is the secret, and evaluates it at n points to generate shares.
     * 
     * The polynomial is: P(x) = a_d * x^d + ... + a_1 * x^1 + secret
     * where d is the polynomial degree and a_1..a_d are random coefficients.
     * 
     * @param polyDegree degree of the polynomial (k-1 where k is threshold)
     * @param nShareholders total number of shares to generate
     * @param secret the secret value to be shared (must be less than field modulus)
     * @return array of Share objects containing shareholder IDs and share values
     * @throws IllegalArgumentException if secret is not in the finite field
     */
    public static Share[] share(int polyDegree, int nShareholders, BigInteger secret) {
        // Creating polynomial: P(x) = a_d * x^d + ... + a_1 * x^1 + secret
        BigInteger[] polynomial = new BigInteger[polyDegree + 1];

        // Constant term (a0) = secret
        polynomial[0] = secret.mod(field);

        // Random coefficients a1..ad
        for (int i = 1; i <= polyDegree; i++) {
            polynomial[i] = new BigInteger(field.bitLength() - 1, rndGenerator).mod(field);
        }

        // Calculating shares
        Share[] shares = new Share[nShareholders];
        for (int i = 0; i < nShareholders; i++) {
            BigInteger shareholder = BigInteger.valueOf(i + 1); //shareholder id can be any positive number, except 0
            BigInteger share = calculatePoint(shareholder, polynomial);
            shares[i] = new Share(shareholder, share);
        }

        return shares;
    }

    /**
     * Reconstructs the secret from a set of shares using Lagrange interpolation.
     * Requires at least (degree + 1) shares to successfully reconstruct the secret.
     * 
     * The reconstruction uses the formula:
     * secret = Σ (y_i * Π (x_j / (x_j - x_i))) for j ≠ i
     * 
     * @param shares array of Share objects containing shareholder IDs and share values
     * @return the reconstructed secret
     * @throws IllegalArgumentException if insufficient shares are provided
     *         (needs at least degree + 1 shares where degree was used in share())
     */
    public static BigInteger combine(Share[] shares) {
        BigInteger secret = BigInteger.ZERO;

        for (int i = 0; i < shares.length; i++) {
            BigInteger xi = shares[i].getShareholder();
            BigInteger yi = shares[i].getShare();

            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for (int j = 0; j < shares.length; j++) {
                if (i == j) continue;
                BigInteger xj = shares[j].getShareholder();

                numerator = numerator.multiply(xj.negate()).mod(field); // -x_j
                denominator = denominator.multiply(xi.subtract(xj)).mod(field);
            }

            // Lagrange coefficient: numerator * denominator⁻¹ mod field
            BigInteger lagrangeCoefficient = numerator.multiply(denominator.modInverse(field)).mod(field);

            // Accumulate contribution to secret
            secret = secret.add(yi.multiply(lagrangeCoefficient)).mod(field);
        }

        return secret;
    }

    /**
     * Evaluates a polynomial at a given point using Horner's method for efficiency.
     * Horner's method reduces the number of multiplications needed to evaluate
     * a polynomial from O(n²) to O(n).
     * 
     * The polynomial is evaluated as:
     * ((((a_d * x + a_{d-1}) * x + ...) * x) + a0)
     * 
     * @param x the x-coordinate at which to evaluate the polynomial
     * @param polynomial array of polynomial coefficients where
     *        polynomial[0] is the constant term (a0)
     * @return P(x) = polynomial evaluated at point x
     */
    private static BigInteger calculatePoint(BigInteger x, BigInteger[] polynomial) {
        BigInteger result = BigInteger.ZERO;

        // Horner’s method: ((((a_d * x + a_{d-1}) * x + ...) * x) + a0)
        for (int i = polynomial.length - 1; i >= 0; i--) {
            result = result.multiply(x).add(polynomial[i]).mod(field);
        }

        return result;
    }

    /**
     * Inner class representing a share in the secret sharing scheme.
     * Each share consists of a shareholder ID and the corresponding
     * share value (y-coordinate of the polynomial).
     */
    public static class Share {
        private final BigInteger shareholder;
        private final BigInteger share;

        public Share(BigInteger shareholder, BigInteger share) {
            this.shareholder = shareholder;
            this.share = share;
        }

        public BigInteger getShare() {
            return share;
        }

        public BigInteger getShareholder() {
            return shareholder;
        }
        
        public String serialize() {
            return shareholder.toString() + ":" + share.toString(16);
        }
        
        public static Share deserialize(String data) {
            String[] parts = data.split(":");
            return new Share(
                new BigInteger(parts[0]),
                new BigInteger(parts[1], 16)
            );
        }
    }
}