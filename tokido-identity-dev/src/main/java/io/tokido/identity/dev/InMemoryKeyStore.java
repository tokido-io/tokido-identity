package io.tokido.identity.dev;

import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * DEV-ONLY in-memory {@link KeyStore}. Generates an ephemeral RS256 key per
 * process (or loads a pinned PEM for reproducible demos). Not for production:
 * keys are not durable, not encrypted, and not shared across instances.
 */
public final class InMemoryKeyStore implements KeyStore {

    private static final System.Logger LOG = System.getLogger(InMemoryKeyStore.class.getName());

    /** Immutable snapshot of the store; swapped atomically so readers never see a mid-rotation state. */
    private record State(SigningKey current, List<VerificationKey> retained) {
    }

    private final Clock clock;
    private volatile State state;

    private InMemoryKeyStore(SigningKey current, Clock clock) {
        this.state = new State(current, List.of());
        this.clock = clock;
    }

    /** Generate a fresh ephemeral RS256 key. Logs a loud dev warning. */
    public static InMemoryKeyStore ephemeral(Clock clock) {
        Objects.requireNonNull(clock, "clock");
        KeyPair kp = generateRsa();
        String kid = kidFor(kp.getPublic());
        LOG.log(System.Logger.Level.WARNING,
                "EPHEMERAL DEV SIGNING KEY — not for production, not multi-instance safe (kid={0})", kid);
        return new InMemoryKeyStore(signingKey(kid, kp, clock), clock);
    }

    /** Load a pinned key from PKCS#8 (private) + X.509 (public) PEM. Logs a dev warning. */
    public static InMemoryKeyStore fromPem(String privateKeyPem, String publicKeyPem, String kid, Clock clock) {
        Objects.requireNonNull(clock, "clock");
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(decodePem(privateKeyPem)));
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(decodePem(publicKeyPem)));
            LOG.log(System.Logger.Level.WARNING, "DEV KeyStore loaded from PEM — not for production use (kid={0})", kid);
            return new InMemoryKeyStore(
                    new SigningKey(kid, SignatureAlgorithm.RS256, priv, pub, clock.instant(), null), clock);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid RSA PEM material", e);
        }
    }

    /** Rotate: retain the current key for verification and generate a new current key. */
    public synchronized void rotate() {
        KeyPair kp = generateRsa();
        State s = state;
        List<VerificationKey> retained = new ArrayList<>(s.retained());
        retained.add(s.current().toVerificationKey());
        state = new State(signingKey(kidFor(kp.getPublic()), kp, clock), List.copyOf(retained));
    }

    @Override
    public SigningKey currentSigningKey() {
        return state.current();
    }

    @Override
    public List<VerificationKey> verificationKeys() {
        State s = state;
        List<VerificationKey> all = new ArrayList<>();
        all.add(s.current().toVerificationKey());
        all.addAll(s.retained());
        return List.copyOf(all);
    }

    private static SigningKey signingKey(String kid, KeyPair kp, Clock clock) {
        return new SigningKey(kid, SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(), clock.instant(), null);
    }

    private static KeyPair generateRsa() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }

    private static String kidFor(PublicKey pub) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(pub.getEncoded());
            return HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("kid derivation failed", e);
        }
    }

    private static byte[] decodePem(String pem) {
        String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s+", "");
        return Base64.getDecoder().decode(body);
    }
}
