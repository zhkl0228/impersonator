package tech.kwik.core.crypto;

import junit.framework.TestCase;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.NullLogger;

import java.util.Arrays;

/**
 * What a Retry does to the Initial keys, which is not quite what it looks like.
 * <p>
 * RFC 9001 section 5.2 changes the Initial secrets when a Retry arrives, and says what the change is
 * for: the secrets "used for constructing subsequent Initial packets". Receiving is section 4.9.1,
 * where Initial keys are discarded "when it first sends a Handshake packet" - which a Retry is not.
 * So the keys the peer's Initial packets were protected with before the Retry are still worth having,
 * and this is where they are kept.
 * <p>
 * It matters because a server may answer a first flight with a Retry <em>and</em> a CONNECTION_CLOSE,
 * which RFC 9000 section 10.2.3 allows it to put in an Initial packet. Both arrive at once; the Retry
 * is processed first; and the close is then protected with keys that have just been replaced. Without
 * these, the client discards the close as undecryptable and waits out its connect timeout for an
 * answer it has already been given. nghttp2.org does exactly that to about one connection in fifty -
 * see docs/tools/README.md, where the packets are read out - and it is what took a failure there from
 * a five second timeout with no reason to a 149 ms failure that says the peer closed the connection.
 */
public class ConnectionSecretsTest extends TestCase {

    private static final byte[] ORIGINAL_DCID = { 1, 2, 3, 4, 5, 6, 7, 8 };
    private static final byte[] RETRY_SCID = { 9, 10, 11, 12, 13, 14, 15, 16 };

    private ConnectionSecrets secrets() {
        ConnectionSecrets secrets =
                new ConnectionSecrets(new VersionHolder(Version.getDefault()), Role.Client, null, new NullLogger());
        secrets.computeInitialKeys(ORIGINAL_DCID);
        return secrets;
    }

    /** Nothing to keep until a Retry has replaced something. */
    public void testAConnectionThatWasNotRetriedKeepsNoOtherKeys() {
        assertNull(secrets().getOriginalPeerInitialAead());
    }

    /**
     * After a Retry the peer's Initial keys are new ones, and the old ones are still there. Both
     * halves matter: the new keys are what the server will protect its next Initial packets with, and
     * the old ones are what it protected the ones already in flight with.
     */
    public void testARetryKeepsTheKeysThePeerHasAlreadyUsed() throws Exception {
        ConnectionSecrets secrets = secrets();
        Aead beforeRetry = secrets.getPeerAead(EncryptionLevel.Initial);

        secrets.recomputeInitialKeys(RETRY_SCID);

        assertSame("the keys from before the Retry must be the ones that are kept",
                beforeRetry, secrets.getOriginalPeerInitialAead());
        Aead afterRetry = secrets.getPeerAead(EncryptionLevel.Initial);
        assertNotSame("and the connection must go on with new ones", beforeRetry, afterRetry);
        assertFalse("which are derived from the Retry's connection id and so are different keys",
                Arrays.equals(beforeRetry.getHp(), afterRetry.getHp()));
    }

    /**
     * And they go when the Initial keys go. RFC 9001 section 4.9.1 is the moment reading Initial
     * packets stops meaning anything: "a client MUST discard Initial keys when it first sends a
     * Handshake packet ... Endpoints MUST NOT send Initial packets after this point."
     */
    public void testDiscardingTheInitialKeysDiscardsThoseToo() {
        ConnectionSecrets secrets = secrets();
        secrets.recomputeInitialKeys(RETRY_SCID);
        assertNotNull(secrets.getOriginalPeerInitialAead());

        secrets.discardKeys(EncryptionLevel.Initial);

        assertNull(secrets.getOriginalPeerInitialAead());
    }
}
