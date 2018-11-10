package com.icodici.minicrypto.rsaoaep;

import com.icodici.minicrypto.PrivateKey;
import com.icodici.minicrypto.boss.Boss;
import com.icodici.minicrypto.utils.Bytes;

import java.security.SecureRandom;
import java.util.ArrayList;

/**
 * The class capable of serialization and deserialization of {@link RSAOAEPPrivateKey} to BOSS format and back,
 * to support the .unikey file format.
 */
public class UnikeyFactory {

    /**
     * Given the .unikey-format byte array with the private key, create the {@link RSAOAEPPrivateKey}.
     */
    static RSAOAEPPrivateKey rsaOaepPKFromUnikey( byte[] bytes) {
        assert bytes != null;

        try {
            final ArrayList unpackedFromBoss = Boss.load(bytes);

            assert ((Integer) unpackedFromBoss.get(0)) == 0;

            final byte[]
                    e = ((Bytes) unpackedFromBoss.get(1)).toArray(),
                    p = ((Bytes) unpackedFromBoss.get(2)).toArray(),
                    q = ((Bytes) unpackedFromBoss.get(3)).toArray();

            return new RSAOAEPPrivateKey(
                    e, p, q,
                    RSAOAEPPrivateKey.DEFAULT_OAEP_HASH, RSAOAEPPrivateKey.DEFAULT_MGF1_HASH,
                    new SecureRandom());
        } catch (Throwable e) {
            return null;
        }
    }

    /**
     * Given the .unikey-format byte array with the private key, create the {@link PrivateKey}.
     */
    public static PrivateKey fromUnikey( byte[] bytes) {
        assert bytes != null;
        try {
            return new PrivateKey(bytes);
        } catch (Throwable e) {
            return null;
        }
    }

    /**
     * Given the {@link RSAOAEPPrivateKey}, create the .unikey-format byte array.
     */
    static byte[] toUnikey( RSAOAEPPrivateKey privateKey) {
        assert privateKey != null;
        return privateKey.pack();
    }

    /**
     * Given the {@link RSAOAEPPrivateKey}, create the .unikey-format byte array.
     */
    public static byte[] toUnikey( PrivateKey privateKey) {
        assert privateKey != null;
        return privateKey.pack();
    }
}
