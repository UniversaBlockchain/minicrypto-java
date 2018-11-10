/*
 * Copyright (c) 2017 Sergey Chernov, iCodici S.n.C, All Rights Reserved
 *
 * Written by Sergey Chernov <real.net.sergeych@gmail.com>, August 2017.
 *
 */

package com.icodici.minicrypto.rsaoaep;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Among OAEP configuration options, two ones cover the hash functions
 * used for the primary hash and for the MGF.
 * Thus we need to be able to choose the hash upon the stored options.
 * <p>
 * Created by amyodov on 18.04.16.
 */
public class RSAOAEPDigestFactory {
    private static Class[] supportedDigestAlgorithmsClasses = {
            SHA1Digest.class,
            SHA224Digest.class,
            SHA256Digest.class,
            SHA384Digest.class,
            SHA512Digest.class,
    };

    static Map supportedDigestAlgorithmClassesByName = Collections.unmodifiableMap(new HashMap<String, Class>() {{
        for (Class digestClass : supportedDigestAlgorithmsClasses) {
            try {
                Digest dig = (Digest) (digestClass.newInstance());
                put(dig.getAlgorithmName(), digestClass);
            } catch (IllegalAccessException exc) {
                /*
                 * We are iterating over the predefined list of classes;
                 * all of them ARE expected to be castable to Digest.
                 */
                exc.printStackTrace();
            } catch (InstantiationException exc) {
                /*
                 * We are iterating over the predefined list of classes;
                 * all of them ARE expected to be castable to Digest.
                 */
                exc.printStackTrace();
            }
        }
    }});

    /**
     * Given the digest name, return a new instance of the appropriate digest class.
     * May return `null` if the digest `digestName` is not supported.
     */
    public static Digest getDigestByName(String digestName) {
        Class digestClass = (Class) supportedDigestAlgorithmClassesByName.get(digestName);
        if (digestClass == null) {
            return null;
        } else {
            try {
                return (Digest) (digestClass.newInstance());
            } catch (InstantiationException e) {
                return null;
            } catch (IllegalAccessException e) {
                return null;
            }
        }
    }

    /**
     * Create a new instance of Digest (e.g. for thread safety).
     */
    public static Digest cloneDigest(Digest digest) {
        try {
            return digest.getClass().newInstance();
        } catch (InstantiationException exc) {
            /* Do nothing more; this hash is expected to be clonable, but still revert to the original hash. */
            exc.printStackTrace();
            return digest;
        } catch (IllegalAccessException exc) {
            /* Do nothing more; this hash is expected to be clonable, but still revert to the original hash. */
            exc.printStackTrace();
            return digest;
        }
    }
}
