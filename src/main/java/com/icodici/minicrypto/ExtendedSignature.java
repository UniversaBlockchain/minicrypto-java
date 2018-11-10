/*
 * Copyright (c) 2017 Sergey Chernov, iCodici S.n.C, All Rights Reserved
 *
 * Written by Sergey Chernov <real.sergeych@gmail.com>, August 2017.
 *
 */

package com.icodici.minicrypto;

import com.icodici.minicrypto.digest.Sha3_384;
import com.icodici.minicrypto.digest.Sha512;
import com.icodici.minicrypto.boss.Boss;
import com.icodici.minicrypto.utils.Bytes;
import org.threeten.bp.ZonedDateTime;

import java.util.HashMap;
import java.util.Map;


public class ExtendedSignature {

    static public Bytes keyId(AbstractKey key) {
        if (key instanceof PrivateKey)
            return new Bytes(key.getPublicKey().fingerprint());
        return new Bytes(key.fingerprint());
    }
    static public byte[] createTargetSignature(PublicKey publicKey, byte[] data, boolean savePublicKey) {
        Map<String,Object> targetSignatureBinder = new HashMap();
        targetSignatureBinder.put("key", keyId(publicKey));
        targetSignatureBinder.put("sha512", new Sha512().digest(data));
        targetSignatureBinder.put("sha3_384", new Sha3_384().digest(data));
        targetSignatureBinder.put("created_at", ZonedDateTime.now());
        if (savePublicKey)
            targetSignatureBinder.put("pub_key", publicKey.pack());
        return Boss.pack(targetSignatureBinder);
    }

    /**
     * Sign the data with a given key.
     *
     * @param key is {@link PrivateKey} to sign with.
     * @param data to be sign with key.
     * @param savePublicKey if true key will stored in the {@link ExtendedSignature}.
     *
     * @return binary signature
     */
    static public byte[] sign(PrivateKey key, byte[] data, boolean savePublicKey) {
        try {
            byte[] targetSignature = ExtendedSignature.createTargetSignature(key.getPublicKey(),data,savePublicKey);

            return ExtendedSignature.of(targetSignature,
                    key.sign(targetSignature, HashType.SHA512),
                    key.sign(targetSignature, HashType.SHA3_384));

        } catch (EncryptionError e) {
            throw new RuntimeException("signature failed", e);
        }
    }

    static public byte[] of(byte[] targetSignature, byte[] sign, byte[] sign2) {
        Map<String,Object> result = new HashMap();
        result.put("exts", targetSignature);
        result.put("sign", sign);
        result.put("sign2", sign2);

        return Boss.pack(result);
    }
}
