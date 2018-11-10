/*
 * Copyright (c) 2017 Sergey Chernov, iCodici S.n.C, All Rights Reserved
 *
 * Written by Sergey Chernov <real.net.sergeych@gmail.com>, August 2017.
 *
 */

package com.icodici.minicrypto;

import com.icodici.minicrypto.digest.Digest;
import com.icodici.minicrypto.digest.Sha256;
import com.icodici.minicrypto.rsaoaep.RSAOAEPPublicKey;
import com.icodici.minicrypto.boss.Boss;
import com.icodici.minicrypto.tools.Hashable;
import com.icodici.minicrypto.utils.Bytes;
import com.icodici.minicrypto.utils.Ut;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Created by net.sergeych on 02/12/16.
 */
public class PublicKey extends AbstractKey {
    private final RSAOAEPPublicKey publicKey;
    private final AtomicBoolean unpacked = new AtomicBoolean(false);
    private byte[] cachedHint;
    private boolean publicExponent;

    public PublicKey(AbstractPublicKey publicKey) {
        this.publicKey = (RSAOAEPPublicKey) publicKey;
        setupInfo(pack());
    }

    public PublicKey() {
        this.publicKey = new RSAOAEPPublicKey();
    }

    public PublicKey(final byte[] bytes) throws EncryptionError {
        this.publicKey = new RSAOAEPPublicKey();
        setupKey(bytes,null);
    }

    public PublicKey(final byte[] bytes, KeyInfo info) throws EncryptionError {
        this.publicKey = new RSAOAEPPublicKey();
        setupKey(bytes, info);
    }

//    public void setupKey(byte[] bytes) throws EncryptionError {
//        setupKey(bytes, null);
//    }

    @Override
    public boolean isPublic() {
        return true;
    }

    public int getBitStrength() {
        return publicKey.getBitStrength();
    }

    private void setupKey(byte[] bytes, KeyInfo info) throws EncryptionError {
        if(unpacked.getAndSet(true)) {
            throw new IllegalStateException("public key is already set");
        }

        List parts = Boss.load(bytes);
        switch ((Integer) parts.get(0)) {
            case 0:
            case 2:
                throw new EncryptionError("the key is private, not public");
            case 1:
                break;
            default:
                throw new EncryptionError("invalid packed public key");
        }


        try {
            // e, n
            Map<String, Object> hash = new HashMap<>();
            hash.put("e", ((Bytes) parts.get(1)).toArray());
            hash.put("n", ((Bytes) parts.get(2)).toArray());
            setComponents(hash);
        } catch (Exception error) {
            error.printStackTrace();
            throw new EncryptionError("failed to parse public key", error);
        }
        if (info == null)
            setupInfo(bytes);
        else
            keyInfo = info;
    }

    private void setupInfo(byte[] bytes) {
        keyInfo = new KeyInfo(KeyInfo.Algorythm.RSAPublic,
                              Arrays.copyOfRange(fingerprint(), 1, 6),
                              publicKey.getBitStrength() / 8);
    }

    private void setComponents(Map<String, Object> hash) throws Hashable.Error {
        publicKey.updateFromHash(hash);
        cachedHint = null;
    }

    private AtomicBoolean inUse = new AtomicBoolean();
    private PublicKey copy = null;
    private Object copyMutex = new Object();

    @Override
    public byte[] encrypt(final byte[] bytes) throws EncryptionError {
        if (inUse.getAndSet(true)) {
            // our copy is in use
            synchronized (copyMutex) {
                if (copy == null)
                    copy = new PublicKey(pack());
            }
            return copy.encrypt(bytes);
        } else {
            try {
                return publicKey.encrypt(bytes);
            }
            finally {
                inUse.set(false);
            }
        }
    }

    public byte[] encrypt(String plainText) throws EncryptionError {
        return encrypt(plainText.getBytes(Ut.utf8));
    }

//    public byte[] encrypt(byte[] bytes) throws EncryptionError {
//        return publicKey.encrypt(bytes);
//    }

    public byte[] pack() {
        Map<String, Object> params = publicKey.toHash();
        return Boss.dumpToArray(new Object[]{
                1,
                params.get("e"),
                params.get("n")
        });
    }

    public boolean verify(InputStream source, byte[] signature, HashType hashType) throws
            IOException {
        return publicKey.checkSignature(source, signature, hashType);
    }

    /**
     * Keys equality check. Only public keys are equal to each other. Right now private keys can't be equal to the
     * public even if the latter is its part.
     *
     * @param obj
     *         key to compare with. Should be PublicKey instaance.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof PublicKey) {
            PublicKey k = (PublicKey) obj;
            Map<String, Object> a = publicKey
                    .toHash();
            Map<String, Object> b = k.publicKey
                    .toHash();
            return Arrays.equals((byte[]) a.get("e"), (byte[]) b.get("e")) &&
                    Arrays.equals((byte[]) a.get("n"), (byte[]) b.get("n"));
        }
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        Map<String, Object> a = publicKey
                .toHash();
        byte[] key = (byte[]) a.get("n");
        return key[0] + (key[1] << 8) + (key[2] << 16) + (key[3] << 24);
    }

    private byte[] _fingerprint;

    @Override
    public byte[] fingerprint() {
        synchronized (publicKey) {
            if (_fingerprint == null) {
                _fingerprint = new byte[33];
                _fingerprint[0] = (byte) FINGERPRINT_SHA256;
                System.arraycopy(
                        updateDigestWithKeyComponents(new Sha256()).digest(),
                        0,
                        _fingerprint,
                        1,
                        32);
            }
            return _fingerprint;
        }
    }

    @Override
    public Digest updateDigestWithKeyComponents(Digest digest) {
        Map<String, Object> a = publicKey.toHash();
        digest.update((byte[]) a.get("e")).update((byte[]) a.get("n"));
        return digest;
    }


    public long getPublicExponent() {
        Map<String, Object> params = publicKey.toHash();
        byte[] arr = (byte[]) params.get("e");
        long e = 0;
        for (int i = 0; i < arr.length; i++)
            e = (e << 8) | arr[i];
        return e;
    }
}
