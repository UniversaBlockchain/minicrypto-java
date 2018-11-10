/*
 * Copyright (c) 2017 Sergey Chernov, iCodici S.n.C, All Rights Reserved
 *
 * Written by Sergey Chernov <real.net.sergeych@gmail.com>, August 2017.
 *
 */

package com.icodici.minicrypto;

import com.icodici.minicrypto.digest.Crc32;
import com.icodici.minicrypto.digest.Digest;
import com.icodici.minicrypto.rsaoaep.RSAOAEPPrivateKey;

import com.icodici.minicrypto.boss.Boss;
import com.icodici.minicrypto.tools.Do;
import com.icodici.minicrypto.utils.Bytes;
import com.icodici.minicrypto.utils.Ut;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Basic private key used in the system. At the moment it is long RSA key ad probably more strong
 * or at least the same than widely used elliptic curves.
 * <p>
 * Created by net.sergeych on 02/12/16.
 */
public class PrivateKey extends AbstractKey {

    private final RSAOAEPPrivateKey privateKey = new RSAOAEPPrivateKey();

    public PrivateKey(byte[] packedBinaryKey, KeyInfo info) throws EncryptionError {
        this(packedBinaryKey);
        // the tag is changed. so we can't use it
//        this.keyInfo = info;
    }

    public PrivateKey(byte[] packedBinaryKey) throws EncryptionError {
        List parts = Boss.load(packedBinaryKey);
        if ((Integer) parts.get(0) == 0) {
            // e, p, q: private key
            try {

                Map<String, Object> pp = new HashMap<>();
                pp.put("e", ((Bytes) parts.get(1)).toArray());
                pp.put("p", ((Bytes) parts.get(2)).toArray());
                pp.put("q", ((Bytes) parts.get(3)).toArray());

                privateKey.updateFromHash(pp);
            } catch (Exception error) {
                error.printStackTrace();
                throw new EncryptionError("failed to parse private key", error);
            }
        } else if ((Integer) parts.get(0) == 1) {
            throw new EncryptionError("the key is public, not private");
        } else if ((Integer) parts.get(0) == 2) {
            throw new PasswordProtectedException("key is password protected");
        } else {
            throw new EncryptionError("Bad or unknown private key type");
        }
    }

    public PrivateKey(int bitStrength) {
        privateKey.generate(bitStrength, HashType.SHA1);
    }


    private AtomicBoolean inUse = new AtomicBoolean();
    private PrivateKey copy = null;
    private Object copyMutex = new Object();

    @Override
    public byte[] decrypt(final byte[] encrypted) throws EncryptionError {
        // mini-pooling of keys for parallel processing:
        if (inUse.getAndSet(true)) {
            // our copy is in use - create a copy for later use
            synchronized (copyMutex) {
                // we lock only to create a copy
                if (copy == null)
                    copy = new PrivateKey(pack());
            }
            // now the copy will do the same: encrypt or create a copy...
            return copy.decrypt(encrypted);
        } else {
            try {
                return privateKey.decrypt(encrypted);
            }
            finally {
                inUse.set(false);
            }
        }
    }

    private PublicKey cachedPublicKey;

    public PublicKey getPublicKey() {
        if (cachedPublicKey == null)
            cachedPublicKey = new PublicKey(privateKey.getPublicKey());
        return cachedPublicKey;
    }

    public byte[] pack() {
        final Map<String, Object> params = privateKey.toHash();
        return Boss.dumpToArray(new Object[]{
                0,
                params.get("e"),
                params.get("p"),
                params.get("q")
        });
    }

    @Override
    public byte[] sign(InputStream input, HashType hashType) throws EncryptionError, IOException {
        return privateKey.sign(input, hashType);
    }

    @Override
    public KeyInfo info() {
        if (keyInfo == null) {
            KeyInfo i = getPublicKey().info();
            keyInfo = new KeyInfo(KeyInfo.Algorythm.RSAPrivate, i.getTag(), privateKey
                    .getBitStrength() / 8);
        }
        return super.info();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof PrivateKey))
            return false;
        Map<String, Object> a = privateKey
                .toHash();
        Map<String, Object> b = ((PrivateKey) obj).privateKey
                .toHash();
        return Arrays.equals((byte[]) a.get("e"), (byte[]) b.get("e")) &&
                Arrays.equals((byte[]) a.get("p"), (byte[]) b.get("p")) &&
                Arrays.equals((byte[]) a.get("q"), (byte[]) b.get("q"));
    }

    @Override
    public int hashCode() {
        Map<String, Object> a = privateKey
                .toHash();
        byte[] key = (byte[]) a.get("p");
        return key[0] + (key[1] << 8) + (key[2] << 16) + (key[3] << 24);
    }

    @Override
    public byte[] fingerprint() {
        return getPublicKey().fingerprint();
    }

    public static PrivateKey fromPath(Path path) throws IOException {
        return new PrivateKey(Do.read(path.toAbsolutePath().toString()));
    }

    @Override
    public Digest updateDigestWithKeyComponents(Digest digest) {
        return getPublicKey().updateDigestWithKeyComponents(digest);
    }

    private static int getKDFRounds() {
        return Ut.isJUnitTest() ? 250 : 100000;
    }

    public byte[] packWithPassword(String password) throws EncryptionError {
        byte[] packedKey = pack();
        byte[] salt = getClass().getCanonicalName().getBytes();
        int rounds = getKDFRounds();
        KeyInfo.PRF function = KeyInfo.PRF.HMAC_SHA256;
        SymmetricKey key = new KeyInfo(function, rounds, salt, null)
                .derivePassword(password);

        byte[] packedEncryptedKey = key.encrypt(packedKey);

        return Boss.dumpToArray(new Object[]{
                2,
                rounds,
                salt,
                function.name(),
                packedEncryptedKey,
                new Crc32().update(packedKey).digest()
        });
    }

    public static PrivateKey unpackWithPassword(byte[] packedBinary, String password) throws EncryptionError {
        List params = Boss.load(packedBinary);
        if ((Integer) params.get(0) == 0) {
            return new PrivateKey(packedBinary);
        } else if ((Integer) params.get(0) == 1) {
            throw new EncryptionError("the key is public, not private");
        } else if ((Integer) params.get(0) == 2) {
            try {
                int rounds = (int) params.get(1);
                Bytes salt = (Bytes) params.get(2);
                String function = (String) params.get(3);
                Bytes packedEncryptedKey = (Bytes) params.get(4);
                Bytes digest = (Bytes) params.get(5);
                SymmetricKey key = new KeyInfo(KeyInfo.PRF.valueOf(function), rounds, salt.getData(), null)
                        .derivePassword(password);
                byte[] packedKey = key.decrypt(packedEncryptedKey.getData());
                byte[] resDigest = new Crc32().update(packedKey).digest();

                if (!digest.equals(new Bytes(resDigest))) {
                    throw new PasswordProtectedException("wrong password");
                }

                return new PrivateKey(packedKey);
            } catch (Exception e) {
                if (e instanceof PasswordProtectedException)
                    throw e;

                throw new EncryptionError("failed to parse password protected private key", e);
            }

        } else {
            throw new EncryptionError("Bad or unknown private key type");
        }
    }

    public static class PasswordProtectedException extends EncryptionError {

        public PasswordProtectedException(String message) {
            super(message);
        }
    }
}