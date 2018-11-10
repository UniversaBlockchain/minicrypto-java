/*
 * Copyright (c) 2017 Sergey Chernov, iCodici S.n.C, All Rights Reserved
 *
 * Written by Sergey Chernov <real.net.sergeych@gmail.com>, August 2017.
 *
 */

package com.icodici.minicrypto;

import com.icodici.minicrypto.digest.Digest;
import com.icodici.minicrypto.digest.HMAC;

import com.icodici.minicrypto.tools.Do;
import com.icodici.minicrypto.utils.Base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * All the functions that some key should be able to perform. The default implementation throws {@link
 * UnsupportedOperationException} - this is a valid behaviour for the function that the key is not able to perform.
 * Well, there could be keys that do nothing too. Just for ;)
 * <p>
 * Created by net.sergeych on 17.12.16.
 */
public abstract class AbstractKey implements KeyMatcher {
    public static final int FINGERPRINT_SHA256 = 7;
    public static final int FINGERPRINT_SHA384 = 8;

    protected KeyInfo keyInfo;

    public byte[] encrypt(byte[] plain) throws EncryptionError {
        throw new UnsupportedOperationException("this key can't encrypt");
    }

    public byte[] decrypt(byte[] plain) throws EncryptionError {
        throw new UnsupportedOperationException("this key can't decrypt");
    }

    public byte[] sign(InputStream input, HashType hashType) throws EncryptionError, IOException {
        throw new UnsupportedOperationException("this key can't sign");
    }

    public byte[] sign(byte[] input, HashType hashType) throws EncryptionError {
        try {
            return sign(new ByteArrayInputStream(input), hashType);
        } catch (IOException e) {
            throw new RuntimeException("unexpected IO exception while signing", e);
        }
    }

    public boolean verify(InputStream input, byte[] signature, HashType hashType) throws
            EncryptionError, IOException {
        throw new UnsupportedOperationException("this key can not verify signatures");
    }

    public boolean verify(byte[] input, byte[] signature, HashType hashType) throws
            EncryptionError {
        try {
            return verify(new ByteArrayInputStream(input), signature, hashType);
        } catch (IOException e) {
            throw new RuntimeException("unexpected IO exception", e);
        }
    }

    static Charset utf8 = Charset.forName("utf-8");

    public boolean verify(String input, byte[] signature, HashType hashType) throws
            EncryptionError {
        return verify(input.getBytes(utf8), signature, hashType);
    }

    public KeyInfo info() {
        return keyInfo;
    }

    public byte[] packedInfo() {
        return info().pack();
    }

    public byte[] pack() {
        throw new UnsupportedOperationException("not implemented");
    }

    public String packToBase64String() {
        return Base64.encodeString(pack());
    }

    public void unpack(byte[] bytes) throws EncryptionError {
        throw new UnsupportedOperationException("not implemented");
    }

    /**
     * If it is an instance of the private key, it will return true, then {@link #getPublicKey()} must return valid
     * key.
     *
     * @return
     */
    public boolean canSign() {
        return false;
    }

    public boolean isPublic() {
        return false;
    }

    public boolean isPrivate() {
        return false;
    }

    /**
     * Return valid public key, for example self, or raise the exception. This implementation returns self if {@link
     * #isPublic()} or throws an exception.
     *
     * @return
     */
    public AbstractKey getPublicKey() {
        if (isPublic())
            return this;
        throw new UnsupportedOperationException("this key can't provide public key");
    }

    public boolean matchType(AbstractKey other) {
        return info().matchType(other.info());
    }

    public boolean matchTag(AbstractKey other) {
        return info().matchTag(other.info());
    }

    public void setTag(String tag) {
        try {
            setTag(tag.getBytes("utf-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("utf8 is not supported?");
        }
    }

    public void setTag(byte[] tag) {
        info().setTag(tag);
    }

    @Override
    public String toString() {
        AbstractKey k = this instanceof PrivateKey ? getPublicKey() : this;
        return info().toString() + ":" + info().getBase64Tag();
    }


    /**
     * The fingerprint of the key is a uniqie sequence of bytes that matches the key without compromising it. In fact,
     * only public keys can have it, for symmetric keys the fingerprint will compromise it.
     * <p>
     * Therefore, the private key fingerprint is its public key fingerprint. The public key fingerprint is calculated
     * using some hash over it's parameters, see {@link PublicKey#fingerprint()}
     *
     * @return
     */
    public byte[] fingerprint() {
        throw new RuntimeException("this key does not support fingerprints");
    }

    /**
     * Arbitrary fingerprint calculation. As the digest may be different adn it might be useful to include more
     * information than a key to it, it is possible to update some digest instance with key data.
     * <p>
     * Create any digest you need and call this method to update it with a ket data.
     * <p>
     * This can and should be used to obtain higher-order composite fingerprints for high security setups.
     *
     * @return same digest instance (to chain calls)
     */
    public Digest updateDigestWithKeyComponents(Digest digest) {
        throw new RuntimeException("this key does not support fingerprints");
    }

    /**
     * Create a random (e.g. every call a different) sequence of bytes that identidy this key. There can almost infinite
     * number if anonynous ids for e key (more than 1.0E77), so it is really anonymous way to identify some key. The
     * anonymousId for public and private keys are the same.
     * <p>
     * Anonymous ID size is 64 bytes: first are 32 random bytes, last are HMAC(key, sha256) of these random bytes.
     * <p>
     * The most important thing about anonymous ids is that every time this call generates new id for the same key,
     * providing anonymous but exact identification of a key.
     * <p>
     * To check that the key matches some anonymousId, use {@link #matchAnonymousId(byte[])}.
     * <p>
     * Therefore, the private key fingerprint is its public key fingerprint. The public key fingerprint is calculated
     * using some hash over it's parameters, see {@link PublicKey#fingerprint()}
     *
     * @return
     */
    public byte[] createAnonymousId() {
        byte[] rvector = Do.randomBytes(32);
        HMAC hmac = new HMAC(fingerprint());
        hmac.update(rvector);
        byte[] result = new byte[64];
        System.arraycopy(rvector, 0, result, 0, 32);
        System.arraycopy(hmac.digest(), 0, result, 32, 32);
        return result;
    }

    /**
     * Check that the packed anonymousId matches current key. Use {@link #createAnonymousId()} to get a random anonymous
     * id for this key.
     *
     * @param packedId
     * @return true if it matches.
     * @throws IOException
     */
    public boolean matchAnonymousId(byte[] packedId) throws IOException {
        assert (packedId.length == 64);
        HMAC hmac = new HMAC(fingerprint());
        hmac.update(packedId, 0, 32);
        byte[] idDigest = Arrays.copyOfRange(packedId, 32, 64);
        return Arrays.equals(hmac.digest(), idDigest);
    }

    /**
     * Generate address for the key, see {@link KeyAddress} for more.
     *
     * @param useSha3_384 use SHA3-384 for hash, otherwise SHA3-256
     * @param keyMark some data code in 0..15 range inclusive
     * @return generated address
     */
    public KeyAddress address(boolean useSha3_384, int keyMark) {
        return new KeyAddress(this, keyMark, useSha3_384);
    }

    private KeyAddress shortAddress;

    public final KeyAddress getShortAddress() {
        if( shortAddress == null )
            shortAddress = address(false, 0);
        return shortAddress;
    }

    private KeyAddress longAddress;

    public final KeyAddress getLongAddress() {
        if( longAddress == null )
            longAddress = address(true, 0);
        return longAddress;
    }

    @Override
    public boolean isMatchingKey(AbstractKey key) {
        return getShortAddress().isMatchingKeyAddress(key.getShortAddress());
    }

    @Override
    public final boolean isMatchingKeyAddress(KeyAddress other) {
        return other.isLong() ?
                getLongAddress().isMatchingKeyAddress(other) : getShortAddress().isMatchingKeyAddress(other);
    }



}
