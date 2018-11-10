/*
 * Copyright (c) 2017 Sergey Chernov, iCodici S.n.C, All Rights Reserved
 *
 * Written by Sergey Chernov <real.net.sergeych@gmail.com>, August 2017.
 *
 */

package com.icodici.minicrypto;

/**
 * Abstract key for asymmetric encryption.
 */
public class AbstractAsymmetricKey extends AbstractKey {
    protected static int MAX_SALT_LENGTH = -1;


    /**
     * For given `emBits` (key length in bits) and `hLen` (hash size in bytes),
     * calculate the maximum possible salt size.
     * */
    protected static int getMaxSaltLength(int emBits, int hLen) {
//        saltLength = (getBitStrength() + 7) / 8 - primaryDigest.getDigestSize() - 2;
        return (emBits + 7) / 8 - hLen - 2;
    }
}
