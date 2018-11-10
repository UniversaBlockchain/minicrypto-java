/*
 * Copyright (c) 2017 Sergey Chernov, iCodici S.n.C, All Rights Reserved
 *
 * Written by Sergey Chernov <real.net.sergeych@gmail.com>, August 2017.
 *
 */

package com.icodici.minicrypto.digest;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA512tDigest;

/**
 * SHA-512/256 (SHA-2 family) digest implementation.
 */
public class Sha512_256 extends SpongyCastleDigest {

    final org.spongycastle.crypto.Digest md = new SHA512tDigest(256);

    public Sha512_256() {
    }

    @Override
    protected int getChunkSize() {
        return 128;
    }

    @Override
    protected Digest getUnderlyingDigest() {
        return md;
    }
}
