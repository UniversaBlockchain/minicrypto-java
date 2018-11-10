/*
 * Copyright (c) 2017 Sergey Chernov, iCodici S.n.C, All Rights Reserved
 *
 * Written by Sergey Chernov <real.net.sergeych@gmail.com>, August 2017.
 *
 */

package com.icodici.minicrypto;

import java.io.IOException;

/**
 * Created by net.sergeych on 15/04/16.
 */
public class EncryptionError extends IOException {
    public EncryptionError() {
    }

    public EncryptionError(String reason) {
        super(reason);
    }

    public EncryptionError(String reason, Throwable cause) {
        super(reason, cause);
    }
}
