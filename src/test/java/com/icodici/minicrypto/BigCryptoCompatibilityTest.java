package com.icodici.minicrypto;



import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.assertTrue;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class BigCryptoCompatibilityTest {
    @Test
    public void testWithBigCrypto() throws Exception {
        com.icodici.crypto.PrivateKey privateKeyFull = new com.icodici.crypto.PrivateKey(2048);
        com.icodici.crypto.PublicKey publicKeyFull = privateKeyFull.getPublicKey();
        byte[] fullPacked = privateKeyFull.pack();
        com.icodici.minicrypto.PrivateKey privateKeyMini = new com.icodici.minicrypto.PrivateKey(fullPacked);
        com.icodici.minicrypto.PublicKey publicKeyMini = privateKeyMini.getPublicKey();

        assertTrue(bytesEqual(fullPacked,privateKeyMini.pack()));

        assertTrue(bytesEqual(publicKeyFull.pack(),publicKeyMini.pack()));


        byte[] bytes = new byte[64];
        new Random().nextBytes(bytes);

        byte[] encryptedMini = publicKeyMini.encrypt(bytes);
        byte[] encryptedFull = publicKeyFull.encrypt(bytes);

        assertTrue(bytesEqual(bytes,privateKeyFull.decrypt(encryptedMini)));
        assertTrue(bytesEqual(bytes,privateKeyMini.decrypt(encryptedFull)));

        assertTrue(publicKeyFull.verify(bytes,privateKeyMini.sign(bytes,com.icodici.minicrypto.HashType.SHA3_384),com.icodici.crypto.HashType.SHA3_384));
        assertTrue(publicKeyFull.verify(bytes,privateKeyMini.sign(bytes,com.icodici.minicrypto.HashType.SHA512),com.icodici.crypto.HashType.SHA512));

        assertTrue(publicKeyMini.verify(bytes,privateKeyFull.sign(bytes,com.icodici.crypto.HashType.SHA3_384),com.icodici.minicrypto.HashType.SHA3_384));
        assertTrue(publicKeyMini.verify(bytes,privateKeyFull.sign(bytes,com.icodici.crypto.HashType.SHA512),com.icodici.minicrypto.HashType.SHA512));


        byte[] sigFull = com.icodici.minicrypto.ExtendedSignature.sign(privateKeyMini, bytes, true);
        byte[] sigMini = com.icodici.universa.contract.ExtendedSignature.sign(privateKeyFull, bytes, true);
        assertTrue(bytesEqual(sigFull,sigMini));

    }

    private boolean bytesEqual(byte[] encryptedMini, byte[] encryptedFull) {
        if(encryptedMini.length != encryptedFull.length)
            return false;
        for(int i = 0; i < encryptedMini.length;i++) {
            if(encryptedFull[i] != encryptedMini[i])
                return false;
        }
        return true;
    }
}