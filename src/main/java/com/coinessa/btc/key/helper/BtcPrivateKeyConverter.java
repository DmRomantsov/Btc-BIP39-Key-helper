package com.coinessa.btc.key.helper;

import java.util.Arrays;

/**
 * Created by d.romantsov on 24.02.2016.
 */
public class BtcPrivateKeyConverter {

    public static byte[] wifToPrivateKey(String wif) {
        //
        // Decode the private key
        //
        byte[] decodedKey = Base58.decodeChecked(wif);
        int version = (int)decodedKey[0]&0xff;

        //
        // The private key length is 33 for a compressed public key, otherwise it is 32
        //
        if (decodedKey.length == 33+1 && decodedKey[33] == (byte)1) {
            //isCompressed = true;
            return Arrays.copyOfRange(decodedKey, 1, decodedKey.length - 1);
        } else if (decodedKey.length == 32+1) {
            //isCompressed = false;
            return Arrays.copyOfRange(decodedKey, 1, decodedKey.length);
        }
        return null;
    }

    public static String wifToPrivateKeyStr(String wif) {
        return ByteUtils.toHex(wifToPrivateKey(wif));
    }
}
