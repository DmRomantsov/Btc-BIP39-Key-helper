package com.coinessa.btc.key.helper;

/**
 * Created by d.romantsov on 24.02.2016.
 */
public class BtcPrivateKeyConverter {

    public static String wifToPrivateKey(String wif) {
        String base58 = ByteUtils.toHex(Base58.decode(wif));
        return base58.substring(2, base58.length() - 8);
    }
}
