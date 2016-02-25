package com.coinessa.btc.key.helper;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

/**
 * Created by d.romantsov on 24.02.2016.
 */
public class BIP39Test {

    private static final String TESTS_RESOURCE = "/BIP39.json";
    private BIP39 bip39 = new BIP39();

    @Test
    public void testEncodeWif() {
        String mnemonic = bip39.encodeWif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", "sdfs");
        String result = bip39.decodeToHexString(mnemonic, "sdfs");
        Assert.assertEquals("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d", result);
    }

    @Test
    public void bip39TrezorTest () {
        JSONObject testData = ResourcesUtil.readJsonObject(getClass(), TESTS_RESOURCE);
        JSONArray english = testData.getJSONArray("english");
        for ( int i = 0; i < english.length (); ++i )
        {
            JSONArray test = english.getJSONArray (i);
            String m = bip39.encode(ByteUtils.fromHex(test.getString(0)));
            assertTrue (m.equals (test.getString (1)));
        }
    }

    @Test
    public void bip39EncodeDecodeTest () {
        JSONObject testData = ResourcesUtil.readJsonObject(getClass(), TESTS_RESOURCE);
        JSONArray english = testData.getJSONArray ("english");
        for ( int i = 0; i < english.length (); ++i ) {
            JSONArray test = english.getJSONArray (i);
            byte[] m = bip39.decode (test.getString (1), "BOP");
            assertTrue (test.getString (1).equals(bip39.encode(m, "BOP")));
        }
        SecureRandom random = new SecureRandom ();
        for ( int i = 0; i < 1000; ++i ) {
            byte[] secret = new byte[32];
            random.nextBytes (secret);
            String e = bip39.encode (secret, "BOP");
            assertTrue (Arrays.equals(bip39.decode(e, "BOP"), secret));
        }
    }


}
