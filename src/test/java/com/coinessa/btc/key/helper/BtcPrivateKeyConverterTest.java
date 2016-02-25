package com.coinessa.btc.key.helper;

import junit.framework.Assert;
import org.junit.Test;

/**
 * Created by d.romantsov on 24.02.2016.
 */
public class BtcPrivateKeyConverterTest {

    @Test
    public void testWifToPrivateConverter() throws Exception {
        Assert.assertEquals(BtcPrivateKeyConverter.wifToPrivateKey("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"),
                "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
    }
}
