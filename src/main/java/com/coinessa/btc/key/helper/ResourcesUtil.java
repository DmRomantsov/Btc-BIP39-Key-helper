package com.coinessa.btc.key.helper;

import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;

/**
 * Created by d.romantsov on 24.02.2016.
 */
public class ResourcesUtil {
    public static JSONObject readJsonObject (Class loader, String resource)  {
        return new JSONObject (readString(loader, resource));
    }

    public static String readString(Class loader ,String resource) {
        try {
            InputStream in = loader.getResourceAsStream(resource);
            byte[] data = IOUtils.toByteArray(in);
            return new String(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
