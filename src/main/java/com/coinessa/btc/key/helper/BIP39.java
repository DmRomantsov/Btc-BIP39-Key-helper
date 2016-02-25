package com.coinessa.btc.key.helper;/*
 * Copyright 2013 bits of proof zrt.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.ValidationException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.StringTokenizer;

public class BIP39 {
	private final String worldListResource = "/english.txt";
	private String[] worldList;

	public BIP39() {
		Security.addProvider(new BouncyCastleProvider());
		worldList = ResourcesUtil.readString(getClass(), worldListResource).split(" ");
	}

	public String decodeToHexString(String mnemonic, String passphrase) {
		return ByteUtils.toHex(decode(mnemonic, passphrase));
	}

	/**
	 * Dencode data[] to mnemonic phrase with password phrase.
	 * @param mnemonic
	 * @param passphrase
	 * @return
	 * @throws ValidationException
	 */
	public byte[] decode (String mnemonic, String passphrase)
	{
		StringTokenizer tokenizer = new StringTokenizer (mnemonic);
		int nt = tokenizer.countTokens ();
		if ( nt % 6 != 0 )
		{
			throw new Bip39FormatExceptipn("invalid mnemonic - word cound not divisible by 6");
		}
		boolean[] bits = new boolean[11 * nt];
		int i = 0;
		while ( tokenizer.hasMoreElements () )
		{
			int c = Arrays.binarySearch (worldList, tokenizer.nextToken ());
			for ( int j = 0; j < 11; ++j )
			{
				bits[i++] = (c & (1 << (10 - j))) > 0;
			}
		}
		byte[] data = new byte[bits.length / 33 * 4];
		for ( i = 0; i < bits.length / 33 * 32; ++i )
		{
			data[i / 8] |= (bits[i] ? 1 : 0) << (7 - (i % 8));
		}
		byte[] check = Hash.sha256 (data);
		for ( i = bits.length / 33 * 32; i < bits.length; ++i )
		{
			if ( (check[(i - bits.length / 33 * 32) / 8] & (1 << (7 - (i % 8))) ^ (bits[i] ? 1 : 0) << (7 - (i % 8))) != 0 )
			{
				throw new Bip39FormatExceptipn("invalid mnemonic - checksum failed");
			}
		}
		try
		{
			SecretKey seedkey = new SecretKeySpec (("mnemonic" + passphrase).getBytes ("UTF-8"), "Blowfish");
			Cipher cipher = Cipher.getInstance ("BlowFish/ECB/NoPadding", "BC");
			cipher.init (Cipher.DECRYPT_MODE, seedkey);
			for ( i = 0; i < 1000; ++i )
			{
				data = cipher.doFinal (data);
			}
		}
		catch ( UnsupportedEncodingException | NoSuchAlgorithmException |
				NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e )
		{
			throw new Bip39FormatExceptipn("can not decrypt mnemonic", e);
		}
		return data;
	}

	/**
	 * Encode data[] to mnemonic phrase with password phrase.
	 * @param data
	 * @param passphrase
	 * @return mnemonic phrase
	 * @throws ValidationException
	 */
	public String encode(byte[] data, String passphrase)
	{
		if ( data.length % 8 != 0 )
		{
			throw new Bip39FormatExceptipn("can nor encode - data length not divisible with 8");
		}
		try
		{
			SecretKey seedkey = new SecretKeySpec (("mnemonic" + passphrase).getBytes ("UTF-8"), "Blowfish");
			Cipher cipher = Cipher.getInstance("BlowFish/ECB/NoPadding", "BC");
			cipher.init (Cipher.ENCRYPT_MODE, seedkey);
			for ( int i = 0; i < 1000; ++i )
			{
				data = cipher.doFinal (data);
			}
		}
		catch ( UnsupportedEncodingException | NoSuchAlgorithmException |
				NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e )
		{
			throw new Bip39FormatExceptipn("can not decrypt mnemonic", e);
		}
		return encode(data);
	}

	/**
	 * Encode data[] to mnemonic phrase without password phrase.
	 * @param data
	 * @return mnemonic phrase
	 * @throws ValidationException
	 */
	public String encode(byte[] data)
	{
		if ( data.length % 4 != 0 )
		{
			throw new Bip39FormatExceptipn("Invalid data length for mnemonic");
		}
		byte[] check = Hash.sha256 (data);

		boolean[] bits = new boolean[data.length * 8 + data.length / 4];

		for ( int i = 0; i < data.length; i++ )
		{
			for ( int j = 0; j < 8; j++ )
			{
				bits[8 * i + j] = (data[i] & (1 << (7 - j))) > 0;
			}
		}
		for ( int i = 0; i < data.length / 4; i++ )
		{
			bits[8 * data.length + i] = (check[i / 8] & (1 << (7 - (i % 8)))) > 0;
		}

		int mlen = data.length * 3 / 4;
		StringBuffer mnemo = new StringBuffer ();
		for ( int i = 0; i < mlen; i++ )
		{
			int idx = 0;
			for ( int j = 0; j < 11; j++ )
			{
				idx += (bits[i * 11 + j] ? 1 : 0) << (10 - j);
			}
			mnemo.append (worldList[idx]);
			if ( i < mlen - 1 )
			{
				mnemo.append (" ");
			}
		}
		return mnemo.toString ();
	}

	/**
	 * Encode private keys in WIF format to mnemonic phrase.
	 * @see <a href="https://en.bitcoin.it/wiki/Wallet_import_format">https://en.bitcoin.it/wiki/Wallet_import_format</a>
	 * @param wif
	 * @param passphrase
	 * @return
	 */
	public String encodeWif(String wif, String passphrase) {
		return encode(ByteUtils.fromHex(BtcPrivateKeyConverter.wifToPrivateKey(wif)), passphrase);
	}
}