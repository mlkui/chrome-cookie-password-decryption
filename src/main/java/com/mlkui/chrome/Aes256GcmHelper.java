package com.mlkui.chrome;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//EVP_aead_aes_256_gcm
//The same algorithm of the cookie and password encryption in Chrome (prefixed by v10)
public class Aes256GcmHelper
{
	private static Logger logger = LoggerFactory.getLogger(Aes256GcmHelper.class);

	private static final int KEY_LENGTH = 256 / 8;
	private static final int IV_LENGTH = 96 / 8;
	private static final int GCM_TAG_LENGTH = 16;

	static
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	public static final byte[] getEncryptedBytes(byte[] inputBytes, byte[] keyBytes, byte[] ivBytes)
	{
		try
		{
			if (inputBytes == null)
			{
				throw new IllegalArgumentException();
			}

			if (keyBytes == null)
			{
				throw new IllegalArgumentException();
			}
			if (keyBytes.length != KEY_LENGTH)
			{
				throw new IllegalArgumentException();
			}

			if (ivBytes == null)
			{
				throw new IllegalArgumentException();
			}
			if (ivBytes.length != IV_LENGTH)
			{
				throw new IllegalArgumentException();
			}

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivBytes);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
			return cipher.doFinal(inputBytes);
		}
		catch (Exception ex)
		{
			logger.error(ex.toString(), ex.fillInStackTrace());
			return null;
		}
	}

	public static final byte[] getDecryptBytes(byte[] inputBytes, byte[] keyBytes, byte[] ivBytes)
	{
		try
		{
			if (inputBytes == null)
			{
				throw new IllegalArgumentException();
			}

			if (keyBytes == null)
			{
				throw new IllegalArgumentException();
			}
			if (keyBytes.length != KEY_LENGTH)
			{
				throw new IllegalArgumentException();
			}

			if (ivBytes == null)
			{
				throw new IllegalArgumentException();
			}
			if (ivBytes.length != IV_LENGTH)
			{
				throw new IllegalArgumentException();
			}

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivBytes);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
			return cipher.doFinal(inputBytes);
		}
		catch (Exception ex)
		{
			logger.error(ex.toString(), ex.fillInStackTrace());
			return null;
		}
	}
}
