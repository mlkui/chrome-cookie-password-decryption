package com.mlkui.chrome;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.windpapi4j.WinDPAPI;
import com.github.windpapi4j.WinDPAPI.CryptProtectFlag;
import com.mlkui.chrome.cookie.entity.ChromeCookie;
import com.mlkui.chrome.cookie.entity.DecryptedCookie;
import com.mlkui.chrome.cookie.entity.EncryptedCookie;

public class ChromeDecryptHelper
{
	private static final int QUERY_TIMEOUT = 30;

	private static final int kKeyLength = 256 / 8;
	private static final int kNonceLength = 96 / 8;
	private static final String kEncryptionVersionPrefix = "v10";
	private static final String kDPAPIKeyPrefix = "DPAPI";

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	private String cookieFileFullPathAndName;
	private String localStateFileFullPathAndName;

	public ChromeDecryptHelper(String cookieFileFullPathAndName)
	{
		this.cookieFileFullPathAndName = cookieFileFullPathAndName;
	}

	public ChromeDecryptHelper(String cookieFileFullPathAndName, String localStateFileFullPathAndName)
	{
		this.cookieFileFullPathAndName = cookieFileFullPathAndName;
		this.localStateFileFullPathAndName = localStateFileFullPathAndName;
	}

	public String getCookieFileFullPathAndName()
	{
		return cookieFileFullPathAndName;
	}

	public String getLocalStateFileFullPathAndName()
	{
		return localStateFileFullPathAndName;
	}

	public Set<ChromeCookie> getDecryptedCookies()
	{
		HashSet<ChromeCookie> cookieSet = new HashSet<>();

		File cookieFile = new File(cookieFileFullPathAndName);
		if (!cookieFile.exists())
		{
			return cookieSet;
		}

		Connection connection = null;
		try
		{
			File tempFile = new File(UUID.randomUUID().toString());
			FileUtils.copyFile(cookieFile, tempFile);

			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:" + tempFile.getAbsolutePath());
			Statement statement = connection.createStatement();
			statement.setQueryTimeout(QUERY_TIMEOUT);

			ResultSet resultSet = statement.executeQuery("SELECT * FROM cookies");

			while (resultSet.next())
			{
				String name = resultSet.getString("name");
				parseCookieFromResult(tempFile, name, cookieSet, resultSet);
			}
		}
		catch (Exception ex)
		{
			logger.error(ex.toString(), ex.fillInStackTrace());
		}
		finally
		{
			try
			{
				if (connection != null)
				{
					connection.close();
				}
			}
			catch (Exception e)
			{
			}
		}

		return cookieSet;
	}

	private void parseCookieFromResult(File cookieStore, String name, HashSet<ChromeCookie> cookieSet, ResultSet resultSet) throws SQLException
	{
		byte[] encryptedBytes = resultSet.getBytes("encrypted_value");
		String path = resultSet.getString("path");
		String domain = resultSet.getString("host_key");
		boolean secure = resultSet.getBoolean("is_secure");
		boolean httpOnly = resultSet.getBoolean("is_httponly");
		Date expires = resultSet.getDate("expires_utc");

		EncryptedCookie encryptedCookie = new EncryptedCookie(name, encryptedBytes, expires, path, domain, secure, httpOnly, cookieStore);
		DecryptedCookie decryptedCookie = decrypt(encryptedCookie);
		if (decryptedCookie != null)
		{
			cookieSet.add(decryptedCookie);
		}
		else
		{
			cookieSet.add(encryptedCookie);
		}
	}

	private DecryptedCookie decrypt(EncryptedCookie encryptedCookie)
	{
		byte[] decryptedBytes = null;

		byte[] encryptedValue = encryptedCookie.getEncryptedValue();
		try
		{
			boolean isV10 = new String(encryptedValue).startsWith("v10");
			if (WinDPAPI.isPlatformSupported())
			{
				WinDPAPI winDPAPI = WinDPAPI.newInstance(CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);

				if (!isV10)
				{
					decryptedBytes = winDPAPI.unprotectData(encryptedValue);
				}
				else
				{
					if (StringUtils.isEmpty(localStateFileFullPathAndName))
					{
						throw new IllegalArgumentException("Local State is required");
					}

					// Retrieve the AES key which is encrypted by DPAPI from Local State
					String localState = FileUtils.readFileToString(new File(this.localStateFileFullPathAndName));
					JSONObject jsonObject = new JSONObject(localState);
					String encryptedKeyBase64 = jsonObject.getJSONObject("os_crypt").getString("encrypted_key");
					byte[] encryptedKeyBytes = Base64.decodeBase64(encryptedKeyBase64);
					if (!new String(encryptedKeyBytes).startsWith(kDPAPIKeyPrefix))
					{
						throw new IllegalStateException("Local State should start with DPAPI");
					}
					encryptedKeyBytes = Arrays.copyOfRange(encryptedKeyBytes, kDPAPIKeyPrefix.length(), encryptedKeyBytes.length);

					// Use DPAPI to get the real AES key
					byte[] keyBytes = winDPAPI.unprotectData(encryptedKeyBytes);
					if (keyBytes.length != kKeyLength)
					{
						throw new IllegalStateException("Local State key length is wrong");
					}

					// Obtain the nonce.
					byte[] nonceBytes = Arrays.copyOfRange(encryptedValue, kEncryptionVersionPrefix.length(), kEncryptionVersionPrefix.length() + kNonceLength);

					// Strip off the versioning prefix before decrypting.
					encryptedValue = Arrays.copyOfRange(encryptedValue, kEncryptionVersionPrefix.length() + kNonceLength, encryptedValue.length);

					// Use BC provider to decrypt
					decryptedBytes = Aes256GcmHelper.getDecryptBytes(encryptedValue, keyBytes, nonceBytes);
				}
			}
		}
		catch (Exception e)
		{
			logger.error(e.toString(), e.fillInStackTrace());
			return null;
		}

		return new DecryptedCookie(encryptedCookie.getName(), encryptedValue, new String(decryptedBytes), encryptedCookie.getExpires(), encryptedCookie.getPath(), encryptedCookie.getDomain(), encryptedCookie.isSecure(), encryptedCookie.isHttpOnly(), encryptedCookie.getCookieStore());
	}
}
