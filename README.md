# chrome-cookie-password-decryption
The decryption implementation of Chrome cookie ('encrypted\_value' of the 'Cookies' SQLite file) or password ('password\_value' of the 'Login Data' SQLite file) on Windows. Both those which are not prefixed by 'v10' and those which are prefixed by 'v10' are supported. The codes in this repo are written in JDK1.8 and tested against Chrome 80.0.3987.106 x86 64bit on Windows 10 Professional 1903.

The encrypted cookie and password are stored in SQLite file 'Cookies' and 'Login Data', which can be found in Chrome user data directory. Chrome user data directory is shown in [https://chromium.googlesource.com/chromium/src/+/master/docs/user\_data\_dir.md](https://chromium.googlesource.com/chromium/src/+/master/docs/user_data_dir.md).

[https://github.com/n8henrie/pycookiecheat/issues/12](https://github.com/n8henrie/pycookiecheat/issues/12 "pycookiecheat") is a good place to learn how to find the symmetric key from keyring/keychain and decrypt cookie in Linux and Mac. However, pycookiecheat does not cover helpful information in Windows platform.

We can understand how cookie values are encrypted from Chromium source code. I have written an article in Chinese at [http://www.meilongkui.com/archives/1904](http://www.meilongkui.com/archives/1904). In short, according to the version of Chrome, there are two different encryption methods:

1. encrypted values that are not prefixed by 'v10' or 'v11'
2. encrypted values that are prefixed by 'v10' or 'v11'

If the encrypted values are not prefixed by 'v10' or 'v11', then Windows DPAPI (Data Protection Application Programming Interface) is used to encrypt the raw values. In theory, the Data Protection API can enable symmetric encryption of any kind of data; in practice, its primary use in the Windows operating system is to perform symmetric encryption of asymmetric private keys, using a user or system secret as a significant contribution of entropy. Actually, Chrome just uses DPAPI directly to get the encrpyted cookie values in this scenario.

If the encrypted values are prefixed by 'v10' or 'v11', then AES-256-GCM AEAD algorithm is used to encrypt the raw values and the symmetric key is encrypted by DPAPI. The encrypted symmetric key is stored in 'Local State' file which is a big JSON text file. The symmetric key encrypted by DPAPI is located at 'os\_crypt.encrypted\_key' in Base64 format. The AES-256-GCM AEAD algorithm uses 256bit (32Byte) key and 96bit (12Byte) nonce/IV and 128bit (16*8) tag length. Each encrypted values are constructed by 3Bytes v10/v11 prefix followed by 12Bytes nonce/IV and the ciphertext.

Because of the fact that DPAPI is hard to be handled directly for Windows platform and Java environment, we use windpapi4j. We use Bouncy Castle to implement AES-256-GCM instead of the native Java implementation which is limited by JCE.