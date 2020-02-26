package com.mlkui.chrome.test;

import java.util.Set;

import org.junit.Test;

import com.mlkui.chrome.ChromeDecryptHelper;
import com.mlkui.chrome.cookie.entity.ChromeCookie;

public class ChromeCookieTest
{
	@Test
	public void test()
	{
		String cookieFileFullPathAndName = "D:\\chrome\\test-user-data\\Default\\Cookies";
		String localStateFileFullPathAndName = "D:\\chrome\\test-user-data\\Local State";
		ChromeDecryptHelper chromeDecryptHelper = new ChromeDecryptHelper(cookieFileFullPathAndName, localStateFileFullPathAndName);
		Set<ChromeCookie> chromeCookies = chromeDecryptHelper.getDecryptedCookies();
		for (ChromeCookie chromeCookie : chromeCookies)
		{
			System.out.println(chromeCookie);
		}
	}
}
