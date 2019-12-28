package com.securityapp.classes;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.http.HttpHeaders;

public class TestScanController {
    @Test
    public void jUnitInitialAssertionTest(){
        Assert.assertTrue(true);
    }

    //@JA - This is a very rudimentary DEMO of unit testing.  This is not complete.
    @Test
    public void checkSecurityResultsGrade(){
        HttpHeaders testHeader = new HttpHeaders();
        //@JA - Below is some actual header data from www.google.com to use for this test.
        testHeader.add("Transfer-Encoding","chunked");
        testHeader.add("Server","gws");
        testHeader.add("Alt-Svc","quic=\\\":443\\\"; ma=2592000; v=\\\"46,43\\\",h3-Q050=\\\":443\\\"; ma=2592000,h3-Q049=\\\":443\\\"; ma=2592000,h3-Q048=\\\":443\\\"; ma=2592000,h3-Q046=\\\":443\\\"; ma=2592000,h3-Q043=\\\":443\\\"; ma=2592000");
        testHeader.add("P3P","CP=\\\"This is not a P3P policy! See g.co/p3phelp for more info.\\\"");
        testHeader.add("Date","Sat, 28 Dec 2019 00:39:47 GMT");
        testHeader.add("X-Frame-Options","SAMEORIGIN");
        testHeader.add("Accept-Ranges","none");
        testHeader.add("Cache-Control","private, max-age=0");
        testHeader.add("Set-Cookie","1P_JAR=2019-12-28-00; expires=Mon, 27-Jan-2020 00:39:47 GMT; path=/; domain=.google.com");
        testHeader.add("Vary","Accept-Encoding");
        testHeader.add("X-XSS-Protection","0");
        testHeader.add("Content-Type","text/html; charset=ISO-8859-1");

        checkResults results = SecurityHeaderChecker.scanHeaders(testHeader);//@JA - Does not actually make connection to Google.com in this case, but simulates a result that should generate a 'D' Grade.
        Assert.assertTrue(results.getGrade() == 1);
    }
}
