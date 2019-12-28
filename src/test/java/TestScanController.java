import com.securityapp.classes.SecurityHeaderChecker;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class TestScanController {
    @Test
    public void jUnitInitialAssertionTest(){
        assertTrue(true);
    }

    //@JA - This is a very rudimentary DEMO of unit testing.  This is not complete.
    @Test
    public void checkSecurityResultsGrade(){
        SecurityHeaderChecker checker = new SecurityHeaderChecker();

        //@JA - Below is some actual header data from www.google.com to use for this test.
        checker.headers.add("Transfer-Encoding","chunked");
        checker.headers.add("Server","gws");
        checker.headers.add("Alt-Svc","quic=\\\":443\\\"; ma=2592000; v=\\\"46,43\\\",h3-Q050=\\\":443\\\"; ma=2592000,h3-Q049=\\\":443\\\"; ma=2592000,h3-Q048=\\\":443\\\"; ma=2592000,h3-Q046=\\\":443\\\"; ma=2592000,h3-Q043=\\\":443\\\"; ma=2592000");
        checker.headers.add("P3P","CP=\\\"This is not a P3P policy! See g.co/p3phelp for more info.\\\"");
        checker.headers.add("Date","Sat, 28 Dec 2019 00:39:47 GMT");
        checker.headers.add("X-Frame-Options","SAMEORIGIN");
        checker.headers.add("Accept-Ranges","none");
        checker.headers.add("Cache-Control","private, max-age=0");
        checker.headers.add("Set-Cookie","1P_JAR=2019-12-28-00; expires=Mon, 27-Jan-2020 00:39:47 GMT; path=/; domain=.google.com");
        checker.headers.add("Vary","Accept-Encoding");
        checker.headers.add("X-XSS-Protection","0");
        checker.headers.add("Content-Type","text/html; charset=ISO-8859-1");

        String results = checker.securityScanResults("www.google.com");//@JA - Does not actually make connection to Google.com in this case, but simulates a result that should generate a 'D' Grade.
        assertTrue(checker.grade == 1);
    }
}
