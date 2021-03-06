package com.securityapp.classes;

import org.springframework.http.HttpHeaders;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.regex.Pattern;

public class SecurityHeaderChecker {

    private static Pattern cookieSecurePattern = Pattern.compile("/; Secure",Pattern.CASE_INSENSITIVE);
    private static Pattern hostPattern = Pattern.compile("__Host",Pattern.CASE_INSENSITIVE);
    private static Pattern sameSitePattern = Pattern.compile("; SameSite",Pattern.CASE_INSENSITIVE);

    //@JA - Returns JSON of the security scan results
    public static checkResults scanHeaders(HttpHeaders headers){

        checkResults results = new checkResults();

        //@JA - Convert the Set type to a hashMap that we can easily sort/find with. (https://stackoverflow.com/questions/16108734/convert-setmap-entryk-v-to-hashmapk-v)
        Set<Map.Entry<String, List<String>>> headerEntriesSet = headers.entrySet();
        Map<String, String> headerMapFromSet = new HashMap<>();
        for(Map.Entry<String, List<String>> entry : headerEntriesSet)
        {
            headerMapFromSet.put(entry.getKey(), entry.getValue().get(0));//@JA - Convert to simple string,string hash map for easy of use and efficiency moving forward.
        }

        Map<String,Map<String,String>> jsonResults = new HashMap<>();//@JA - List of hash maps to store the results.

        results.setRawHeaders(headerMapFromSet);//@JA - Sets the raw headers.
        checkHeaders(headerMapFromSet,results);//@JA - List of passing header results with information regarding it.
        missingHeaders(headerMapFromSet,results);//@JA - Finds all the missing headers and puts into a hashmap with the header in question and how to solve the issue.

        return results;
    }

    //@JA - Checks for problems in existing headers
    static void checkHeaders(Map<String,String> headerData,checkResults result){
        Map<String,String> returnData = new HashMap<>();
        StringJoiner joiner = new StringJoiner(" ");

        //Cookie security checks.
        if(headerData.containsKey("Set-Cookie")){
            String setCookieProblems = "";
            String cookieData = headerData.get("Set-Cookie");

            //@JA - Check if it contains the secure flag or not.  Note that this is not the best RegEx for this, this is merely a DEMO.
            if(!cookieSecurePattern.matcher(cookieData).find()){
                joiner.add("The 'secure' flag is not set on this cookie.");
                result.setGrade(result.getGrade()-1);
            }

            //Check for Cookie Prefix
            if(!hostPattern.matcher(cookieData).find()){
                joiner.add("There is no Cookie Prefix on this cookie.");
                result.setGrade(result.getGrade()-1);
            }

            //Check for SameSite Cookie.
            if(!sameSitePattern.matcher(cookieData).find()){
                joiner.add("This is not a SameSite Cookie.");
                result.setGrade(result.getGrade()-1);
            }

            setCookieProblems = joiner.toString();
            returnData.put("Set-Cookie",setCookieProblems);
        }
        if(headerData.containsKey("X-Powered-By")){
            returnData.put("X-Powered-By","X-Powered-By can usually be seen with values like \"PHP/5.5.9-1ubuntu4.5\" or \"ASP.NET\". Trying to minimise the amount of information you give out about your server is a good idea. This header should be removed or the value changed.");
            result.setGrade(result.getGrade()-1);
        }
        if(headerData.containsKey("Server")){
            returnData.put("Server","This Server header seems to advertise the software being run on the server but you can remove or change this value.");
            result.setGrade(result.getGrade()-1);
        }

        result.setProblemHeaders(returnData);//@JA - Mutate by reference the result.
    }

    //@JA - Checks for missing headers.  TODO: Add more headers to search for! This is only a DEMO
    static void missingHeaders(Map<String,String> headerData,checkResults result){
        Map<String,String> returnData = new HashMap<>();

        //@JA - One by One check every possible missing header.
        if(headerData.containsKey("Strict-Transport-Security")){
            returnData.put("Strict-Transport-Security","Pass");
        }else{
            returnData.put("Strict-Transport-Security","HTTP Strict Transport Security is an excellent feature to support on your site and strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS. Recommended value \"Strict-Transport-Security: max-age=31536000; includeSubDomains\".");
            result.setGrade(result.getGrade()-1);
        }
        if(headerData.containsKey("Content-Security-Policy")){
            returnData.put("Content-Security-Policy","Pass");
        }else{
            returnData.put("Content-Security-Policy","Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets.");
            result.setGrade(result.getGrade()-1);
        }
        if(headerData.containsKey("X-Frame-Options")){
            returnData.put("X-Frame-Options","Pass");
        }else{
            returnData.put("X-Frame-Options","X-Frame-Options tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking. Recommended value \"X-Frame-Options: SAMEORIGIN\".");
            result.setGrade(result.getGrade()-1);
        }
        if(headerData.containsKey("X-Content-Type-Options")){
            returnData.put("X-Content-Type-Options","Pass");
        }else{
            returnData.put("X-Content-Type-Options","X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is \"X-Content-Type-Options: nosniff\".");
            result.setGrade(result.getGrade()-1);
        }
        if(headerData.containsKey("Referrer-Policy")){
            returnData.put("Referrer-Policy","Pass");
        }else{
            returnData.put("Referrer-Policy","Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites.");
            result.setGrade(result.getGrade()-1);
        }
        if(headerData.containsKey("Feature-Policy")){
            returnData.put("Feature-Policy","Pass");
        }else{
            returnData.put("Feature-Policy","Feature Policy is a new header that allows a site to control which features and APIs can be used in the browser.");
            result.setGrade(result.getGrade()-1);
        }

        result.setMissingHeaders(returnData);
    }
}
