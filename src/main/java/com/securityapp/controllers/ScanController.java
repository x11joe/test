package com.securityapp.controllers;

import com.securityapp.classes.SecurityHeaderChecker;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


//@JA - Note that content for this DEMO comes from (https://securityheaders.com/?q=google.com&followRedirects=on)
//@JA - This implementation DOES NOT do `follow redirects` but could be added in the future if needed.
//@JA - This implementation DOES NOT support multiple cookies very well at the moment.
@RestController
public class ScanController {

	@RequestMapping("/")
	public String index() {
		return "To get started, navigate to /scan/{www.website.com}, this will perform a manual scan for vulnerabilities";
	}

	@RequestMapping(path = "/scan/{website}", produces = "application/json")
	public String scan(@PathVariable("website") String website) {
		SecurityHeaderChecker checker = new SecurityHeaderChecker();
		return checker.securityScanResults(website);
	}

}
