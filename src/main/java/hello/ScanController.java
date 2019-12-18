package hello;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

@RestController
public class ScanController {

	private RestTemplate rest = new RestTemplate();
	private HttpHeaders headers;
	private HttpStatus status;

	@RequestMapping("/")
	public String index() {
		return "To get started, navigate to /scan/{website}, this will perform a manual scan for vulnerabilities";
	}

	@RequestMapping(path = "/scan/{website}", produces = "application/json")
	public String scan(@PathVariable("website") String website) {
		URI url = URI.create("https://"+website);
		//String result = rest.getForObject(url,String.class); //If we want the body data uncomment this.
		headers = rest.headForHeaders(url);
		ObjectMapper mapper = new ObjectMapper();
		try {
			String jsonStr = mapper.writeValueAsString(headers);
			return jsonStr;
		} catch (JsonProcessingException e) {
			e.printStackTrace();
			return "{Failed}";
		}
	}

}
