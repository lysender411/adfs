package hello;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import static org.junit.Assert.*;		

public class HelloIntegrationTest {

    @Test
    public void getHello() throws Exception {
    	String host = System.getenv("SBWEB_HOST");
    	String port = System.getenv("SBWEB_PORT");
        String url = "http://"+host+":"+port;
        
        System.out.println("Url = " + url);
		
		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("GET");

		int responseCode = con.getResponseCode();

		BufferedReader in = new BufferedReader(
		        new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		//print result
		assertEquals(response.toString(), "Greetings from Spring Boot!");
		
     }
}
