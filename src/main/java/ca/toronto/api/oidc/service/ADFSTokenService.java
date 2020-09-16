package ca.toronto.api.oidc.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.spring.cache.HazelcastCache;
import com.hazelcast.spring.cache.HazelcastCacheManager;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ca.toronto.api.oidc.model.ADFSTokens;

@Service
public class ADFSTokenService {
	private static Logger log = LoggerFactory.getLogger(ADFSTokenService.class);
	
	@Autowired
	RestTemplate restTemplate;
	
//	@Autowired
//	Config config;
	
	@Value("${spring.security.oauth2.client.provider.adfs.token-uri}")
	private String tokenUrl;
	
	@Value("${spring.security.oauth2.client.registration.adfs.client-id}")
	private String clientId;
	
	@Value("${spring.security.oauth2.client.registration.adfs.client-secret}")
	private String clientSecret;
	
	public String getTokenUrl() {
		return tokenUrl;
	}

	public void setTokenUrl(String tokenUrl) {
		this.tokenUrl = tokenUrl;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	@Cacheable(value = "adfsTokens", key="#cid")
	public ADFSTokens getToken(String cid, ADFSTokens at) {
		log.info("fail to get rt in cache for "+cid+" , refresh token.");
	    return at;
	}

	@CachePut(value = "adfsTokens", key="#at.upn")
	public ADFSTokens updateToken(ADFSTokens at) {
		log.info("Executing update refresh token method...");
		log.info("update cache >>> "+at.getUpn()+" : "+at.getRefreshToken());
		
		return at;
	}
	
	@CacheEvict(value = "adfsTokens", allEntries = true)
	public void evictAllTokens() {}
	
	@CacheEvict(value = "adfsTokens", key = "#cid")
	public void evictSingleToken(String cid) {}

	
	public String refreshIdToken(String refreshToken){
		
		String idToken = null;
			
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-Type", "application/x-www-form-urlencoded");

		MultiValueMap<String, String> map= new LinkedMultiValueMap<>();
		map.add("grant_type", "refresh_token");
		map.add("client_id", clientId);
		map.add("refresh_token", refreshToken);
		map.add("client_secret", clientSecret);
		
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

		ResponseEntity<String> res = null;
		try {
			res = restTemplate.postForEntity(tokenUrl, request, String.class);
		} catch (Exception e) {
			log.error(e.getLocalizedMessage());
		}

		if (res != null && (res.getStatusCodeValue() >= 200 && res.getStatusCodeValue() < 300)) {
						
			String result = res.getBody();
log.info("result:"+result);			

			JsonObject tt = new JsonParser().parse(result).getAsJsonObject();
			if(tt==null || !tt.has("id_token")){
				log.info("can not refresh id_token.");
				return ("error:cannot refresh id_token");
			}			
			
			idToken = tt.get("id_token").getAsString();
				
		} else {
			log.error(String.format("Failed to retrieve from %s", tokenUrl));
			idToken = "fail to refresh id_token";
		}
		
		return idToken;
	
	}
/*	
	public CacheManager getCacheManager(){

		   HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance(config);
		   return new HazelcastCacheManager(hazelcastInstance);
		   
	}
	
	public int getCacheSize(){
		HazelcastCache cache = (HazelcastCache)getCacheManager().getCache("adfsTokens");
		
		return cache.getNativeCache().size();
	}
*/
}	