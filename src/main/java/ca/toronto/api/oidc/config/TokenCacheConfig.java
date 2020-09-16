/**
 * 
 */
package ca.toronto.api.oidc.config;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.hazelcast.config.Config;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.spring.cache.HazelcastCacheManager;

@Configuration
@EnableCaching
@Profile("embedded")
public class TokenCacheConfig {

	private static Logger log = LoggerFactory.getLogger(TokenCacheConfig.class);

	@Bean
	  Config config() {
	    Config config = new Config();

	    MapConfig mapConfig = new MapConfig();
	    mapConfig.setTimeToLiveSeconds(3600);
	    config.getMapConfigs().put("adfsTokens", mapConfig);

	    return config;
	  }
}
