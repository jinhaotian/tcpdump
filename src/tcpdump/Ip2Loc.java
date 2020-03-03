package tcpdump;


import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

import org.apache.commons.lang3.StringUtils;



public class Ip2Loc {
	public static final  javax.ws.rs.client.Client client = ClientBuilder.newClient( );
	public static final String link ="http://ip2loc-load.internal.rhapsody.com/";
	
	public WebTarget target;
	public Map<String,String> cache = new HashMap<String,String>();
	
	public Ip2Loc() {
		target = client.target(link);
	}
	public String getCountryFromIP(String ip) {
		if("notexists".equals(ip)||"UNKNOWN".equals(ip)) {
			return "UNKNOWN";
		}
		if(cache.get(ip)!=null) {
			return cache.get(ip);
		}
		try {
			String response = target.path("perl/ip2co.pl").queryParam("ip", ip)
					.request().get(String.class);
			if(cache.size()>10000) {
				cache.clear();
			}
			String country = StringUtils.strip(response).toUpperCase();
			cache.put(ip, country);
			return country;
		} catch (Exception e) {
			return null;
		}
	}
	public void close() {
		if(client!=null) {
			client.close();
		}
	}
}
