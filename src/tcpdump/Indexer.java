package tcpdump;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;

import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RestClient;
import org.apache.commons.lang3.StringUtils;
import org.elasticsearch.client.RestClientBuilder.HttpClientConfigCallback;

import com.google.gson.Gson;

public class Indexer {
	private static Map<String,Map<String,String>> headerMap = new HashMap<String,Map<String,String>>();
	private static Map<String,Map<String,String>> respMap = new HashMap<String,Map<String,String>>();
	static DateFormat dateFormat = new SimpleDateFormat("dd MMM yyy HH:mm:ss z", Locale.US);
	static DateFormat isoDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");//new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
	
	public static void main(String[] args) {
		String filename = args[0];
		String indexName = args[1];
		String serverName = args[2];
		BufferedReader reader;
		Map<String,String> requestMap = new TreeMap<String,String>();
		Map<String,String> responseMap = new HashMap<String,String>();
		
		try {
			reader = new BufferedReader(new FileReader(filename));
			String line = reader.readLine();
			int i = 0;
			while (line != null) {
				if (line.contains(" > ")) {
					i++;
					if(i % 100 == 0) {
						System.out.println(i);
					}else {
						System.out.print(".");
					}

					String[] fields = line.split("\\s+");
					if (fields[4] != null && fields[4].charAt(fields[4].length()-1)==':') {
						fields[4] = fields[4].substring(0,fields[4].length()-1);
					}
					
					String id ;
					if (fields[4].contains("rds-authserver-prod")) {
						id =  fields[4] +"--"+ fields[2];
						String time = fields[0];
						ids.put(id, time);
						id = id + "--" + time;
						requestMap.put(id , line);
						line = handleRequest(id,reader);
						continue;
					}else if (fields[2].contains("rds-authserver-prod")) {
						id =  fields[2]+"--"+ fields[4];
						if(ids.get(id)==null) {
							System.out.println("abc");
						}
						id = id + "--"+ ids.get(id);
						responseMap.put(id, line);
						line = handleRespone(id,reader);
						continue;
					}
				}
								line = reader.readLine();
			}
			reader.close();
			System.out.println(".");
			Gson gsonObj = new Gson();
			final CredentialsProvider credentialsProvider =
				    new BasicCredentialsProvider();
				credentialsProvider.setCredentials(AuthScope.ANY,
				    new UsernamePasswordCredentials("elastic", "changeme"));
				
			RestClient elasticClient =   RestClient.builder(
				    new HttpHost(serverName, 9200, "http"))
					.setHttpClientConfigCallback(new HttpClientConfigCallback() {
				        @Override
				        public org.apache.http.impl.nio.client.HttpAsyncClientBuilder customizeHttpClient(
				                HttpAsyncClientBuilder httpClientBuilder) {
				            return httpClientBuilder
				                .setDefaultCredentialsProvider(credentialsProvider);
				        }
				    }).build();
			
			for (String id:requestMap.keySet() ) {
				System.out.print(id);
				Map<String,String> header = new TreeMap<String,String>();
				if (headerMap.get(id) != null) {
					header.putAll(headerMap.get(id));
				}
				if (respMap.get(id) != null) {
					header.putAll(respMap.get(id));
				}else {
					System.out.println("abc");
				}
//				for(String hkey: header.keySet()){
//					System.out.print(hkey+":"+header.get(hkey)+",");
//				}
				String entity = gsonObj.toJson(header);
				Request request = new Request("POST","/"+indexName+"/_doc/"+id);
				request.setJsonEntity(entity);
				if(header.get("status")==null) {
					System.out.println("what is wrong");
				}
				if(id.contains("rds-greenlight-prod")||
						id.contains("platformqa-prod")) {
					continue;
				}
				if(header.get("url")!=null && header.get("url").contains("/authserver/system/version")) {
					continue;
				}
				elasticClient.performRequest(request);
				System.out.println(":done");
			}
			elasticClient.close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
   
	private static String handleRespone(String id, BufferedReader reader) throws IOException {
		String line = reader.readLine();
//		if(id.contains("rds-authserver-prod-1205.sea2.rhapsody.com.webcache--sea2-lbprod.net.rhapsody.com.10885--06:22:08.645242")) {
//			System.out.println("what is wrong");
//		}
		boolean populate = false;
		Map<String,String> header = new HashMap<String,String>();
		while (line != null && !line.contains(" > ")) {
			if (line.contains("HTTP")&&respMap.get(id)==null) {
				Integer hS = Integer.parseInt(line.split("HTTP")[1].split("\\s+")[1]);
				header.put("status", hS.toString());
				populate = true;
			}
			line = reader.readLine();
		}
		if(populate) {
			respMap.put(id,header);	
		}
		return line;
	}
	private static Map<String,String> ids = new HashMap<String,String>();
	public static final String xRdsAuthentication = "X-RDS-Authentication";
	public static final String xRequestID = "x-request-id";
	public static final String trueClientIP = "true-client-ip";
	public static final String xClientIp = "x-client-id";
	public static final String userAgent = "user-agent";
	public static final String authorization = "authorization";
	public static final String xRdsDevKey = "X-RDS-DevKey";
	public static final String DATE = "Date:";
	
	private static String handleRequest(String id, BufferedReader reader) throws IOException, ParseException {
		String line = reader.readLine();
		Map<String,String> header = headerMap.get(id);
				new TreeMap<String,String>();
		if(header==null) {
			header = new TreeMap<String,String>();
		}
		
		while (line != null && !line.contains(" > ")) {
			
			if (line.contains(xRequestID)) {
				header.put(xRequestID.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
			}else if (line.contains(trueClientIP)||line.contains("True-Client-IP")) {
				header.put(trueClientIP.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
			}else if (line.contains(xClientIp)) {
				header.put(xClientIp.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
			}else if (line.contains(userAgent)||line.contains("User-Agent")) {
				header.put(userAgent.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
			}else if (line.contains(authorization)||line.contains("Authorization")) {
				header.put(authorization.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
			}else if (line.contains(xRdsDevKey)||line.contains("x-rds-devkey")) {
				header.put(xRdsDevKey.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
			}else if (line.contains(DATE)||line.contains("date:")) {
				String date =line.split(", ")[1];
				Date calendar =dateFormat.parse(date);
//				String[] dates = date.split("\\s+");
//				Calendar calendar = Calendar.getInstance();
//				calendar.set(Calendar.YEAR, value);
				header.put("date", isoDateFormat.format(calendar));
			}else if (line.contains("HTTP")) {
				if(line.contains("authserver")) {
					if(line.contains("GET")) {
						header.put("method", "GET");
						header.put("url", StringUtils.strip(line.split("GET")[1].split("\\s")[1]));
					}else if (line.contains("POST")){
						header.put("method", "POST");
						header.put("url", StringUtils.strip(line.split("POST")[1].split("\\s")[1]));
					}else if (line.contains("PUT")){
						header.put("method", "PUT");
						header.put("url", StringUtils.strip(line.split("PUT")[1].split("\\s")[1]));
					}
				}
			}else if (line.contains("X-Forwarded-For")) {
				header.put("x-forwarded-for", StringUtils.strip(line.split(": ")[1]));
			}
//			if (line.contains(xRdsAuthentication)) {
//				header.put(xRdsAuthentication, line.split(": ")[1]);
//			}else
			line = reader.readLine();
		}
		if(header.get(trueClientIP)==null) {
			header.put(trueClientIP,"notexists");
		}
		headerMap.put(id,header);
		return line;
	}
}
