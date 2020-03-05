package tcpdump;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.elasticsearch.client.RestClientBuilder.HttpClientConfigCallback;

import com.google.gson.Gson;

public class Indexer {
	private static Map<String, Map<String, String>> headerMap = new ConcurrentHashMap<String, Map<String, String>>();
	private static Map<String, Map<String, String>> respMap = new ConcurrentHashMap<String, Map<String, String>>();
	static DateFormat dateFormat = new SimpleDateFormat("dd MMM yyy HH:mm:ss.SSS z", Locale.US);
	static DateFormat isoDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
	static ArrayBlockingQueue<String> workingQueue = new ArrayBlockingQueue<String>(512);
	static Ip2Loc ip2loc = new Ip2Loc();
	static Decoder decoder = Base64.getDecoder();

	private static Map<String, String> ids = new HashMap<String, String>();
	public static final String xRdsAuthentication = "x-rds-authentication";
	public static final String xRequestID = "x-request-id";
	public static final String trueClientIP = "true-client-ip";
	public static final String xClientIp = "x-client-id";
	public static final String userAgent = "user-agent";
	public static final String authorization = "authorization";
	public static final String xRdsDevKey = "X-RDS-DevKey";
	public static final String DATE = "Date:";
	 

	public static void main(String[] args) {
		StopWatch watch = new StopWatch();
		watch.start();
		String filename = args[0];
		String indexName = args[1];
		String serverName = args[2];
		int thread = 4;
		if (args.length > 3) {
			thread = Integer.valueOf(args[3]);
		}
		boolean markC = true;
		if (args.length > 4) {
			markC = Boolean.valueOf(args[4]);
		}
		
		BufferedReader reader;
		Map<String, String> requestMap = new TreeMap<String, String>();
		Map<String, String> responseMap = new HashMap<String, String>();
		RestClient client = buildClient(serverName);
		try {
			Set<ESIndexer> threads = new HashSet<ESIndexer>();
			for (int i = 0; i < thread; i++) {
				ESIndexer worker = new ESIndexer(serverName, indexName, "worker-" + i, markC, client);
				worker.setDaemon(true);
				worker.start();
				threads.add(worker);
			}
			if ("console".equals(filename)) {
				reader = new BufferedReader(new InputStreamReader(System.in));
			} else {
				reader = new BufferedReader(new FileReader(filename));
			}
			String line = reader.readLine();
			int i = 0;
			while (line != null) {
				if (line.contains(" > ")) {
					i++;
					String[] fields = line.split("\\s+");
					if (fields[4] != null && fields[4].charAt(fields[4].length() - 1) == ':') {
						fields[4] = fields[4].substring(0, fields[4].length() - 1);
					}

					String id;
					if (fields[4].contains("rds-authserver-prod")) {
						id = fields[4] + "--" + fields[2];
						String time = fields[0];
						ids.put(id, time);
						id = id + "--" + time;
						requestMap.put(id, line);
						line = handleRequest(line, id, reader);
						continue;
					} else if (fields[2].contains("rds-authserver-prod")) {
						id = fields[2] + "--" + fields[4];
						if (ids.get(id) == null) {
							System.out.println("abc");
						}
						id = id + "--" + ids.get(id);
						responseMap.put(id, line);
						line = handleRespone(line, id, reader);
						continue;
					}
				}
				line = reader.readLine();
			}
			reader.close();
			System.out.println(".");
			
			try {
				if (workingQueue.size()>0) Thread.sleep(10);
			} catch (InterruptedException e1) {
			}
			//Should be done now
			for(ESIndexer t : threads) {
				t.stop=true;
			}
			
			watch.stop();
			System.out.println("took:" + watch.toString());
			System.exit(0);

		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static final class ESIndexer extends Thread {
		Gson gsonObj = new Gson();
		String indexName;
		String serverName;
		boolean stop = false;
		RestClient elasticClient;
		int total = 0;
		boolean mark = true;
		String workerName;
		private static final Pattern guidSplitter =
				  Pattern.compile("([A-F0-9]{32})");
		
		ESIndexer(String serverName, String indexName, String workerName, boolean mark, RestClient client) {
			this.serverName = serverName;
			this.indexName = indexName;
			this.workerName = workerName;
			this.mark = mark;
			this.elasticClient = client;
		}

		@Override
		public void run() {
			Map<String, String> header = new TreeMap<String, String>();
			String entity = "";
			String id;
			while (!stop) {
				try {
					id = workingQueue.poll(10, TimeUnit.SECONDS);
					if (id != null) {
						try {
							header = new TreeMap<String, String>();

							if (headerMap.get(id) != null) {
								header.putAll(headerMap.get(id));
							} else {
								continue;
							}
							total++;
							if (respMap.get(id) != null) {
								header.putAll(respMap.get(id));
							} else {
								System.out.println("No Response");
							}

							if (header.get("status") == null) {
								System.out.println("what is wrong");
							}
							if (id.contains("rds-greenlight-prod") || id.contains("platformqa-prod")) {
								System.out.println(":skip test");
								continue;
							}
							if (header.get("url") != null && header.get("url").contains("/authserver/system/version")) {
								System.out.println(":skip version");
								continue;
							}else {
								String[] urls =  header.get("url").split("\\?");
								if(urls.length>1) {
									urls[1] = URLDecoder.decode(urls[1],StandardCharsets.UTF_8.name());
									header.put("url", urls[0]+"?"+urls[1]);
									header.put("urlpath", urls[0]);
									header.put("urlquery", urls[1]);
									String nameQuery ="";
									try {
										if(urls[1].contains("&")) {
											header.put("urlquery", urls[1].split("&")[0].split("=")[1]);
										}else {
											header.put("urlquery", urls[1].split("=")[1]);
										}
									} catch (Exception e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}
								}else {
									Matcher m = guidSplitter.matcher(urls[0]);
									if (m.find()) {
										String  guid = m.group(1);
										header.put("urlpath", urls[0].replace(guid, "{guid}"));
										header.put("urlquery", guid);
									} else {
										header.put("urlpath", urls[0]);
									}
								}
							}
							if (mark || (header.get("status") != null
									&& (header.get("status").equals("200") || header.get("status").equals("201")))) {
								header.put("x-rds-authentication", "***");
							}
							entity = gsonObj.toJson(header);
							Request request = new Request("POST", "/" + indexName + "/_doc/" + id);
							request.setJsonEntity(entity);

							Response response = elasticClient.performRequest(request);
							int statusCode = response.getStatusLine().getStatusCode();
							if (200 != statusCode) {
								// Try again
								elasticClient.performRequest(request);
							}

							System.out.println(id + ":done :" + workerName + " " + +total);
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} finally {
							headerMap.remove(id);
							respMap.remove(id);
						}
					} else {
						continue;
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			return;
		}
	}

	private static String handleRequest(String reqLine, String id, BufferedReader reader)
			throws IOException, ParseException {
		String time = reqLine.split("\\s")[0];
		String line = reader.readLine();
		Map<String, String> header = headerMap.get(id);
		new TreeMap<String, String>();
		if (header == null) {
			header = new TreeMap<String, String>();
		}

		while (line != null && !line.contains(" > ")) {

			try {
				if (line.contains(xRequestID)) {
					header.put(xRequestID.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
				} else if (line.contains(trueClientIP) || line.contains("True-Client-IP")) {
					header.put(trueClientIP.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
				} else if (line.contains(xClientIp)) {
					header.put(xClientIp.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
				} else if (line.contains(userAgent) || line.contains("User-Agent")) {
					header.put(userAgent.toLowerCase(), StringUtils.strip(line.split(": ")[1]).split("\\s")[0]);
				} else if (line.contains(authorization) || line.contains("Authorization")) {
					String base64Auth = StringUtils.strip(line.split("Basic ")[1]);
					try {
						base64Auth = new String(decoder.decode(base64Auth));
					} catch (Exception e) {
					}
					header.put(authorization.toLowerCase(), base64Auth);
				} else if (line.contains(xRdsDevKey) || line.contains("x-rds-devkey")) {
					header.put(xRdsDevKey.toLowerCase(), StringUtils.strip(line.split(": ")[1]));
				} else if (line.contains(DATE) || line.contains("date:")) {
					try {
						String date = line.split(", ")[1];
						date = date.substring(0, 12) + time.substring(0, 12) + " GMT";
						;
						Date calendar = dateFormat.parse(date);
						header.put("date", isoDateFormat.format(calendar));
					} catch (ParseException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} else if (line.contains("HTTP")) {
					if (line.contains("authserver")) {
						if (line.contains("GET")) {
							header.put("method", "GET");
							header.put("url", StringUtils.strip(line.split("GET")[1].split("\\s")[1]));
						} else if (line.contains("POST")) {
							header.put("method", "POST");
							header.put("url", StringUtils.strip(line.split("POST")[1].split("\\s")[1]));
						} else if (line.contains("PUT")) {
							header.put("method", "PUT");
							header.put("url", StringUtils.strip(line.split("PUT")[1].split("\\s")[1]));
						}
					}
				} else if (line.contains("X-Forwarded-For")) {
					header.put("x-forwarded-for", StringUtils.strip(line.split(": ")[1]));
				} else if (line.contains(xRdsAuthentication) || line.contains("X-RDS-Authentication")) {
					try {
						String token = StringUtils.strip(line.substring(xRdsAuthentication.length() + 1));
						if (token.length() > 20) {
							token = "token";
						}
						header.put(xRdsAuthentication, token);
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			line = reader.readLine();
		}

		String country = ip2loc.getCountryFromIP(header.get(trueClientIP));
		header.put("country", country);

		headerMap.put(id, header);
		return line;
	}

	private static String handleRespone(String respLine, String id, BufferedReader reader) throws IOException {
		String time = respLine.split("\\s")[0];
		String line = reader.readLine();
		boolean populate = false;

		Map<String, String> header = respMap.get(id);
		Map<String, String> reqHeader = headerMap.get(id);
		if (reqHeader == null) {
			while (line != null && !line.contains(" > ")) {
				line = reader.readLine();
			}
			return line;
		}
		if (header == null) {
			header = new HashMap<String, String>();
		} else {
			while (line != null && !line.contains(" > ")) {
				line = reader.readLine();
			}
			return line;
		}
		while (line != null && !line.contains(" > ")) {
			try {
				if (line.contains("HTTP") && header.get("status") == null) {
					Integer hS;
					try {
						hS = Integer.parseInt(line.split("HTTP")[1].split("\\s+")[1]);
						header.put("status", hS.toString());
						populate = true;
					} catch (NumberFormatException e) {
						System.out.println(line);
					}

				} else if (line.contains(DATE) || line.contains("date:")) {
					try {
						String date = line.split(", ")[1];
						date = date.substring(0, 12) + time.substring(0, 12) + " GMT";
						Date calendar = dateFormat.parse(date);
						header.put("f_date", isoDateFormat.format(calendar));
					} catch (ParseException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			line = reader.readLine();
		}
		if (reqHeader.get("date") == null) {
			reqHeader.put("date", header.get("f_date"));
		}

		if (populate) {
			try {
				if (header.get("f_date") != null) {
					Date start = isoDateFormat.parse(reqHeader.get("date"));
					Date end = isoDateFormat.parse(header.get("f_date"));
					header.put("took", String.valueOf(end.getTime() - start.getTime()));
				}
			} catch (ParseException e) {
				System.out.print("");
			}
			respMap.put(id, header);

		}

		boolean inserted = (workingQueue.offer(id));
		while (!inserted) {
			inserted = (workingQueue.offer(id));
		}
		return line;
	}

	public static RestClient buildClient(String serverName) {
		final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials("elastic", "changeme"));

		// Header[] defaultHeaders = new Header[]{new BasicHeader("authorization",
		// "Basic ZWxhc3RpYzpjaGFuZ2VtZQ==")};
		RestClient elasticClient = RestClient.builder(new HttpHost(serverName, 9200, "http"))
				.setHttpClientConfigCallback(new HttpClientConfigCallback() {
					@Override
					public org.apache.http.impl.nio.client.HttpAsyncClientBuilder customizeHttpClient(
							HttpAsyncClientBuilder httpClientBuilder) {
						return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
					}
				}).setRequestConfigCallback(new RestClientBuilder.RequestConfigCallback() {
					@Override
					public RequestConfig.Builder customizeRequestConfig(RequestConfig.Builder requestConfigBuilder) {
						return requestConfigBuilder.setSocketTimeout(10000).setConnectTimeout(1000);
					}
				})
//				.setDefaultHeaders(defaultHeaders)
				.build();
		return elasticClient;
	}
}