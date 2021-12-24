package client.app.httpInterface;

import org.json.JSONObject;

public class HttpOM2M {
	
	
	public static String retrieveLatestResource(String uri, String acp) {
		HttpResponse httpResponse = RestHttpClient.get(acp, uri);
		JSONObject result = new JSONObject(httpResponse.getBody());
		String val = result.getJSONObject("m2m:cin").getString("con");
		return val;
	}
}
