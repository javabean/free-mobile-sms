package fr.cedrik.freemobile.sms;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class FreeMobileSMSServlet
 *
 * @author C&eacute;drik LIME
 */
public class FreeMobileSMSServlet extends HttpServlet {

	private static final boolean DEBUG = false;

	protected static final String HEADER_IFMODSINCE   = "If-Modified-Since";//$NON-NLS-1$
	protected static final String HEADER_LASTMOD      = "Last-Modified";//$NON-NLS-1$
	protected static final String HEADER_CACHECONTROL = "Cache-Control";//$NON-NLS-1$
	protected static final String HEADER_EXPIRES      = "Expires";//$NON-NLS-1$

	private static final long serialVersionUID = 1931932431169535254L;

	private static final SSLSocketFactory trustingSSLSocketFactory;
	static {
		try {
			// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
				@Override
				public void checkClientTrusted(X509Certificate[] certs, String authType) {
				}
				@Override
				public void checkServerTrusted(X509Certificate[] certs,String authType) {
				}
			} };
			// Install the all-trusting trust manager
			SSLContext sc = SSLContext.getInstance("TLS");//$NON-NLS-1$
			sc.init(null, trustAllCerts, new SecureRandom());
			trustingSSLSocketFactory = sc.getSocketFactory();
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	// Create all-trusting host name verifier
	private static final HostnameVerifier allHostsValid = new HostnameVerifier() {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	};


	private String gatewayUrl;


    /**
     * @see HttpServlet#HttpServlet()
     */
    public FreeMobileSMSServlet() {
        super();
    }

    @Override
    public void log(String msg) {
    	if (DEBUG) {
    		super.log(msg);
    	}
    }

    /**
	 * @see HttpServlet#init()
	 */
	@SuppressWarnings("unused")
	@Override
	public void init() throws ServletException {
		super.init();
		gatewayUrl = getInitParameter("gateway.url");//$NON-NLS-1$
		if (gatewayUrl == null || "".equals(gatewayUrl.trim())) {
			throw new UnavailableException("Missing 'gateway.url' parameter");
		}
		try {
			new URL(gatewayUrl);
		} catch (MalformedURLException e) {
			throw new UnavailableException("Bad 'gatewayUrl' parameter value: " + e.getMessage());
		}
		if (! gatewayUrl.endsWith("&msg=")) {
			if ( ! gatewayUrl.endsWith("&")) {
				gatewayUrl += '&';
			}
			gatewayUrl += "msg=";
		}
		log("SMS gateway URL: " + gatewayUrl);
	}

	/**
	 * @see Servlet#destroy()
	 */
	@Override
	public void destroy() {
		gatewayUrl = null;
	}

	/**
	 * @see Servlet#getServletInfo()
	 */
	@Override
	public String getServletInfo() {
		return "FreeMobileSMSServlet Copyright Cédrik LIME";
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String root = request.getContextPath();
		if (root == null || root.isEmpty()) {
			root = "/";
		}
		response.sendRedirect(root);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		setNoCache(response);
		response.setContentType("text/html; charset=" + StandardCharsets.UTF_8.name());

		String msg = request.getParameter("msg");//$NON-NLS-1$
		if (msg == null || "".equals(msg.trim())) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "empty SMS");
			return;
		}

		String fullURLStr = gatewayUrl + URLEncoder.encode(msg, StandardCharsets.ISO_8859_1.name());//FIXME should RFC5997-encode?  http://tools.ietf.org/html/rfc5987
		URL fullURL = new URL(fullURLStr);

		Proxy proxy = Proxy.NO_PROXY;
		if (DEBUG) {
			proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(3128));
		}
		HttpsURLConnection connection = (HttpsURLConnection) fullURL.openConnection(proxy);
		{
			connection.setAllowUserInteraction(false);
			connection.setUseCaches(false);
			connection.setConnectTimeout((int) SECONDS.toMillis(5));
			connection.setReadTimeout((int) SECONDS.toMillis(15));
			connection.setInstanceFollowRedirects(false);
			//connection.setRequestMethod("POST"); // POST does not work...
			connection.setRequestMethod("GET");
			connection.setDoInput(true);
			connection.setDoOutput(false);
			//connection.addRequestProperty("Authorization", BASIC_AUTH + Base64.encode("user name" + ':' + "pass phrase"));
			//connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=" + StandardCharsets.UTF_8.name());
			connection.setRequestProperty("Content-Type", "text/plain; charset=" + StandardCharsets.ISO_8859_1.name());

			if (DEBUG) {
				// Install the all-trusting host verifier
				connection.setHostnameVerifier(allHostsValid);
			}
			// Certificate is not recognised by the default JVM store...
			// Install the all-trusting trust manager
			connection.setSSLSocketFactory(trustingSSLSocketFactory);
		}
		connection.connect();
//		OutputStream bodyOS = connection.getOutputStream();
//		String postParameters = "msg=" + URLEncoder.encode(msg, StandardCharsets.UTF_8.name());
//		PrintStream body = new PrintStream(bodyOS, true, StandardCharsets.UTF_8.name());
//		body.append(postParameters);
//		body.flush();
//		body.close();

		int responseCode = connection.getResponseCode();
		String responseMessage = connection.getResponseMessage();
		connection.disconnect();

		if (DEBUG) {
			log("" + responseCode + ' ' + responseMessage);
		}

		response.setStatus(responseCode);
		request.setAttribute("responseCode", responseCode);
		request.setAttribute("responseMessage", responseMessage);
		switch (responseCode) {
		case 200: // Le SMS a été envoyé sur votre mobile.
			request.setAttribute("resultMessage", "Le SMS a été envoyé sur votre mobile");
			break;
		case 400: // Un des paramètres obligatoires est manquant.
			request.setAttribute("resultMessage", "Un des paramètres obligatoires est manquant");
			break;
		case 402: // Trop de SMS ont été envoyés en trop peu de temps.
			request.setAttribute("resultMessage", "Trop de SMS ont été envoyés en trop peu de temps");
			break;
		case 403: // Le service n'est pas activé sur l'espace abonné, ou login / clé incorrect.
			request.setAttribute("resultMessage", "Le service n'est pas activé sur l'espace abonné, ou login / clé incorrect");
			break;
		case 500: // Erreur côté serveur. Veuillez réessayer ultérieurement.
			request.setAttribute("resultMessage", "Erreur côté serveur. Veuillez réessayer ultérieurement");
			break;
		default:
			request.setAttribute("resultMessage", "Code retour passerelle SMS inconnu");
		}
		request.getRequestDispatcher("/result.jsp").forward(request, response);//$NON-NLS-1$
	}

	public void setNoCache(HttpServletResponse response) {
		// <strong>NOTE</strong> - This header will be overridden
		// automatically if a <code>RequestDispatcher.forward()</code> call is
		// ultimately invoked.
		//resp.setHeader("Pragma", "No-cache"); // HTTP 1.0 //$NON-NLS-1$ //$NON-NLS-2$
		response.setHeader(HEADER_CACHECONTROL, "no-cache,no-store,max-age=0"); // HTTP 1.1 //$NON-NLS-1$
		response.setDateHeader(HEADER_EXPIRES, 0); // 0 means now
		// should we decide to enable caching, here are the current vary:
		response.addHeader("Vary", "Accept-Language,Accept-Encoding,Accept-Charset");//$NON-NLS-1$//$NON-NLS-2$
	}
}
