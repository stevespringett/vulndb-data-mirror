/*
 * This file is part of vulndb-data-mirror.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.springett.vulndbdatamirror.client;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestInstance;
import us.springett.vulndbdatamirror.parser.VulnDbParser;
import us.springett.vulndbdatamirror.parser.model.Product;
import us.springett.vulndbdatamirror.parser.model.Results;
import us.springett.vulndbdatamirror.parser.model.Status;
import us.springett.vulndbdatamirror.parser.model.Vendor;
import us.springett.vulndbdatamirror.parser.model.Version;
import us.springett.vulndbdatamirror.parser.model.Vulnerability;

/**
 * OAuth2 access to the VulnDB API. For more information visit https://vulndb.flashpoint.io/ .
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class VulnDbApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDbApi.class);
    private static final String USER_AGENT = "VulnDB Data Mirror (https://github.com/stevespringett/vulndb-data-mirror)";
    private static final String STATUS_URL = "https://vulndb.flashpoint.io/api/v1/account_status";
    private static final String VENDORS_URL = "https://vulndb.flashpoint.io/api/v1/vendors/";
    private static final String PRODUCTS_URL = "https://vulndb.flashpoint.io/api/v1/products/";
    private static final String VERSIONS_URL = "https://vulndb.flashpoint.io/api/v1/versions/by_product_id?product_id=";
    private static final String VULNERABILITIES_URL = "https://vulndb.flashpoint.io/api/v1/vulnerabilities/"
            + "?nested=true&additional_info=true&show_cpe_full=true&show_cvss_v3=true&package_info=true&vtem=true";
    private static final String VULNERABILITIES_FIND_BY_CPE_URL = "https://vulndb.flashpoint.io/api/v1/vulnerabilities/find_by_cpe?&cpe=";
    //Returns vulnerabilities that were updated or created in the last specified number of hours.
    private static final String VULNERABILITIES_LAST_UPDATED = "https://vulndb.flashpoint.io/api/v1/vulnerabilities/find_by_time_full?hours_ago=";
    private static final String TOKEN_URL = "https://vulndb.flashpoint.io/oauth/token";

    private final String consumerKey;
    private final String consumerSecret;
    private String accessToken;

    public enum Type {
        VENDORS,
        PRODUCTS,
        VULNERABILITIES
    }

    public VulnDbApi(final String consumerKey, final String consumerSecret) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
    }

    public VulnDbApi(final String consumerKey, final String consumerSecret, final UnirestInstance ui) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
    }

    /**
     * Makes a request and returns {@link Status}.
     *
     * @return a Results object
     * @since 1.0.0
     */
    public Status getStatus() {
        final HttpResponse<JsonNode> response = makeRequest(STATUS_URL);
        if (response != null) {
            if (response.getStatus() == 200) {
                final VulnDbParser parser = new VulnDbParser();
                return parser.parseStatus(response.getBody());
            } else {
                logHttpResponseError(response);
            }
        }
        return new Status();
    }


    /**
     * Makes a request and returns {@link Vendor} Results.
     *
     * @param size the number of items to fetch
     * @param page the page number of the fetched items
     * @return a Results object
     * @since 1.0.0
     */
    public Results getVendors(final int size, final int page) {
        return getResults(VENDORS_URL, Vendor.class, size, page);
    }

    /**
     * Makes a request and returns {@link Product} Results.
     *
     * @param size the number of items to fetch
     * @param page the page number of the fetched items
     * @return a Results object
     * @since 1.0.0
     */
    public Results getProducts(final int size, final int page) {
        return getResults(PRODUCTS_URL, Product.class, size, page);
    }

    /**
     * Makes a request and returns {@link Version} Results.
     *
     * @param productId the VulnDB product_id to retrieve versions from
     * @param size      the number of items to fetch
     * @param page      the page number of the fetched items
     * @return a Results object
     * @since 1.0.0
     */
    public Results getVersions(final int productId, final int size, final int page) {
        return getResults(VERSIONS_URL + productId, Version.class, size, page);
    }

    /**
     * Makes a request and returns {@link Vulnerability} Results.
     *
     * @param size the number of items to fetch
     * @param page the page number of the fetched items
     * @return a Results object
     * @since 1.0.0
     */
    public Results getVulnerabilities(final int size, final int page) {
        return getResults(VULNERABILITIES_URL, Vulnerability.class, size, page);
    }

    /**
     * Makes a request and returns {@link Vulnerability} Results for the specified CPE.
     *
     * @param cpe the CPE to query on
     * @param size the number of items to fetch
     * @param page the page number of the fetched items
     * @return a Results object
     * @since 1.0.0
     */
    public Results getVulnerabilitiesByCpe(final String cpe, final int size, final int page) {
        String encodedCpe = cpe;
        try {
            encodedCpe = URLEncoder.encode(cpe, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            LOGGER.error("An error occurred while URL encoding a CPE", e);
        }
        return getResults(VULNERABILITIES_FIND_BY_CPE_URL + encodedCpe, Vulnerability.class, size, page);
    }

    /**
     * Makes a request and returns Last Updated {@link Vulnerability} Results.
     * Includes the following options preset for ease of use and performance improvements:
     * nested=true, additional_info=true, show_cpe_full=true, full_reference_url=true, show_cvss_v3=true, package_info=true, and library_info=true
     * @param size the number of items to fetch
     * @param page the page number of the fetched items
     * @param hours_ago The number of hours far back you want to check for updated vulnerabilities
     * @return a Results object
     * @since 1.0.0
     */
    public Results getUpdatedVulnerabilities(final int size, final int page, final int hours_ago) {
        return getResults(VULNERABILITIES_LAST_UPDATED + hours_ago, Vulnerability.class, size, page);
    }

    /**
     * Makes a request and returns the results
     *
     * @param url   the URL being requested
     * @param clazz the model vulndb model class to parse
     * @param size  the number of items to fetch
     * @param page  the page number of the fetched items
     * @return a parsed Results object
     * @since 1.0.0
     */
    private Results getResults(final String url, final Class clazz, final int size, final int page) {
        final String modifiedUrl = (url.contains("?")) ? url + "&" : url + "?";
        final HttpResponse<JsonNode> response = makeRequest(modifiedUrl + "size=" + size + "&page=" + page);
        if (response != null) {
            if (response.getStatus() == 200) {
                final VulnDbParser parser = new VulnDbParser();
                final Results results = parser.parse(response.getBody(), clazz);
                return results;
            } else {
                final Results results = new Results();
                results.setErrorCondition("An unexpected response was returned from VulnDB. Request unsuccessful: " + response.getStatus() + " - " + response.getStatusText() + " - " + response.getBody());
                logHttpResponseError(response);
                return results;
            }
        }
        final Results results = new Results();
        results.setErrorCondition("No response was returned from VulnDB. No further information is available.");
        return results;
    }

    // /**
    //  * Makes a request to the specified URL using OAuth 2.0 Bearer Token
    //  *
    //  * @param url the URL being requested
    //  * @return an HttpResponse
    //  * @since 1.0.0
    //  */
    private HttpResponse<JsonNode> makeRequest(final String url) {
        try {
            if (accessToken == null || accessToken.isEmpty()) {
                // Set request body parameters
                String grantType = "client_credentials";
                String clientId = this.consumerKey;
                String clientSecret = this.consumerSecret;

                // Get access token
                HttpResponse<JsonNode> accessTokenResponse =
                    Unirest.post(TOKEN_URL)
                        .field("grant_type", grantType)
                        .field("client_id", clientId)
                        .field("client_secret", clientSecret)
                        .asJson();

                 if (accessTokenResponse.isSuccess()) {
                    // Extract access token from response
                    accessToken = accessTokenResponse.getBody().getObject().getString("access_token");
                    System.out.println("New Token: "+accessToken);
                 } else {
                     LOGGER.error("Access token request failed with status: " + accessTokenResponse.getStatus());
                     return null;
                 }
            }

            // Make API call using stored access token
            HttpResponse<JsonNode> apiCallResponse =
                Unirest.get(url)
                    .header("Authorization", "Bearer " + accessToken)
                    .header("X-User-Agent", USER_AGENT)  // Add User Agent VulnDB Data Mirror
                    .asJson();

             if (apiCallResponse.isSuccess()) {
                 return apiCallResponse;
             } else {
                 LOGGER.error("API call failed with status: " + apiCallResponse.getStatus());
             }
        } catch (Exception e) {
             LOGGER.error("An error occurred making request: " + url, e);
        }

        return null;
    }

    /**
     * Logs errors from an HttpResponse.
     *
     * @param response the response from the server
     * @since 1.0.0
     */
    private void logHttpResponseError(final HttpResponse<JsonNode> response) {
        LOGGER.error("Response was not successful: " + response.getStatus() + " - " + response.getStatusText() + " - " + response.getBody());
        System.err.println("\n" + response.getStatus() + " - " + response.getStatusText() + " - " + response.getBody());
    }
}
