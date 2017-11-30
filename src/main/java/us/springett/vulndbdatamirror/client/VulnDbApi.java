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

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.exception.OAuthException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.vulndbdatamirror.parser.VulnDbParser;
import us.springett.vulndbdatamirror.parser.model.Product;
import us.springett.vulndbdatamirror.parser.model.Results;
import us.springett.vulndbdatamirror.parser.model.Status;
import us.springett.vulndbdatamirror.parser.model.Vendor;
import us.springett.vulndbdatamirror.parser.model.Version;
import us.springett.vulndbdatamirror.parser.model.Vulnerability;

/**
 * OAuth access to the VulnDB API. For more information visit https://vulndb.cyberriskanalytics.com/ .
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class VulnDbApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDbApi.class);
    private static final String USER_AGENT = "VulnDB Data Mirror (https://github.com/stevespringett/vulndb-data-mirror)";
    private static final String STATUS_URL = "https://vulndb.cyberriskanalytics.com/api/v1/account_status";
    private static final String VENDORS_URL = "https://vulndb.cyberriskanalytics.com/api/v1/vendors/";
    private static final String PRODUCTS_URL = "https://vulndb.cyberriskanalytics.com/api/v1/products/";
    private static final String VERSIONS_URL = "https://vulndb.cyberriskanalytics.com/api/v1/versions/by_product_id?product_id=";
    private static final String VULNERABILITIES_URL = "https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/"
            + "?nested=true&additional_info=true&show_cpe=true&show_cvss_v3=true&package_info=true&vtem=true";

    private String consumerKey;
    private String consumerSecret;

    public enum Type {
        VENDORS,
        PRODUCTS,
        VULNERABILITIES
    }

    public VulnDbApi(String consumerKey, String consumerSecret) {
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
    public Results getVendors(int size, int page) {
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
    public Results getProducts(int size, int page) {
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
    public Results getVersions(int productId, int size, int page) {
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
    public Results getVulnerabilities(int size, int page) {
        return getResults(VULNERABILITIES_URL, Vulnerability.class, size, page);
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
    private Results getResults(String url, Class clazz, int size, int page) {
        url = (url.contains("?")) ? url + "&" : url + "?";
        final HttpResponse<JsonNode> response = makeRequest(url + "size=" + size + "&page=" + page);
        if (response != null) {
            if (response.getStatus() == 200) {
                final VulnDbParser parser = new VulnDbParser();
                return parser.parse(response.getBody(), clazz);
            } else {
                logHttpResponseError(response);
            }
        }
        return new Results();
    }

    /**
     * Makes a one-legged OAuth 1.0a request for the specified URL.
     *
     * @param url the URL being requested
     * @return an HttpResponse
     * @since 1.0.0
     */
    private HttpResponse<JsonNode> makeRequest(String url) {
        try {
            final OAuthConsumer consumer = new DefaultOAuthConsumer(this.consumerKey, this.consumerSecret);
            final String signed = consumer.sign(url);
            return Unirest.get(signed).header("X-User-Agent", USER_AGENT).asJson();
        } catch (OAuthException | UnirestException e) {
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
    private void logHttpResponseError(HttpResponse<JsonNode> response) {
        LOGGER.error("Response was not successful: " + response.getStatus() + " - " + response.getStatusText() + " - " + response.getBody());
        System.err.println("\n" + response.getStatus() + " - " + response.getStatusText() + " - " + response.getBody());
    }
}
