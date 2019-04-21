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
package us.springett.vulndbdatamirror.parser;

import kong.unirest.JsonNode;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.vulndbdatamirror.parser.model.ApiObject;
import us.springett.vulndbdatamirror.parser.model.Author;
import us.springett.vulndbdatamirror.parser.model.CPE;
import us.springett.vulndbdatamirror.parser.model.Classification;
import us.springett.vulndbdatamirror.parser.model.CvssV2Metric;
import us.springett.vulndbdatamirror.parser.model.CvssV3Metric;
import us.springett.vulndbdatamirror.parser.model.ExternalReference;
import us.springett.vulndbdatamirror.parser.model.ExternalText;
import us.springett.vulndbdatamirror.parser.model.NvdAdditionalInfo;
import us.springett.vulndbdatamirror.parser.model.Product;
import us.springett.vulndbdatamirror.parser.model.Results;
import us.springett.vulndbdatamirror.parser.model.Status;
import us.springett.vulndbdatamirror.parser.model.Vendor;
import us.springett.vulndbdatamirror.parser.model.Version;
import us.springett.vulndbdatamirror.parser.model.Vulnerability;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for VulnDB API response.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class VulnDbParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDbParser.class);

    public Status parseStatus(JsonNode jsonNode) {
        LOGGER.debug("Parsing JSON node");

        final Status status = new Status();
        final JSONObject root = jsonNode.getObject();
        status.setOrganizationName(root.optString("organization_name"));
        status.setUserNameRequesting(root.optString("user_name_requesting"));
        status.setUserEmailRequesting(root.optString("user_email_address_requesting"));
        status.setSubscriptionEndDate(root.optString("subscription_end_date"));
        status.setApiCallsAllowedPerMonth(root.optString("number_of_api_calls_allowed_per_month"));
        status.setApiCallsMadeThisMonth(root.optString("number_of_api_calls_made_this_month"));
        status.setVulnDbStatistics(root.optString("vulndb_statistics"));
        status.setRawStatus(jsonNode.toString());
        return status;
    }

    public <T> Results<T> parse(JsonNode jsonNode, Class<? extends ApiObject> apiObject) {
        LOGGER.debug("Parsing JSON node");

        final Results<T> results = new Results<>();
        final JSONObject root = jsonNode.getObject();
        results.setPage(root.getInt("current_page"));
        results.setTotal(root.getInt("total_entries"));
        results.setRawResults(jsonNode.toString());
        final JSONArray rso = root.getJSONArray("results");

        if (Product.class == apiObject) {
            results.setResults(parseProducts(rso));
        } else if (Vendor.class == apiObject) {
            results.setResults(parseVendors(rso));
        } else if (Version.class == apiObject) {
            results.setResults(parseVersions(rso));
        } else if (Vulnerability.class == apiObject) {
            results.setResults(parseVulnerabilities(rso));
        }
        return results;
    }

    public <T> Results<T> parse(String jsonData, Class<? extends ApiObject> apiObject) {
        return parse(new JsonNode(jsonData), apiObject);
    }

    public <T> Results<T> parse(File file, Class<? extends ApiObject> apiObject) throws IOException {
        String jsonData = new String(Files.readAllBytes(Paths.get(file.toURI())));
        return parse(new JsonNode(jsonData), apiObject);
    }

    private List<CPE> parseCpes(JSONArray rso) {
        List<CPE> cpes = null;
        if (rso != null) {
            cpes = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final CPE cpe = new CPE();
                cpe.setCpe(StringUtils.trimToNull(object.optString("cpe", null)));
                cpe.setType(StringUtils.trimToNull(object.optString("type", null)));
                cpes.add(cpe);
            }
        }
        return cpes;
    }

    private List<Product> parseProducts(JSONArray rso) {
        List<Product> products = null;
        if (rso != null) {
            products = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final Product product = new Product();
                product.setId(object.getInt("id"));
                product.setName(StringUtils.trimToNull(object.optString("name", null)));
                product.setVersions(parseVersions(object.optJSONArray("versions")));
                products.add(product);
            }
        }
        return products;
    }

    private List<Vendor> parseVendors(JSONArray rso) {
        List<Vendor> vendors = null;
        if (rso != null) {
            vendors = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final Vendor vendor = new Vendor();
                vendor.setId(object.getInt("id"));
                vendor.setName(StringUtils.trimToNull(object.optString("name", null)));
                vendor.setShortName(StringUtils.trimToNull(object.optString("short_name", null)));
                vendor.setVendorUrl(StringUtils.trimToNull(object.optString("vendor_url", null)));
                vendor.setProducts(parseProducts(object.optJSONArray("products")));
                vendors.add(vendor);
            }
        }
        return vendors;
    }

    private List<Version> parseVersions(JSONArray rso) {
        List<Version> versions = null;
        if (rso != null) {
            versions = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final Version version = new Version();
                version.setId(object.getInt("id"));
                version.setName(StringUtils.trimToNull(object.optString("name", null)));
                version.setAffected(object.optBoolean("affected", false));
                version.setCpes(parseCpes(object.optJSONArray("cpe")));
                versions.add(version);
            }
        }
        return versions;
    }

    private List<Vulnerability> parseVulnerabilities(JSONArray rso) {
        List<Vulnerability> vulnerabilities = null;
        if (rso != null) {
            vulnerabilities = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final Vulnerability vulnerability = new Vulnerability();
                vulnerability.setId(object.getInt("vulndb_id"));
                vulnerability.setTitle(StringUtils.trimToNull(object.optString("title", null)));
                vulnerability.setDisclosureDate(StringUtils.trimToNull(object.optString("disclosure_date", null)));
                vulnerability.setDiscoveryDate(StringUtils.trimToNull(object.optString("discovery_date", null)));
                vulnerability.setExploitPublishDate(StringUtils.trimToNull(object.optString("exploit_publish_date", null)));
                vulnerability.setKeywords(StringUtils.trimToNull(object.optString("keywords", null)));
                vulnerability.setShortDescription(StringUtils.trimToNull(object.optString("short_description", null)));
                vulnerability.setDescription(StringUtils.trimToNull(object.optString("description", null)));
                vulnerability.setSolution(StringUtils.trimToNull(object.optString("solution", null)));
                vulnerability.setManualNotes(StringUtils.trimToNull(object.optString("manual_notes", null)));
                vulnerability.setTechnicalDescription(StringUtils.trimToNull(object.optString("t_description", null)));
                vulnerability.setSolutionDate(StringUtils.trimToNull(object.optString("solution_date", null)));
                vulnerability.setVendorInformedDate(StringUtils.trimToNull(object.optString("vendor_informed_date", null)));
                vulnerability.setVendorAckDate(StringUtils.trimToNull(object.optString("vendor_ack_date", null)));
                vulnerability.setThirdPartySolutionDate(StringUtils.trimToNull(object.optString("third_party_solution_date", null)));

                final JSONArray classifications = object.optJSONArray("classifications");
                if (classifications != null) {
                    for (int j = 0; j < classifications.length(); j++) {
                        final JSONObject jso = classifications.getJSONObject(j);
                        final Classification classification = new Classification();
                        classification.setId(jso.getInt("id"));
                        classification.setName(StringUtils.trimToNull(jso.optString("name", null)));
                        classification.setLongname(StringUtils.trimToNull(jso.optString("longname", null)));
                        classification.setDescription(StringUtils.trimToNull(jso.optString("description", null)));
                        classification.setMediumtext(StringUtils.trimToNull(jso.optString("mediumtext", null)));
                        vulnerability.addClassifications(classification);
                    }
                }

                final JSONArray authors = object.optJSONArray("authors");
                if (authors != null) {
                    for (int j = 0; j < authors.length(); j++) {
                        final JSONObject jso = authors.getJSONObject(j);
                        final Author author = new Author();
                        author.setId(jso.getInt("id"));
                        author.setName(StringUtils.trimToNull(jso.optString("name", null)));
                        author.setCompany(StringUtils.trimToNull(jso.optString("company", null)));
                        author.setEmail(StringUtils.trimToNull(jso.optString("email", null)));
                        author.setCompanyUrl(StringUtils.trimToNull(jso.optString("company_url", null)));
                        author.setCountry(StringUtils.trimToNull(jso.optString("country", null)));
                        vulnerability.addAuthor(author);
                    }
                }

                final JSONArray extRefs = object.optJSONArray("ext_references");
                if (extRefs != null) {
                    for (int j = 0; j < extRefs.length(); j++) {
                        final JSONObject jso = extRefs.getJSONObject(j);
                        final ExternalReference externalReference = new ExternalReference();
                        externalReference.setType(StringUtils.trimToNull(jso.optString("type", null)));
                        externalReference.setValue(StringUtils.trimToNull(jso.optString("value", null)));
                        vulnerability.addExtReference(externalReference);
                    }
                }

                final JSONArray extTexts = object.optJSONArray("ext_texts");
                if (extTexts != null) {
                    for (int j = 0; j < extTexts.length(); j++) {
                        final JSONObject jso = extTexts.getJSONObject(j);
                        final ExternalText externalText = new ExternalText();
                        externalText.setType(StringUtils.trimToNull(jso.optString("type", null)));
                        externalText.setValue(StringUtils.trimToNull(jso.optString("value", null)));
                        vulnerability.addExtText(externalText);
                    }
                }

                final JSONArray cvssv2Metrics = object.optJSONArray("cvss_metrics");
                if (cvssv2Metrics != null) {
                    for (int j = 0; j < cvssv2Metrics.length(); j++) {
                        final JSONObject jso = cvssv2Metrics.getJSONObject(j);
                        final CvssV2Metric metric = new CvssV2Metric();
                        metric.setId(jso.getInt("id"));
                        metric.setAccessComplexity(StringUtils.trimToNull(jso.optString("access_complexity", null)));
                        metric.setCveId(StringUtils.trimToNull(jso.optString("cve_id", null)));
                        metric.setSource(StringUtils.trimToNull(jso.optString("source", null)));
                        metric.setAvailabilityImpact(StringUtils.trimToNull(jso.optString("availability_impact", null)));
                        metric.setConfidentialityImpact(StringUtils.trimToNull(jso.optString("confidentiality_impact", null)));
                        metric.setAuthentication(StringUtils.trimToNull(jso.optString("authentication", null)));
                        metric.setCalculatedCvssBaseScore((jso.optBigDecimal("calculated_cvss_base_score", null)));
                        metric.setGeneratedOn(StringUtils.trimToNull(jso.optString("generated_on", null)));
                        metric.setScore((jso.optBigDecimal("score", null)));
                        metric.setAccessVector(StringUtils.trimToNull(jso.optString("access_vector", null)));
                        metric.setIntegrityImpact(StringUtils.trimToNull(jso.optString("integrity_impact", null)));
                        vulnerability.addCvssV2Metric(metric);
                    }
                }

                final JSONArray cvssv3Metrics = object.optJSONArray("cvss_version_three_metrics");
                if (cvssv3Metrics != null) {
                    for (int j = 0; j < cvssv3Metrics.length(); j++) {
                        final JSONObject jso = cvssv3Metrics.getJSONObject(j);
                        final CvssV3Metric metric = new CvssV3Metric();
                        metric.setId(jso.getInt("id"));
                        metric.setAttackComplexity(StringUtils.trimToNull(jso.optString("attack_complexity", null)));
                        metric.setScope(StringUtils.trimToNull(jso.optString("scope", null)));
                        metric.setAttackVector(StringUtils.trimToNull(jso.optString("attack_vector", null)));
                        metric.setAvailabilityImpact(StringUtils.trimToNull(jso.optString("availability_impact", null)));
                        metric.setScore(jso.optBigDecimal("score", null));
                        metric.setPrivilegesRequired(StringUtils.trimToNull(jso.optString("privileges_required", null)));
                        metric.setUserInteraction(StringUtils.trimToNull(jso.optString("user_interaction", null)));
                        metric.setCveId(StringUtils.trimToNull(jso.optString("cve_id", null)));
                        metric.setSource(StringUtils.trimToNull(jso.optString("source", null)));
                        metric.setConfidentialityImpact(StringUtils.trimToNull(jso.optString("confidentiality_impact", null)));
                        metric.setCalculatedCvssBaseScore(jso.optBigDecimal("calculated_cvss_base_score", null));
                        metric.setGeneratedOn(StringUtils.trimToNull(jso.optString("generated_on", null)));
                        metric.setIntegrityImpact(StringUtils.trimToNull(jso.optString("integrity_impact", null)));
                        vulnerability.addCvssV3Metric(metric);
                    }
                }

                final JSONArray nvdInfo = object.optJSONArray("nvd_additional_information");
                if (nvdInfo != null) {
                    for (int j = 0; j < nvdInfo.length(); j++) {
                        final JSONObject jso = nvdInfo.getJSONObject(j);
                        final NvdAdditionalInfo nvdAdditionalInfo = new NvdAdditionalInfo();
                        nvdAdditionalInfo.setSummary(StringUtils.trimToNull(jso.optString("summary", null)));
                        nvdAdditionalInfo.setCweId(StringUtils.trimToNull(jso.optString("cwe_id", null)));
                        nvdAdditionalInfo.setCveId(StringUtils.trimToNull(jso.optString("cve_id", null)));
                        vulnerability.setNvdAdditionalInfo(nvdAdditionalInfo);
                    }
                }

                final JSONArray vendors = object.optJSONArray("vendors");
                vulnerability.setVendors(parseVendors(vendors));

                vulnerabilities.add(vulnerability);
            }
        }
        return vulnerabilities;
    }

}
