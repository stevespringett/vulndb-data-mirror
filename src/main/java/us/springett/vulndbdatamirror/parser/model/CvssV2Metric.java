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
package us.springett.vulndbdatamirror.parser.model;

import us.springett.cvss.CvssV2;
import java.math.BigDecimal;

/**
 * The response from VulnDB Vulnerability API will respond with 0 or more CVSS Metrics.
 * This class defines the CvssV2Metric objects returned.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class CvssV2Metric {

    private int id;

    private String accessComplexity;

    private String cveId;

    private String source;

    private String availabilityImpact;

    private String confidentialityImpact;

    private String authentication;

    private BigDecimal calculatedCvssBaseScore;

    private String generatedOn;

    private BigDecimal score;

    private String accessVector;

    private String integrityImpact;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getAccessComplexity() {
        return accessComplexity;
    }

    public void setAccessComplexity(String accessComplexity) {
        this.accessComplexity = accessComplexity;
    }

    public String getCveId() {
        return cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getAvailabilityImpact() {
        return availabilityImpact;
    }

    public void setAvailabilityImpact(String availabilityImpact) {
        this.availabilityImpact = availabilityImpact;
    }

    public String getConfidentialityImpact() {
        return confidentialityImpact;
    }

    public void setConfidentialityImpact(String confidentialityImpact) {
        this.confidentialityImpact = confidentialityImpact;
    }

    public String getAuthentication() {
        return authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    public BigDecimal getCalculatedCvssBaseScore() {
        return calculatedCvssBaseScore;
    }

    public void setCalculatedCvssBaseScore(BigDecimal calculatedCvssBaseScore) {
        this.calculatedCvssBaseScore = calculatedCvssBaseScore;
    }

    public String getGeneratedOn() {
        return generatedOn;
    }

    public void setGeneratedOn(String generatedOn) {
        this.generatedOn = generatedOn;
    }

    public BigDecimal getScore() {
        return score;
    }

    public void setScore(BigDecimal score) {
        this.score = score;
    }

    public String getAccessVector() {
        return accessVector;
    }

    public void setAccessVector(String accessVector) {
        this.accessVector = accessVector;
    }

    public String getIntegrityImpact() {
        return integrityImpact;
    }

    public void setIntegrityImpact(String integrityImpact) {
        this.integrityImpact = integrityImpact;
    }

    public CvssV2 toNormalizedMetric() {
        CvssV2 cvss = new CvssV2();

        if ("ADJACENT_NETWORK".equals(this.accessVector)) {
            cvss.attackVector(CvssV2.AttackVector.ADJACENT);
        } else if ("LOCAL".equals(this.accessVector)) {
            cvss.attackVector(CvssV2.AttackVector.LOCAL);
        } else if ("NETWORK".equals(this.accessVector)) {
            cvss.attackVector(CvssV2.AttackVector.NETWORK);
        }

        if ("SINGLE_INSTANCE".equals(this.authentication)) {
            cvss.authentication(CvssV2.Authentication.SINGLE);
        } else if ("MULTIPLE_INSTANCES".equals(this.authentication)) {
            cvss.authentication(CvssV2.Authentication.MULTIPLE);
        } else if ("NONE".equals(this.authentication)) {
            cvss.authentication(CvssV2.Authentication.NONE);
        }

        cvss.attackComplexity(CvssV2.AttackComplexity.valueOf(this.accessComplexity));
        cvss.confidentiality(CvssV2.CIA.valueOf(this.confidentialityImpact));
        cvss.integrity(CvssV2.CIA.valueOf(this.integrityImpact));
        cvss.availability(CvssV2.CIA.valueOf(this.availabilityImpact));

        return cvss;
    }
}
