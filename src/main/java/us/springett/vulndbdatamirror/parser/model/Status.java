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

/**
 * Defines a top-level Status object.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class Status {

    private String organizationName;
    private String userNameRequesting;
    private String userEmailRequesting;
    private String subscriptionEndDate;
    private String apiCallsAllowedPerMonth;
    private String apiCallsMadeThisMonth;
    private String vulnDbStatistics;
    private String rawStatus;


    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getUserNameRequesting() {
        return userNameRequesting;
    }

    public void setUserNameRequesting(String userNameRequesting) {
        this.userNameRequesting = userNameRequesting;
    }

    public String getUserEmailRequesting() {
        return userEmailRequesting;
    }

    public void setUserEmailRequesting(String userEmailRequesting) {
        this.userEmailRequesting = userEmailRequesting;
    }

    public String getSubscriptionEndDate() {
        return subscriptionEndDate;
    }

    public void setSubscriptionEndDate(String subscriptionEndDate) {
        this.subscriptionEndDate = subscriptionEndDate;
    }

    public String getApiCallsAllowedPerMonth() {
        return apiCallsAllowedPerMonth;
    }

    public void setApiCallsAllowedPerMonth(String apiCallsAllowedPerMonth) {
        this.apiCallsAllowedPerMonth = apiCallsAllowedPerMonth;
    }

    public String getApiCallsMadeThisMonth() {
        return apiCallsMadeThisMonth;
    }

    public void setApiCallsMadeThisMonth(String apiCallsMadeThisMonth) {
        this.apiCallsMadeThisMonth = apiCallsMadeThisMonth;
    }

    public String getVulnDbStatistics() {
        return vulnDbStatistics;
    }

    public void setVulnDbStatistics(String vulnDbStatistics) {
        this.vulnDbStatistics = vulnDbStatistics;
    }

    public String getRawStatus() {
        return rawStatus;
    }

    public void setRawStatus(String rawStatus) {
        this.rawStatus = rawStatus;
    }
}
