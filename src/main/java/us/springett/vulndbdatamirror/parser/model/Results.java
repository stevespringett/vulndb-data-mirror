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

import java.util.ArrayList;
import java.util.List;

/**
 * Defines a top-level Results object containing a list of
 * possible results and count/page data.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class Results {

    private int page;
    private int total;
    private List<Object> results = new ArrayList<>();
    private String rawResults;

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public List<Object> getResults() {
        return results;
    }

    @SuppressWarnings("unchecked")
    public void setResults(List objects) {
        this.results = objects;
    }

    public void add(Object object) {
        results.add(object);
    }

    public String getRawResults() {
        return rawResults;
    }

    public void setRawResults(String rawResults) {
        this.rawResults = rawResults;
    }
}
