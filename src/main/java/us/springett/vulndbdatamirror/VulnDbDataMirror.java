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
package us.springett.vulndbdatamirror;

import org.apache.commons.io.FileUtils;
import us.springett.vulndbdatamirror.client.VulnDbApi;
import us.springett.vulndbdatamirror.parser.model.Results;
import java.io.File;
import java.io.IOException;

/**
 * This self-contained class can be called from the command-line. It downloads the
 * contents of the VulnDB service to the specified output path.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class VulnDbDataMirror {

    private String consumerKey;
    private String consumerSecret;
    private File outputDir;
    private boolean downloadFailed = false;

    public static void main (String[] args) {
        // Ensure at least three argument was specified
        if (args.length != 3) {
            System.out.println("Usage: java VulnDbDataMirror consumerKey consumerSecret outputDir");
            return;
        }
        VulnDbDataMirror mirror = new VulnDbDataMirror(args[0], args[1], args[2]);
        mirror.mirror();
        if (mirror.downloadFailed) {
          System.exit(1);
        }
    }

    public VulnDbDataMirror(String consumerKey, String consumerSecret, String outputDirPath) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.outputDir = new File(outputDirPath);
        if ( ! outputDir.exists()) {
            outputDir.mkdirs();
        }
    }

    public void mirror() {
        final VulnDbApi api = new VulnDbApi(this.consumerKey, this.consumerSecret);

        System.out.print("\nMirroring Vendors feed...");
        int page = 1;
        boolean more = true;
        while (more) {
            final Results results = api.getVendors(100, page);
            more = processResults(this.outputDir, "vendors_", results);
            System.out.print(".");
            page++;
        }

        System.out.print("\nMirroring Products feed...");
        page = 1;
        more = true;
        while (more) {
            final Results results = api.getProducts(100, page);
            more = processResults(this.outputDir, "products_", results);
            System.out.print(".");
            page++;
        }

        System.out.print("\nMirroring Vulnerabilities feed...");
        page = 1;
        more = true;
        while (more) {
            final Results results = api.getVulnerabilities(100, page);
            more = processResults(this.outputDir, "vulnerabilities_", results);
            System.out.print(".");
            page++;
        }
    }

    private boolean processResults(File dir, String leadIn, Results results) {
        try {
            FileUtils.writeStringToFile(new File(dir, leadIn + results.getPage() + ".json"), results.getRawResults(), "UTF-8");
        } catch (IOException ex) {
            System.err.println("Error writing VulnDB output to file");
            System.err.println(ex.getMessage());
        }
        return results.getPage() * 100 < results.getTotal();
    }

}
