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

import us.springett.vulndbdatamirror.client.VulnDbApi;

import java.io.File;

/**
 * This self-contained class can be called from the command-line. It downloads the
 * contents of the VulnDB service to the specified output path.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class VulnDbDataMirror {

    private File outputDir;
    private boolean downloadFailed = false;

    public static void main (String[] args) {

        //todo:
        System.out.println("NOT YET FUNCTIONAL");

        // Ensure at least one argument was specified
        if (args.length != 1) {
            System.out.println("Usage: java VulnDbDataMirror outputDir");
            return;
        }
        VulnDbDataMirror mirror = new VulnDbDataMirror(args[0]);
        mirror.mirror();
        if (mirror.downloadFailed) {
          System.exit(1);
        }
    }

    public VulnDbDataMirror(String outputDirPath) {
        outputDir = new File(outputDirPath);
        if ( ! outputDir.exists()) {
            outputDir.mkdirs();
        }
    }

    public void mirror() {
        VulnDbApi api = new VulnDbApi("", "");
        //todo
        //System.out.println("Downloading files at " + currentDate);
    }
}
