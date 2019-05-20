/*
 * Copyright © 2019 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package io.cdap.directives.dlp.core;

import com.google.api.gax.core.CredentialsProvider;
import com.google.auth.Credentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.ServiceOptions;
import com.google.cloud.dlp.v2.DlpServiceClient;
import com.google.cloud.dlp.v2.DlpServiceSettings;
import com.google.privacy.dlp.v2.ProjectName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * This class <code>DlpServiceProvider</code> provides a singleton instance of <code>DlpServiceClient</code>.
 * <p>
 *   In scenario where there are multiple columns that need to use DLP, this provides an optimization.But, across
 *   multiple Wrangler, they will have separate connections to DLP.
 * </p>
 *
 */
public final class DlpServiceProvider {
  private static final Logger LOG = LoggerFactory.getLogger(DlpServiceProvider.class);
  private static DlpServiceProvider instance = null;
  private final DlpServiceClient client;
  private final ProjectName project;

  private DlpServiceProvider(DlpServiceClient client, ProjectName project) {
    this.client = client;
    this.project = project;
  }

  /**
   *
   * @param projectId
   * @param saPath
   * @return
   */
  public static DlpServiceProvider instance(String projectId, String saPath) throws Exception {
    if (instance == null) {
      synchronized (DlpServiceProvider.class) {
        if (instance == null) {
          DlpServiceSettings.Builder builder = DlpServiceSettings.newBuilder();
          if (saPath != null) {
            File credentialsPath = new File(saPath);
            try (FileInputStream serviceAccountStream = new FileInputStream(credentialsPath)) {
              ServiceAccountCredentials serviceAccountCredentials =
                ServiceAccountCredentials.fromStream(serviceAccountStream);
              builder.setCredentialsProvider(new CredentialsProvider() {
                @Override
                public Credentials getCredentials() throws IOException {
                  return serviceAccountCredentials;
                }
              });
            }
          }
          DlpServiceClient client = DlpServiceClient.create(builder.build());
          if (projectId == null || projectId.isEmpty()) {
            projectId = ServiceOptions.getDefaultProjectId();
          }
          instance = new DlpServiceProvider(client, ProjectName.of(projectId));
        }
      }
    }
    return instance;
  }

  /**
   * @return a instance of <code>DlpServiceClient</code> that was created.
   */
  public DlpServiceClient getClient() {
    return client;
  }

  /**
   * @return a instance of <code>ProjectName</code> for the GCP project.
   */
  public ProjectName getProject() {
    return project;
  }
}
