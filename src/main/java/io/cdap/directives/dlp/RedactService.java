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

package io.cdap.directives.dlp;

import com.google.cloud.dlp.v2.DlpServiceClient;
import com.google.privacy.dlp.v2.ContentItem;
import com.google.privacy.dlp.v2.DeidentifyConfig;
import com.google.privacy.dlp.v2.DeidentifyContentRequest;
import com.google.privacy.dlp.v2.DeidentifyContentResponse;
import com.google.privacy.dlp.v2.InfoType;
import com.google.privacy.dlp.v2.InfoTypeTransformations;
import com.google.privacy.dlp.v2.InspectConfig;
import com.google.privacy.dlp.v2.Likelihood;
import com.google.privacy.dlp.v2.PrimitiveTransformation;
import com.google.privacy.dlp.v2.ProjectName;
import com.google.privacy.dlp.v2.RedactConfig;
import io.cdap.directives.dlp.core.DlpService;

import java.util.List;

/**
 * This class <code>RedactService</code> detects and redacts sensitive data.
 *
 * <p>Implements <code>DlpService</code> interface. The class is initialized
 * with singleton <code>DlpServiceClient</code> that is provided by the
 * <code>DlpServiceProvider</code>.</p>
 *
 * <p>The class is intialized with collection of user defined <code>InfoType</code>
 * and minimum <code>Likelihood</code></p> of Info types.
 */
public class RedactService implements DlpService<String, String> {
  private final DlpServiceClient client;
  private ProjectName project;
  private InspectConfig inspectConfig;
  private DeidentifyConfig deidentifyConfig;

  /**
   * Cronstructs a class with instance of <code>DlpServiceClient</code> and the project id.
   *
   * @param client a instance of <code>DlpServiceClient</code> to make calls to DLP.
   * @param project a instance of <code>ProjectName</code>.
   */
  public RedactService(DlpServiceClient client, ProjectName project) {
    this.client = client;
    this.project = project;
  }

  /**
   * Initializes this class with list of user defined <code>InfoType</code> and <code>Likelihood</code>.
   *
   * <p>The method configures and builds the <code>DeidentifyConfig</code>
   * that is used in every call when it's made with data.</p>
   *
   * @param infoTypes a list of <code>InfoType</code>.
   * @param likelihood a instance of <code>Likelihood</code> for thresholding the detection.
   */
  public void initialize(List<InfoType> infoTypes, Likelihood likelihood) {
    inspectConfig =
      InspectConfig.newBuilder()
        .addAllInfoTypes(infoTypes)
        .setMinLikelihood(likelihood)
        .build();

    RedactConfig redactConfig = RedactConfig.newBuilder().build();

    PrimitiveTransformation primitiveTransformation =
      PrimitiveTransformation.newBuilder().setRedactConfig(redactConfig).build();

    InfoTypeTransformations.InfoTypeTransformation infoTypeTransformation =
      InfoTypeTransformations.InfoTypeTransformation.newBuilder()
        .setPrimitiveTransformation(primitiveTransformation)
        .build();

    InfoTypeTransformations infoTypeTransformations =
      InfoTypeTransformations.newBuilder()
        .addTransformations(infoTypeTransformation)
        .build();

    deidentifyConfig = DeidentifyConfig.newBuilder()
      .setInfoTypeTransformations(infoTypeTransformations)
      .build();
  }

  /**
   *
   * @param data
   * @return
   */
  @Override
  public String getResult(String data) {
    ContentItem contentItem = ContentItem.newBuilder().setValue(data).build();
    DeidentifyContentRequest request = DeidentifyContentRequest.newBuilder()
      .setParent(project.toString())
      .setInspectConfig(inspectConfig)
      .setDeidentifyConfig(deidentifyConfig)
      .setItem(contentItem)
      .build();
    DeidentifyContentResponse response = client.deidentifyContent(request);
    return response.getItem().getValue();
  }
}


