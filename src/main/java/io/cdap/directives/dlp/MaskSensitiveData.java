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
import com.google.privacy.dlp.v2.CharacterMaskConfig;
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
import io.cdap.directives.dlp.core.DlpService;

import java.util.List;

/**
 * Masks sensitive data.
 */
public class MaskSensitiveData implements DlpService<String, String> {
  private final DlpServiceClient client;
  private ProjectName project;
  private InspectConfig inspectConfig;
  private DeidentifyConfig deidentifyConfig;

  public MaskSensitiveData(DlpServiceClient client, ProjectName project) {
    this.client = client;
    this.project = project;
  }

  public void initialize(List<InfoType> infoTypes, String character) {
    initialize(infoTypes, character, -1, false);
  }

  public void initialize(List<InfoType> infoTypes, String character, boolean reverse) {
    initialize(infoTypes, character, -1, reverse);
  }

  public void initialize(List<InfoType> infoTypes, String character, int numberToMask) {
    initialize(infoTypes, character, numberToMask, false);
  }

  public void initialize(List<InfoType> infoTypes, String character, int numberToMask, boolean reverse) {
    inspectConfig =
      InspectConfig.newBuilder()
        .addAllInfoTypes(infoTypes)
        .setMinLikelihood(Likelihood.POSSIBLE)
        .build();

    CharacterMaskConfig.Builder builder = CharacterMaskConfig.newBuilder()
      .setMaskingCharacter(character);

    if (numberToMask > 0) {
      builder.setNumberToMask(numberToMask);
    }

    CharacterMaskConfig characterMaskConfig =
      builder
        .setReverseOrder(reverse)
        .build();

    PrimitiveTransformation primitiveTransformation = PrimitiveTransformation.newBuilder()
      .setCharacterMaskConfig(characterMaskConfig)
      .build();

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

