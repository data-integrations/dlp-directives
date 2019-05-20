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

package io.cdap.directives;

import com.google.privacy.dlp.v2.InfoType;
import com.google.privacy.dlp.v2.Likelihood;
import io.cdap.cdap.api.annotation.Description;
import io.cdap.cdap.api.annotation.Name;
import io.cdap.cdap.api.annotation.Plugin;
import io.cdap.directives.dlp.RedactService;
import io.cdap.directives.dlp.core.DlpServiceProvider;
import io.cdap.wrangler.api.Arguments;
import io.cdap.wrangler.api.Directive;
import io.cdap.wrangler.api.DirectiveExecutionException;
import io.cdap.wrangler.api.DirectiveParseException;
import io.cdap.wrangler.api.ErrorRowException;
import io.cdap.wrangler.api.ExecutorContext;
import io.cdap.wrangler.api.Optional;
import io.cdap.wrangler.api.ReportErrorAndProceed;
import io.cdap.wrangler.api.Row;
import io.cdap.wrangler.api.annotations.Categories;
import io.cdap.wrangler.api.parser.ColumnName;
import io.cdap.wrangler.api.parser.Identifier;
import io.cdap.wrangler.api.parser.Text;
import io.cdap.wrangler.api.parser.TextList;
import io.cdap.wrangler.api.parser.TokenType;
import io.cdap.wrangler.api.parser.UsageDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * This class <code>Redact</code> redacts sensitive data from a column of text.
 * <p>
 *  Implementation uses Cloud Data Loss Prevention (DLP) APIs. This directive provides
 *  a way for user to specify the column which needs to be inspected to indentify various
 *  info types that user specifies and redacts them.
 * </p>
 *
 * This directive defines four parameters as input of which two are optional
 * <ul>
 *   <li> <b>column</b> - defines the column which should be redacted. Required.</li>
 *   <li> <b>info-type</b> - defines the DLP Info Types (https://cloud.google.com/dlp/docs/infotypes-reference)
 *   that the column should be checked for.</li>
 *   <li> <b>project-id</b> - specifies the GCP project id. When running in GCP. This field is optional</li>
 *   <li> <b>service-account-file-path</b> - specifies the path to service account file to
 *   be used to connect to GCP. This field is optional.</li>
 * </ul>
 *
 * @see <a href="Cloud DLP">https://cloud.google.com/dlp/</a>
 * @see <a href="Cloud DLP InfoTypes">https://cloud.google.com/dlp/docs/infotypes-reference</a>
 */
@Plugin(type = Directive.TYPE)
@Name(Redact.NAME)
@Categories(categories = { "redact","dlp", "cloud"})
@Description("Redact sensitive data from a column")
public class Redact implements Directive {
  private static final Logger LOG = LoggerFactory.getLogger(Redact.class);
  public static final String NAME = "redact";

  // Name of the column on which to redact data.
  private ColumnName column;

  // DLP Info Types to check for before redacting.
  private List<InfoType> infoTypes;

  // GCP Project Id optionally provided when not running in GCP.
  private Identifier projectId;

  // GCP Service Account file provided when not running in GCP.
  private Text saPath;

  // Redact Service handler.
  private RedactService service;

  /**
   * Returns a <code>UsageDefinition</code> that defines the argument this directive expects.
   * The directive requires column-name and one or more info-types. Optionally when used in
   * a non-gcp enviroment, the user would have to provide reference to project-id and service account
   * path file.
   *
   * @return an <code>UsageDefinition</code> object that defines the arguments to directive.
   */
  @Override
  public UsageDefinition define() {
    UsageDefinition.Builder builder = UsageDefinition.builder(NAME);
    builder.define("column", TokenType.COLUMN_NAME);
    builder.define("info-type", TokenType.TEXT_LIST);
    builder.define("project-id", TokenType.IDENTIFIER, Optional.TRUE);
    builder.define("service-account-file-path", TokenType.TEXT, Optional.TRUE);
    return builder.build();
  }

  /**
   * Initializes a directive.
   * <p>
   *   Extract optional and non-optional arguments as well as the creates a
   *   instance of <code>RedactService</code> to be later used for making calls
   *   to DLP.
   * </p>
   * @param args a <code>Arguments</code> instance holding user specified values.
   * @throws DirectiveParseException Thrown when there is issue parsing or initalizaing.
   */
  @Override
  public void initialize(Arguments args) throws DirectiveParseException {
    this.column = args.value("column");

    // Extract all infoTypes user specified and convert it to InfoType objects.
    TextList types = args.value("info-type");
    infoTypes = new ArrayList<InfoType>();
    for (String type : types.value()) {
      infoTypes.add(InfoType.newBuilder().setName(type).build());
    }

    if (args.contains("project-id")) {
      this.projectId = args.value("project-id");
    }

    if (args.contains("service-account-file-path")) {
      this.saPath = args.value("service-account-file-path");
    }

    // Initialize RedactService using the DlpServiceProvider.
    try {
      DlpServiceProvider provider = DlpServiceProvider.instance(
        projectId != null ? projectId.value() : null,
        saPath != null ? saPath.value() : null
      );
      service = new RedactService(provider.getClient(), provider.getProject());
      service.initialize(infoTypes, Likelihood.POSSIBLE);
    } catch (Exception e) {
      throw new DirectiveParseException(e.getMessage());
    }
  }

  /**
   * Redacts the column.
   *
   * <p>The method receives list of <code>Row</code>, finds the column user has specified
   * to redact. If the column is not found, the row is added with the redacted column with
   * null value. If column is found, then <code>RedactService</code> is invoked and the
   * result is stored in the redacted column.</p>
   *
   * @param rows a instance of <code>List<Row></Row></code> that have column to be redacted.
   * @param ctx a instance of <code>ExecutorContext</code>.
   *
   * @return a list of modified <code>Row</code>
   *
   * @throws DirectiveExecutionException thrown when there is execution error.
   * @throws ErrorRowException thrown when a row needs to be added to error port.
   * @throws ReportErrorAndProceed thrown when record needs to be sent to error port,
   * but continue with processing.
   */
  @Override
  public List<Row> execute(List<Row> rows, ExecutorContext ctx)
    throws DirectiveExecutionException, ErrorRowException, ReportErrorAndProceed {
    String redactedColumnName = String.format("%s_redacted", column.value());
    for (Row row : rows) {
      int idx = row.find(column.value());
      if (idx == -1) {
        row.addOrSet(redactedColumnName, null);
        continue; // skip row if column doesn't exist.
      }
      Object value = row.getValue(idx);
      if (value instanceof String) {
        String redactedValue = service.getResult((String) value);
        row.addOrSet(redactedColumnName, redactedValue);
      } else {
        row.addOrSet(redactedColumnName, null);
      }
    }
    return rows;
  }

  /**
   * Invoked when before wrangler shutdowns to relinquish any resources held by directive.
   */
  @Override
  public void destroy() {
    // nothing to be done.
  }

}
