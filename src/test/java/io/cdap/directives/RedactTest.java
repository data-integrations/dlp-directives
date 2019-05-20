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


import io.cdap.wrangler.api.RecipePipeline;
import io.cdap.wrangler.api.Row;
import io.cdap.wrangler.test.TestingRig;
import io.cdap.wrangler.test.api.TestRecipe;
import io.cdap.wrangler.test.api.TestRows;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.util.List;

/**
 * Tests {@link Redact}
 */
public class RedactTest {

  @Ignore
  @Test
  public void testBasic() throws Exception {
    TestRecipe recipe = new TestRecipe();
    recipe.add("redact :body 'ALL_BASIC','EMAIL_ADDRESS' cloud-data-fusion-demos " +
                 "'/Users/nmotgi/Work/Demo/cloud-data-fusion-demos-ebb2d12d796b.json'");

    TestRows rows = new TestRows();
    rows.add(new Row("body", "cdap-user@googlegroup.com is a male email id with ssn 567-376-9125"));
    rows.add(new Row("body", "testing"));
    rows.add(new Row("body", "Male"));
    rows.add(new Row("body", "567-376-9125"));

    RecipePipeline pipeline = TestingRig.pipeline(Redact.class, recipe);
    List<Row> actuals = pipeline.execute(rows.toList());
    Assert.assertEquals(4, actuals.size());
  }
}
