/**
 * Copyright 2020 SasanLabs
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.jwt.utils;

import java.awt.GridBagConstraints;
import javax.swing.BorderFactory;
import javax.swing.border.TitledBorder;
import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.utils.FontUtils;

/**
 * Contains the Utility method for handling common UI functionality.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTUIUtils {

    /**
     * Returns the Titled Border with the provided titleKey.
     *
     * @param titleKey, I18N label for the border
     * @return TitledBorder
     */
    public static TitledBorder getTitledBorder(String titleKey) {
        return BorderFactory.createTitledBorder(
                null,
                JWTI18n.getMessage(titleKey),
                TitledBorder.DEFAULT_JUSTIFICATION,
                TitledBorder.DEFAULT_POSITION,
                FontUtils.getFont(FontUtils.Size.standard));
    }

    /**
     * Returns the default configuration instance of GridBagConstraint.
     *
     * @return GridBagConstraints instance.
     */
    public static GridBagConstraints getGridBagConstraints() {
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridx = 0;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.weighty = 1.0D;
        return gridBagConstraints;
    }
}
