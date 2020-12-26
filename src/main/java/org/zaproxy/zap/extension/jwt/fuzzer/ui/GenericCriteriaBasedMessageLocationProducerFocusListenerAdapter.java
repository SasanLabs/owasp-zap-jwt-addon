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
package org.zaproxy.zap.extension.jwt.fuzzer.ui;

import java.awt.event.FocusEvent;
import java.util.function.Supplier;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducer;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducerFocusListenerAdapter;

/**
 * This class is the generic criteria based {@code FocusListener} adapter. This is an extension to
 * {@link MessageLocationProducerFocusListenerAdapter} where this can be used to listen to changes
 * in focus of {@code MessageLocationProducer}s and propagate the event if provided criteria is
 * fulfilled.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class GenericCriteriaBasedMessageLocationProducerFocusListenerAdapter
        extends MessageLocationProducerFocusListenerAdapter {

    private final Supplier<Boolean> criteriaSupplier;

    public GenericCriteriaBasedMessageLocationProducerFocusListenerAdapter(
            MessageLocationProducer source, Supplier<Boolean> criteriaSupplier) {
        super(source);
        this.criteriaSupplier = criteriaSupplier;
    }

    @Override
    public void focusGained(FocusEvent e) {
        if (!this.criteriaSupplier.get()) {
            return;
        }
        super.focusGained(e);
    }
}
