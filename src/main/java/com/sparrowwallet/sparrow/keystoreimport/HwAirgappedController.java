package com.sparrowwallet.sparrow.keystoreimport;

import javafx.fxml.FXML;
import javafx.scene.control.Accordion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HwAirgappedController extends KeystoreImportDetailController {
    private static final Logger log = LoggerFactory.getLogger(HwAirgappedController.class);

    @FXML
    private Accordion importAccordion;

    public void initializeView() {
        // Banshee connects over USB only — no airgapped file or card importers.
    }
}
