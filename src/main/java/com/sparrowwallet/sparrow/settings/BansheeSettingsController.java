package com.sparrowwallet.sparrow.settings;

import com.sparrowwallet.sparrow.control.UnlabeledToggleSwitch;
import com.sparrowwallet.sparrow.io.Config;
import javafx.fxml.FXML;
import javafx.scene.control.TextField;

public class BansheeSettingsController extends SettingsDetailController {
    @FXML
    private TextField studioUrl;

    @FXML
    private TextField studioToken;

    @FXML
    private UnlabeledToggleSwitch studioSigning;

    @Override
    public void initializeView(Config config) {
        studioUrl.setText(config.getBansheeStudioUrl());
        studioUrl.focusedProperty().addListener((obs, was, now) -> {
            if(was) {
                Config.get().setBansheeStudioUrl(studioUrl.getText());
            }
        });
        studioToken.setText(config.getBansheeStudioToken());
        studioToken.focusedProperty().addListener((obs, was, now) -> {
            if(was) {
                Config.get().setBansheeStudioToken(studioToken.getText());
            }
        });
        studioSigning.setSelected(config.isBansheeStudioSigning());
        studioSigning.selectedProperty().addListener((obs, oldVal, selected) -> {
            Config.get().setBansheeStudioSigning(Boolean.TRUE.equals(selected));
        });
    }
}
