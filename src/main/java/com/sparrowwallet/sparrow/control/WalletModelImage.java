package com.sparrowwallet.sparrow.control;

import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.sparrow.AppServices;
import com.sparrowwallet.sparrow.Theme;
import com.sparrowwallet.sparrow.io.Config;
import javafx.beans.NamedArg;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.StackPane;
import org.girod.javafx.svgimage.SVGImage;
import org.girod.javafx.svgimage.SVGLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;

public class WalletModelImage extends StackPane {
    private static final Logger log = LoggerFactory.getLogger(WalletModelImage.class);

    public static final int WIDTH = 50;
    public static final int HEIGHT = 50;

    private final ObjectProperty<WalletModel> walletModelProperty = new SimpleObjectProperty<>();

    public WalletModelImage() {
        setPrefSize(WIDTH, HEIGHT);
        walletModelProperty.addListener((observable, oldValue, walletModel) -> {
            refresh(walletModel);
        });
    }

    public WalletModelImage(@NamedArg("walletModel") WalletModel walletModel) {
        this();
        walletModelProperty.set(walletModel);
    }

    public WalletModel getWalletModel() {
        return walletModelProperty.get();
    }

    public ObjectProperty<WalletModel> walletModelProperty() {
        return walletModelProperty;
    }

    public void refresh() {
        WalletModel walletModel = getWalletModel();
        refresh(walletModel);
    }

    protected void refresh(WalletModel walletModel) {
        getChildren().clear();
        String type = assetType(walletModel);
        boolean dark = Config.get().getTheme() == Theme.DARK;
        ImageView raster = loadRasterImage("/image/walletmodel/" + type + (dark ? "-invert.png" : ".png"));
        if(raster == null && dark) {
            raster = loadRasterImage("/image/walletmodel/" + type + ".png");
        }
        if(raster != null) {
            getChildren().add(raster);
            return;
        }

        SVGImage svgImage;
        if(dark) {
            svgImage = loadSVGImage("/image/walletmodel/" + type + "-invert.svg");
        } else {
            svgImage = loadSVGImage("/image/walletmodel/" + type + ".svg");
        }

        if(svgImage != null) {
            getChildren().add(svgImage);
        }
    }

    /** This app's own wallet format still reports WalletModel.SPARROW, so draw it with the Banshee mark. */
    private static String assetType(WalletModel walletModel) {
        return walletModel == WalletModel.SPARROW ? "banshee" : walletModel.getType();
    }

    private ImageView loadRasterImage(String imageName) {
        try {
            URL url = AppServices.class.getResource(imageName);
            if(url == null) {
                return null;
            }
            Image image = new Image(url.toExternalForm(), WIDTH, HEIGHT, true, true);
            ImageView view = new ImageView(image);
            view.setFitWidth(WIDTH);
            view.setFitHeight(HEIGHT);
            view.setPreserveRatio(true);
            return view;
        } catch(Exception e) {
            log.error("Could not load image " + imageName);
            return null;
        }
    }

    private SVGImage loadSVGImage(String imageName) {
        try {
            URL url = AppServices.class.getResource(imageName);
            if(url != null) {
                return SVGLoader.load(url);
            }
        } catch(Exception e) {
            log.error("Could not find image " + imageName);
        }

        return null;
    }
}
