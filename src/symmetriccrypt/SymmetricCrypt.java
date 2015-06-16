/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package symmetriccrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.Modality;
import javafx.stage.Stage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author dani
 */
public class SymmetricCrypt extends Application {
    
    private Stage stage;
    private Stage errorStage;
    private ArrayList<Integer> keySizes;
    private SecretKey key;
    private byte[] encryptedData;
    private byte[] regularData;
    
    private Scene mainScene() {
        
        GridPane gridPane = new GridPane();
        gridPane.setVgap(25);
        gridPane.setHgap(25);
        gridPane.setAlignment(Pos.CENTER);
        
        Label msgLabel = new Label("Missatge");
        gridPane.add(msgLabel, 0, 0);
        
        final TextField msgField = new TextField();
        gridPane.add(msgField, 1, 0);
        GridPane.setColumnSpan(msgField, 3);
        
        Label passLabel = new Label("Contrasenya");
        gridPane.add(passLabel, 0, 1);
        
        final PasswordField passField = new PasswordField();
        gridPane.add(passField, 1, 1);
        GridPane.setColumnSpan(passField, 3);
        
        Label algLabel = new Label("Algorisme");
        gridPane.add(algLabel, 0 ,2);
        
        final ComboBox<String> algBox = new ComboBox<>();
        algBox.getItems().addAll("AES","DES");
        algBox.setValue("AES");
        gridPane.add(algBox, 1, 2);
        
        Label keySizeLabel = new Label("mida clau");
        gridPane.add(keySizeLabel, 2, 2);
        
        final ComboBox<Integer> keySizeBox = new ComboBox<>();
        keySizeBox.getItems().addAll(64,128,192,256);
        keySizeBox.setValue(128);
        gridPane.add(keySizeBox, 3, 2);
        
        final TextField output = new TextField();
        gridPane.add(output, 0, 3);
        output.setEditable(false);
        GridPane.setColumnSpan(output, 5);
        
        Button encryptBtn = new Button("Encriptar");
        gridPane.add(encryptBtn, 4, 0);
        encryptBtn.setMinWidth(125);
        
        encryptBtn.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent t) {
                if (msgField.getText().length() != 0 & passField.getText().length() != 0) {
                    try {
                        if (algBox.getValue().equals("AES") & keySizeBox.getValue() == 64) {
                            keySizeBox.setValue(128);
                            showErrorDialog("L'algorisme AES te una mida de clau minima de 128 bits");
                        } else if (algBox.getValue().equals("DES") & keySizeBox.getValue() != 64) {
                            keySizeBox.setValue(64);
                            showErrorDialog("L'algorisme DES te una mida de clau de 64 bits");
                        }
                        key = Functions.secretKeyGen(keySizeBox.getValue(), passField.getText(), algBox.getValue());
                    } catch (UnsupportedEncodingException ex) {
                        Logger.getLogger(SymmetricCrypt.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(SymmetricCrypt.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    encryptedData = Functions.encryptData(key, msgField.getText(), algBox.getValue());
                    output.setText(Functions.byteArrayToHexString(encryptedData));
                } else {
                    showErrorDialog("Introdueix un missatge i una contrasenya");
                }
            }
        });
        
        Button decryptBtn = new Button("Desencriptar");
        gridPane.add(decryptBtn, 4, 1);
        decryptBtn.setMinWidth(125);
        
        decryptBtn.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent t) {
                if (msgField.getText().length() != 0 | msgField.getText().length() != 0) {
                    try {
                        if (algBox.getValue().equals("AES") & keySizeBox.getValue() == 64) {
                            keySizeBox.setValue(128);
                            showErrorDialog("L'algorisme AES te una mida de clau minima de 128 bits");
                        } else if (algBox.getValue().equals("DES") & keySizeBox.getValue() != 64) {
                            keySizeBox.setValue(64);
                            showErrorDialog("L'algorisme DES te una mida de clau de 64 bits");
                        }
                        key = Functions.secretKeyGen(keySizeBox.getValue(), passField.getText(), algBox.getValue());
                        encryptedData = Functions.decryptData(key, msgField.getText(), algBox.getValue());
                        output.setText(new String(encryptedData, "UTF-8"));
                    } catch (UnsupportedEncodingException ex) {
                        Logger.getLogger(SymmetricCrypt.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(SymmetricCrypt.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchPaddingException ex) {
                        Logger.getLogger(SymmetricCrypt.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeyException ex) {
                        Logger.getLogger(SymmetricCrypt.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        Logger.getLogger(SymmetricCrypt.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        Logger.getLogger(SymmetricCrypt.class.getName()).log(Level.SEVERE, null, ex);
                    }
                } else {
                    showErrorDialog("Introdueix un missatge i una contrasenya");
                }
            }
        });
        
        Button exitBtn = new Button("Sortir");
        exitBtn.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent t) {
                stage.close();
            }
        });
        gridPane.add(exitBtn, 4, 4);
        exitBtn.setMinWidth(125);
        
        Scene scene = new Scene (gridPane, 640, 280, Color.web("eee"));
        return scene;
    }
    
    public void showErrorDialog(String msg) {
        VBox vbox = new VBox(25);
        vbox.setMinWidth(180);
        vbox.setMaxWidth(180);
        vbox.setAlignment(Pos.CENTER);
        Button exitButton = new Button("Ok");
        exitButton.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent t) {
                errorStage.close();
            }
        });
        Label text = new Label(msg);
        text.maxWidth(50);
        vbox.getChildren().addAll(text, exitButton);
        
        Scene scene = new Scene(vbox, 400, 100, Color.web("eee"));
        errorStage = new Stage();
        errorStage.setScene(scene);
        errorStage.initModality(Modality.WINDOW_MODAL);
        errorStage.initOwner(stage);
        errorStage.show();
    }
    
    @Override
    public void start(Stage primaryStage) {

        stage = new Stage();
        stage.setScene(mainScene());
        stage.setResizable(false);
        stage.show();
        
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        launch(args);
    }
    
}
