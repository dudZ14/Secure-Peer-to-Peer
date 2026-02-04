package gui;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javafx.animation.ScaleTransition;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Cursor;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.Tooltip;
import javafx.scene.image.Image;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.RowConstraints;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.stage.Stage;
import javafx.util.Duration;
import node.DataStore;
import node.P2PNode;

public class GUI extends Application {

    private P2PNode node;
    private Label resultLabel;
    private Label statusLabel;
    private ComboBox<String> tableComboBox;
    private Button addTableBtn;
    private Circle statusIndicator;
    private TableView<KeyValueEntry> dataTable;
    private ObservableList<KeyValueEntry> tableData;

    private void setButtonState(Button btn, boolean enabled) {

        Tooltip tt = btn.getTooltip();

        if (enabled) {
            btn.setOpacity(1.0);
            btn.setCursor(Cursor.HAND);

            // remover tooltip ao ativar
            if (tt != null)
                Tooltip.uninstall(btn, tt);

            // restaurar handler original
            Object saved = btn.getUserData();
            if (saved instanceof EventHandler<?>) {
                @SuppressWarnings("unchecked")
                EventHandler<ActionEvent> original = (EventHandler<ActionEvent>) saved;

                btn.setOnAction(original);
            }

        } else {
            btn.setOpacity(0.4);
            btn.setCursor(Cursor.DEFAULT);

            // instalar tooltip ao desativar
            if (tt != null)
                Tooltip.install(btn, tt);

            // guardar handler original uma única vez
            if (btn.getUserData() == null) {
                btn.setUserData(btn.getOnAction());
            }

            // desativar completamente
            btn.setOnAction((EventHandler<ActionEvent>) null);
        }
    }

    private void handleSearchAction(String key) {
        if (key.isEmpty()) {
            updateResult("Empty key!", false);
            return;
        }

        // Run the search in a separate thread to avoid blocking the JavaFX UI thread
        new Thread(() -> {
            try {
                // Call the P2PNode's global search method
                Map<String, List<String>> allResults = node.localSearch(key);

                // Replace the existing logic inside Platform.runLater:
                Platform.runLater(() -> {
                    if (allResults.isEmpty()) {
                        updateResult("key not found", false);
                    } else {
                        // 1. Use a Set to store and ensure unique table names
                        Set<String> uniqueTableNames = new HashSet<>();

                        // 2. Iterate over all results from all nodes
                        // allResults.values() returns a Collection<List<String>>
                        allResults.values().forEach(resultsList -> {
                            // resultsList contains entries like "tableName"
                            resultsList.forEach(tableName -> {
                                uniqueTableNames.add(tableName);
                            });
                        });

                        // 3. Join the unique table names with a newline character
                        String resultText = String.join("\n", uniqueTableNames);

                        updateResult(resultText, false);
                    }
                });
            } catch (Exception ex) {
                Platform.runLater(() -> {
                    updateResult("Search failed: " + ex.getMessage(), true);
                    ex.printStackTrace();
                });
            }
        }).start();
    }

    // Assuming updateResult is an existing method to show status/results
    private void updateResult(String value, boolean isError) {
        // Existing logic from your GUI.java (snippetFromBack)
        Platform.runLater(() -> {
            if (isError) {
                resultLabel.setText("ERROR: " + value);
                // ... set error style
            } else {
                resultLabel.setText(value);
                // ... set success style
            }
        });
    }

    @SuppressWarnings("unused")
	@Override
    public void start(Stage primaryStage) {

        // === Status Indicator ===
        statusIndicator = new Circle(6);
        statusIndicator.setFill(Color.RED);
        statusLabel = new Label("Status: Off");
        statusLabel.setStyle("-fx-text-fill: #cccccc;");

        HBox statusBox = new HBox(8, statusIndicator, statusLabel);
        statusBox.setAlignment(Pos.CENTER_LEFT);

        // === Header ===
        Label titleLabel = new Label("DHT P2P Secure Network");
        titleLabel.setStyle("-fx-font-size: 22px; -fx-font-weight: bold; -fx-text-fill: #ffffff;");

        statusBox.setAlignment(Pos.CENTER);

        VBox header = new VBox(0, titleLabel, statusBox);
        header.setAlignment(Pos.CENTER);
        header.setPadding(new Insets(0, 0, 0, 0));

        // === Node configuration ===
        TextField nodeIdField = new TextField("node1");
        TextField portField = new TextField("5000");
        Button startBtn = new Button("START NODE");
        startBtn.setMaxWidth(Double.MAX_VALUE);

        // === Bootstrap peer configuration ===
        TextField bootstrapIdField = new TextField("node2");
        TextField bootstrapHostField = new TextField("localhost");
        TextField bootstrapPortField = new TextField("5001");
        Button bootstrapBtn = new Button("BOOTSTRAP");
        bootstrapBtn.setMaxWidth(Double.MAX_VALUE);

        // === Blind Bootstrap Button ===
        Button blindBootstrapBtn = new Button("BLIND BOOTSTRAP");
        blindBootstrapBtn.setMaxWidth(Double.MAX_VALUE);

        // === Local operations ===
        TextField localKeyField = new TextField("key");
        TextField localValueField = new TextField("value");
        TextField localTableField = new TextField("global");
        Button localPutBtn = new Button("PUT");
        Button localGetBtn = new Button("GET");
        Button searchBtn = new Button("SEARCH");

        localPutBtn.setMaxWidth(Double.MAX_VALUE);
        localGetBtn.setMaxWidth(Double.MAX_VALUE);
        searchBtn.setMaxWidth(Double.MAX_VALUE);

        Tooltip thresholdTooltip = new Tooltip("You need to be connected to someone");
        localPutBtn.setTooltip(thresholdTooltip);
        localGetBtn.setTooltip(thresholdTooltip);
        searchBtn.setTooltip(thresholdTooltip);

        setButtonState(localPutBtn, false);
        setButtonState(localGetBtn, false);
        setButtonState(searchBtn, false);

        HBox putGetButtons = new HBox(10, localPutBtn, localGetBtn);
        HBox.setHgrow(localPutBtn, Priority.ALWAYS);
        HBox.setHgrow(localGetBtn, Priority.ALWAYS);

        VBox operationButtons = new VBox(8, putGetButtons, searchBtn);

        // === Result display area ===
        resultLabel = new Label("");
        resultLabel.setStyle("-fx-text-fill: #ffffff; -fx-font-size: 16px; -fx-font-weight: bold;");
        resultLabel.setAlignment(Pos.CENTER);
        resultLabel.setMaxWidth(Double.MAX_VALUE);
        resultLabel.setPrefHeight(400);

        VBox resultContainer = new VBox(resultLabel);
        resultContainer.setAlignment(Pos.CENTER);
        resultContainer.setStyle(
                "-fx-background-color: #2b2b2b; -fx-background-radius: 6; -fx-border-color: #555555; -fx-border-radius: 6;");
        resultContainer.setPadding(new Insets(10));
        VBox.setVgrow(resultContainer, Priority.NEVER); // Allow it to grow

        // === Table Selection ===
        Label tableLabel = new Label("Current Table:");
        tableLabel.setStyle("-fx-text-fill: #b0b0b0; -fx-font-size: 12px;");

        tableComboBox = new ComboBox<>();
        tableComboBox.getItems().add("global");
        tableComboBox.setValue("global");
        tableComboBox.setMaxWidth(150);
        tableComboBox.setPrefWidth(150);
        tableComboBox.setStyle("-fx-background-color: #2b2b2b; -fx-text-fill: #ffffff; -fx-border-color: #555555;");

        tableComboBox.valueProperty().addListener((observable, oldValue, newValue) -> {
            refreshDatabaseView();
        });

        tableComboBox.setButtonCell(new ListCell<String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText("global");
                } else {
                    setText(item);
                }
                setStyle("-fx-text-fill: #ffffff; -fx-background-color: #2b2b2b;");
            }
        });

        addTableBtn = new Button("+ Add Table");
        addTableBtn.setMaxWidth(100);

        HBox tableSelection = new HBox(10, tableLabel, tableComboBox, addTableBtn);
        tableSelection.setAlignment(Pos.CENTER_LEFT);
        tableSelection.setPadding(new Insets(0, 0, 2, 0));

        // === Database Viewer ===
        tableData = FXCollections.observableArrayList();
        dataTable = createDatabaseTable();

        VBox databaseViewer = createCard("Database", dataTable);
        databaseViewer.setMaxHeight(Double.MAX_VALUE);
        VBox.setVgrow(databaseViewer, Priority.ALWAYS);

        // === Apply hover animations ===
        Button[] allButtons = { startBtn, bootstrapBtn, blindBootstrapBtn, addTableBtn };

        for (Button btn : allButtons) {
            ScaleTransition stEnter = new ScaleTransition(Duration.millis(200), btn);
            stEnter.setToX(1.05);
            stEnter.setToY(1.05);

            ScaleTransition stExit = new ScaleTransition(Duration.millis(200), btn);
            stExit.setToX(1.0);
            stExit.setToY(1.0);

            btn.setOnMouseEntered(_ -> stEnter.playFromStart());
            btn.setOnMouseExited(_ -> stExit.playFromStart());
            btn.setCursor(javafx.scene.Cursor.HAND);
        }

        // === Node Card ===
        VBox innerBox = new VBox(5,
                createFormRow("Node ID", nodeIdField),
                createFormRow("Local Port", portField),
                startBtn,
                blindBootstrapBtn);

        VBox.setMargin(blindBootstrapBtn, new Insets(10, 0, 0, 0));

        VBox nodeCard = createCard("Your Node", innerBox);
        nodeCard.setMinHeight(300);
        nodeCard.setPrefHeight(300);
        nodeCard.setMaxHeight(300);

        // === Bootstrap Card ===
        VBox bootstrapCard = createCard("Bootstrap Manual",
                new VBox(5,
                        createFormRow("Peer ID", bootstrapIdField),
                        createFormRow("Host", bootstrapHostField),
                        createFormRow("Port", bootstrapPortField),
                        bootstrapBtn));
        bootstrapCard.setMinHeight(300);
        bootstrapCard.setPrefHeight(300);
        bootstrapCard.setMaxHeight(300);

        // === Operations Card ===
        VBox operationsCard = createCard("Operations",
                new VBox(8,
                        createFormRow("Key", localKeyField),
                        createFormRow("Value", localValueField),
                        createFormRow("Table", localTableField),
                        operationButtons,
                        new Label("Result:"),
                        resultContainer));
        operationsCard.setMinHeight(480);
        operationsCard.setPrefHeight(480);
        operationsCard.setMaxHeight(480);

        // === Main container ===
        GridPane mainContainer = new GridPane();
        mainContainer.setHgap(15);
        mainContainer.setVgap(10);
        mainContainer.setPadding(new Insets(10));

        // Adicionar os cards com alinhamento no topo
        mainContainer.add(nodeCard, 0, 0);
        GridPane.setValignment(nodeCard, javafx.geometry.VPos.TOP);

        mainContainer.add(bootstrapCard, 1, 0);
        GridPane.setValignment(bootstrapCard, javafx.geometry.VPos.TOP);

        mainContainer.add(operationsCard, 2, 0);

        VBox tableAndDatabase = new VBox(0, tableSelection, databaseViewer);
        VBox.setMargin(tableSelection, new Insets(-48, 0, 0, 0));

        tableAndDatabase.setMaxHeight(Double.MAX_VALUE);
        VBox.setVgrow(databaseViewer, Priority.ALWAYS);
        GridPane.setColumnSpan(tableAndDatabase, 3);
        GridPane.setVgrow(tableAndDatabase, Priority.ALWAYS);
        mainContainer.add(tableAndDatabase, 0, 1);

        RowConstraints row1 = new RowConstraints();
        row1.setVgrow(Priority.NEVER);
        RowConstraints row2 = new RowConstraints();
        row2.setVgrow(Priority.ALWAYS);

        mainContainer.getRowConstraints().addAll(row1, row2);

        ColumnConstraints col1 = new ColumnConstraints();
        ColumnConstraints col2 = new ColumnConstraints();
        ColumnConstraints col3 = new ColumnConstraints();
        col1.setPercentWidth(33.33);
        col2.setPercentWidth(33.33);
        col3.setPercentWidth(33.33);

        mainContainer.getColumnConstraints().addAll(col1, col2, col3);

        // === Root layout ===
        VBox root = new VBox(5, header, mainContainer);
        root.setPadding(new Insets(0, 10, 10, 10));
        root.setStyle("-fx-background-color: #2b2b2b;");

        // === Button handlers ===
        startBtn.setOnAction(_ -> {
            String id = nodeIdField.getText();
            int port = Integer.parseInt(portField.getText());
            node = new P2PNode(id, port);
            node.start();

            node.getDataStore().setListener((tableName) -> {
                Platform.runLater(() -> {
                    if (tableName.equals("_system_online_nodes")) {
                        // Atualizar estado dos botões baseado nos online nodes
                        Map<String, Integer> onlineNodes = node.getOnlineNodes();
                        int onlineCount = onlineNodes.size();

                        boolean enableButtons = onlineCount >= 2;
                        setButtonState(localPutBtn, enableButtons);
                        setButtonState(localGetBtn, enableButtons);
                        setButtonState(searchBtn, enableButtons);

                        System.out
                                .println("[GUI] Online nodes: " + onlineCount + ", Buttons enabled: " + enableButtons);
                    } else {
                        refreshDatabaseView();
                    }
                });
            });

            updateStatus(true);

            startBtn.setDisable(true);
            startBtn.setOpacity(0.5);
            startBtn.setText("Running");
        });

        addTableBtn.setOnAction(_ -> {
            TextInputDialog dialog = new TextInputDialog();
            dialog.setTitle("Add Table");
            dialog.setHeaderText("Create New Table");
            dialog.setContentText("Table name:");

            dialog.showAndWait().ifPresent(tableName -> {
                if (tableName != null && !tableName.trim().isEmpty()) {
                    if (node != null) {
                        boolean created = node.createTable(tableName);
                        if (created) {
                            if (!tableComboBox.getItems().contains(tableName)) {
                                tableComboBox.getItems().add(tableName);
                            }
                            tableComboBox.setValue(tableName);
                            refreshDatabaseView();
                        } else {
                            Alert alert = new Alert(Alert.AlertType.WARNING);
                            alert.setTitle("Table Exists");
                            alert.setHeaderText("Table already exists");
                            alert.setContentText("Table '" + tableName + "' already exists.");
                            alert.showAndWait();
                        }
                    }
                }
            });
        });

        bootstrapBtn.setOnAction(_ -> {
            if (node == null) {
                return;
            }

            String peerId = bootstrapIdField.getText();
            String host = bootstrapHostField.getText();
            int port = Integer.parseInt(bootstrapPortField.getText());
            node.bootstrap(peerId, host, port);
        });

        blindBootstrapBtn.setOnAction(_ -> {
            if (node != null) {
                node.BlindBootstrap();
            }
        });

        localPutBtn.setOnAction(_ -> {
            if (localPutBtn.getCursor() != Cursor.HAND)
                return;
            if (node != null) {
                String tableName = localTableField.getText();
                String key = localKeyField.getText();
                String value = localValueField.getText();
                node.globalPut(tableName, key, value);
            }
        });

        localGetBtn.setOnAction(_ -> {
            if (localPutBtn.getCursor() != Cursor.HAND)
                return;
            if (node != null) {
                String tableName = localTableField.getText();
                String key = localKeyField.getText();
                String value = node.getDataStore().get(tableName, key);
                showGetResult(key, value);
            }
        });

        searchBtn.setOnAction(_ -> {
        	handleSearchAction(localKeyField.getText().trim());
        	resultLabel.setStyle("-fx-text-fill: #ffffffff; -fx-font-size: 16px; -fx-font-weight: bold;");
        });

        primaryStage.setOnCloseRequest(_ -> {
            if (node != null)
                node.shutdown();
            Platform.exit();
            System.exit(0);
        });

        Scene scene = new Scene(root, 600, 800);

        String darkTheme = """
                    .root {
                        -fx-background-color: #2b2b2b;
                    }
                    .card {
                        -fx-background-color: #3c3c3c;
                        -fx-background-radius: 8;
                        -fx-border-color: #555555;
                        -fx-border-radius: 8;
                        -fx-border-width: 1;
                        -fx-padding: 15;
                        -fx-effect: dropshadow(gaussian, rgba(0, 0, 0, 0.3), 10, 0.1, 0, 2);
                    }
                    .label {
                        -fx-text-fill: #e0e0e0;
                    }
                    .text-field, .text-area {
                        -fx-background-color: #2b2b2b;
                        -fx-background-radius: 6;
                        -fx-border-color: #555555;
                        -fx-border-radius: 6;
                        -fx-border-width: 1;
                        -fx-text-fill: #ffffff;
                        -fx-padding: 8 10;
                        -fx-font-size: 13px;
                    }
                    .text-area .content {
                        -fx-background-color: #1e1e1e;
                        -fx-background-radius: 4;
                    }
                    .text-field:focused, .text-area:focused {
                        -fx-border-color: #6200ee;
                    }
                    .button {
                        -fx-background-color: #6200ee;
                        -fx-background-radius: 6;
                        -fx-text-fill: white;
                        -fx-font-weight: bold;
                        -fx-font-size: 12px;
                        -fx-padding: 10 15;
                    }
                    .button:hover {
                        -fx-background-color: #7c3aed;
                    }
                    .button:pressed {
                        -fx-background-color: #4a1d9c;
                    }
                    .card-title {
                        -fx-font-size: 14px;
                        -fx-font-weight: bold;
                        -fx-text-fill: #ffffff;
                        -fx-padding: 0 0 10 0;
                        -fx-border-color: #555555;
                        -fx-border-width: 0 0 1 0;
                    }
                    .table-view {
                        -fx-background-color: #2b2b2b;
                        -fx-border-color: #555555;
                        -fx-border-radius: 6;
                    }
                    .table-view .column-header-background {
                        -fx-background-color: #6200ee;
                        -fx-background-radius: 6 6 0 0;
                    }
                    .table-view .column-header {
                        -fx-background-color: transparent;
                        -fx-text-fill: white;
                        -fx-font-weight: bold;
                        -fx-border-color: #e0e0e0;
                        -fx-border-width: 0 1 0 0;
                    }
                    .table-view .column-header:last-child {
                        -fx-border-width: 0;
                    }
                    .table-view .table-cell {
                        -fx-text-fill: #e0e0e0;
                        -fx-border-color: transparent;
                        -fx-border-width: 0;
                        -fx-padding: 8 10;
                    }
                    .table-view .table-cell:first-child {
                        -fx-border-color: transparent #e0e0e0 transparent transparent;
                        -fx-border-width: 0 1 0 0;
                    }
                    .table-row-cell {
                        -fx-background-color: #2b2b2b;
                    }
                    .table-row-cell:odd {
                        -fx-background-color: #252525;
                    }
                    .table-row-cell:selected {
                        -fx-background-color: #6200ee;
                    }
                    .table-view .scroll-bar:vertical {
                        -fx-background-color: #2b2b2b;
                    }
                    .table-view .scroll-bar:horizontal {
                        -fx-background-color: #2b2b2b;
                    }
                """;

        scene.getStylesheets().add("data:text/css," + darkTheme.replace("\n", "%0A"));
        primaryStage.setScene(scene);
        primaryStage.setTitle("DHT P2P Secure Network");
        primaryStage.getIcons().add(new Image(getClass().getResourceAsStream("/icon.png")));
        primaryStage.show();
    }

    private VBox createFormRow(String labelText, Control control) {
        Label label = new Label(labelText);
        label.setStyle("-fx-font-size: 12px; -fx-text-fill: #b0b0b0;");
        VBox row = new VBox(4, label, control);
        control.setMaxWidth(Double.MAX_VALUE);
        return row;
    }

    private VBox createCard(String title, javafx.scene.Node content) {
        Label titleLabel = new Label(title);
        titleLabel.getStyleClass().add("card-title");

        VBox card = new VBox(6, titleLabel, content);
        card.getStyleClass().add("card");
        card.setPadding(new Insets(5));

        return card;
    }

    private TableView<KeyValueEntry> createDatabaseTable() {
        TableView<KeyValueEntry> tableView = new TableView<>();

        TableColumn<KeyValueEntry, String> keyColumn = new TableColumn<>("KEY");
        keyColumn.setCellValueFactory(cellData -> cellData.getValue().keyProperty());
        keyColumn.setPrefWidth(200);

        TableColumn<KeyValueEntry, String> valueColumn = new TableColumn<>("VALUE");
        valueColumn.setCellValueFactory(cellData -> cellData.getValue().valueProperty());
        valueColumn.setPrefWidth(330);

        tableView.getColumns().add(keyColumn);
        tableView.getColumns().add(valueColumn);
        tableView.setItems(tableData);
        tableView.setPrefHeight(500);
        tableView.setPlaceholder(new Label("No data in database"));

        return tableView;
    }

    private void refreshDatabaseView() {
        if (node != null) {
            Platform.runLater(() -> {
                tableData.clear();
                DataStore dataStore = node.getDataStore();

                String selectedTable = tableComboBox.getValue();
                if (selectedTable == null) {
                    selectedTable = "global";
                }

                // Skip system tables in GUI
                if (selectedTable.equals("_system_online_nodes")) {
                    return;
                }

                Map<String, DataStore.VersionedValue> tableDataMap = dataStore.getAll(selectedTable);

                for (Map.Entry<String, DataStore.VersionedValue> entry : tableDataMap.entrySet()) {
                    String key = entry.getKey();
                    try {
                        String value = entry.getValue().getDecryptedValue();
                        tableData.add(new KeyValueEntry(key, value));
                    } catch (Exception e) {
                        System.err.println("[GUI] Failed to decrypt value for key " + key + ": " + e.getMessage());
                        tableData.add(new KeyValueEntry(key, "ERROR: Decryption failed"));
                    }
                }

                tableData.sort((a, b) -> a.getKey().compareTo(b.getKey()));
            });
        }
    }

    private void showGetResult(String key, String value) {
        Platform.runLater(() -> {
            if (value == null) {
                resultLabel.setText("No result");
                resultLabel.setStyle("-fx-text-fill: #ff6b6b; -fx-font-size: 16px; -fx-font-weight: bold;");
            } else {
                resultLabel.setText(value);
                resultLabel.setStyle("-fx-text-fill: #00d92fff; -fx-font-size: 16px; -fx-font-weight: bold;");
            }
        });
    }

    private void updateStatus(boolean isRunning) {
        Platform.runLater(() -> {
            if (isRunning) {
                statusIndicator.setFill(Color.LIMEGREEN);
                statusLabel.setText("Status: Running");
            } else {
                statusIndicator.setFill(Color.RED);
                statusLabel.setText("Status: Off");
            }
        });
    }

    public static class KeyValueEntry {
        private final String key;
        private final String value;

        public KeyValueEntry(String key, String value) {
            this.key = key;
            this.value = value;
        }

        public String getKey() {
            return key;
        }

        public String getValue() {
            return value;
        }

        public javafx.beans.property.SimpleStringProperty keyProperty() {
            return new javafx.beans.property.SimpleStringProperty(key);
        }

        public javafx.beans.property.SimpleStringProperty valueProperty() {
            return new javafx.beans.property.SimpleStringProperty(value);
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}