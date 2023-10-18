from idaapi import PluginForm
from funcs_keeper import fk
from idaif import get_instruction_by_ea
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QSplitter

# class ClickableGroupBox(QtWidgets.QGroupBox):
#     def __init__(self, title):
#         super().__init__(title)
#     def mousePressEvent(self, event):
#         print("event.button: ", event.button())
#     def mouseDoubleClickEvent(self, event):
#         self.hide()
#         print("event.button: ", event.button())


class FunkbusterForm(PluginForm):
    def __init__(self):
        super().__init__()
        self.results = []
        self.prev_results = []
        self.on_analyze_clicked = None
        self.on_result_item_clicked = None
        self.on_result_item_doubleclicked = None
        self.on_info_xref_from_item_doubleclicked = None
        self.on_info_xref_to_item_doubleclicked = None
        self.on_potentional_vmt_calls_item_doubleclicked = None
        self.info = {}

    def OnCreate(self, form) -> None:
        self.parent = self.FormToPyQtWidget(form)
        self.init_ui()

    def OnClose(self, form) -> None:
        # TODO: Implement later.
        pass

    def init_ui(self) -> None:
        self.layout = QtWidgets.QGridLayout(self.parent)
        filters_groupbox = self._create_filters_groupbox()
        self.results_groupbox = self._create_results_groupbox()
        info_groupbox = self._create_info_groupbox()

        splitter = QSplitter(QtCore.Qt.Horizontal)
        splitter.addWidget(filters_groupbox)
        splitter.addWidget(self.results_groupbox)
        splitter.addWidget(info_groupbox)
        self.layout.addWidget(splitter)

    def _create_filters_groupbox(self) -> QtWidgets.QGroupBox:
        filters_groupbox = QtWidgets.QGroupBox("Filters")
        filters_groupbox.setLayout(QtWidgets.QVBoxLayout())

        splitter = QSplitter(QtCore.Qt.Vertical)
        filters_configure_groupbox = self._create_filters_configure_groupbox()
        splitter.addWidget(filters_configure_groupbox)
        # Create signatures filter groupbox and add it to filters groupbox
        filter_signatures_groupbox = self._create_filter_signatures_groupbox()
        splitter.addWidget(filter_signatures_groupbox)
        # Create xrefs filter groupbox and add it to filters groupbox
        filter_xrefs_groupbox = self._create_filter_xrefs_groupbox()
        splitter.addWidget(filter_xrefs_groupbox)
        # Create flows filter groupbox and add it to filters groupbox
        filter_flows_groupbox = self._create_filter_flow_groupbox()
        splitter.addWidget(filter_flows_groupbox)
        # Create Analyze groupbox and add it to filters groupbox
        analyze_groupbox = self._create_analyze_groupbox()
        splitter.addWidget(analyze_groupbox)
        filters_groupbox.layout().addWidget(splitter)
        # Set Filters Visible Sections not y-resizeable
        filters_configure_groupbox.setMaximumHeight(
            filters_configure_groupbox.sizeHint().height())
        return filters_groupbox

    def _create_filters_configure_groupbox(self) -> QtWidgets.QGroupBox:
        filters_configure_groupbox = QtWidgets.QGroupBox("Visible Sections")
        filters_configure_groupbox.setLayout(QtWidgets.QHBoxLayout())
        filters_configure_layout = QtWidgets.QHBoxLayout()
        self.filters_dispaly_signatures_checkbox = QtWidgets.QCheckBox(
            "Signatures")
        self.filters_dispaly_signatures_checkbox.setChecked(True)
        filters_configure_layout.addWidget(
            self.filters_dispaly_signatures_checkbox)
        self.filters_display_xrefs_from_checkbox = QtWidgets.QCheckBox("Xrefs")
        self.filters_display_xrefs_from_checkbox.setChecked(True)
        filters_configure_layout.addWidget(
            self.filters_display_xrefs_from_checkbox)
        self.filters_display_flows_checkbox = QtWidgets.QCheckBox("Flows")
        self.filters_display_flows_checkbox.setChecked(True)
        filters_configure_layout.addWidget(self.filters_display_flows_checkbox)
        filters_configure_groupbox.layout().addLayout(filters_configure_layout)
        return filters_configure_groupbox

    def _create_filter_signatures_groupbox(self) -> QtWidgets.QGroupBox:
        # Create and configure groupbox
        filter_signatures_groupbox = QtWidgets.QGroupBox("Signatures")
        filter_signatures_groupbox.setLayout(QtWidgets.QVBoxLayout())
        # Populate groupbox with tree
        self.signatures_tree = QtWidgets.QTreeWidget()
        self.signatures_tree.setColumnCount(3)
        self.signatures_tree.setHeaderLabels(
            ['Signature Bytes', 'Inverted', 'Enabled'])
        filter_signatures_groupbox.layout().addWidget(self.signatures_tree)
        # Populate groupbox with button
        add_signature_button = QtWidgets.QPushButton("Add Signature")
        add_signature_button.clicked.connect(self._add_signature_filter)
        filter_signatures_groupbox.layout().addWidget(add_signature_button)
        # Align tree columns
        self.signatures_tree.header().setStretchLastSection(False)
        self.signatures_tree.header().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch)
        self.signatures_tree.header().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeToContents)
        self.signatures_tree.header().setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeToContents)

        self.signatures_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.signatures_tree.customContextMenuRequested.connect(
            lambda event: self._setup_context_menu(self.signatures_tree, event))
        self.filters_dispaly_signatures_checkbox.stateChanged.connect(
            lambda: self._on_widget_visible_state_toggled(filter_signatures_groupbox))
        return filter_signatures_groupbox

    def _add_signature_filter(self):
        signature_item = QtWidgets.QTreeWidgetItem(self.signatures_tree)
        signature_item.setText(0, "")
        signature_item.setFlags(signature_item.flags()
                                | QtCore.Qt.ItemIsEditable)
        signature_item.setCheckState(1, QtCore.Qt.Unchecked)
        signature_item.setCheckState(2, QtCore.Qt.Checked)

    def _create_filter_xrefs_groupbox(self) -> QtWidgets.QGroupBox:
        # Create and configure groupbox
        filter_xrefs_groupbox = QtWidgets.QGroupBox("Xrefs")
        filter_xrefs_groupbox.setLayout(QtWidgets.QVBoxLayout())
        # Populate groupbox with tree
        self.xrefs_tree = QtWidgets.QTreeWidget()
        self.xrefs_tree.setColumnCount(3)
        self.xrefs_tree.setHeaderLabels(
            ['Address/Name', 'Direction', 'Call', 'Read', 'Write', 'Access', 'Inverted', 'Enabled'])
        filter_xrefs_groupbox.layout().addWidget(self.xrefs_tree)
        # Populate groupbox with button
        add_xref_button = QtWidgets.QPushButton("Add Xref")
        add_xref_button.clicked.connect(self._add_xref_filter)
        filter_xrefs_groupbox.layout().addWidget(add_xref_button)
        # Align tree columns
        self.xrefs_tree.header().setStretchLastSection(False)
        self.xrefs_tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        for i in range(1, 8):
            self.xrefs_tree.header().setSectionResizeMode(
                i, QtWidgets.QHeaderView.ResizeToContents)

        self.xrefs_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.xrefs_tree.customContextMenuRequested.connect(
            lambda event: self._setup_context_menu(self.xrefs_tree, event))

        self.filters_display_xrefs_from_checkbox.stateChanged.connect(
            lambda: self._on_widget_visible_state_toggled(filter_xrefs_groupbox))
        return filter_xrefs_groupbox

    def _add_xref_filter(self):
        xref_item = QtWidgets.QTreeWidgetItem(self.xrefs_tree)
        xref_item.setText(0, "")
        combo = QtWidgets.QComboBox()
        combo.addItem('To')
        combo.addItem('From')
        combo.addItem('Bidirectional')
        xref_item.treeWidget().setItemWidget(xref_item, 1, combo)
        xref_item.setFlags(xref_item.flags() | QtCore.Qt.ItemIsEditable)
        for i in range(2, 9):
            xref_item.setCheckState(i, QtCore.Qt.Checked)
        xref_item.setFlags(xref_item.flags() | QtCore.Qt.ItemIsUserCheckable)
        xref_item.setCheckState(6, QtCore.Qt.Unchecked)  # Uncheck inverted

    def _setup_context_menu(self, tree_widget, event):
        item = tree_widget.itemAt(event)
        if item:
            context_menu = QtWidgets.QMenu()
            delete_action = context_menu.addAction("Delete")
            action = context_menu.exec_(tree_widget.mapToGlobal(event))
            if action == delete_action:
                tree_widget.invisibleRootItem().removeChild(item)

    def _create_filter_flow_groupbox(self) -> QtWidgets.QGroupBox:
        # Create and configure groupbox
        filter_flow_groupbox = QtWidgets.QGroupBox("Flows")
        filter_flow_groupbox.setLayout(QtWidgets.QVBoxLayout())
        # Populate groupbox with tree
        self.flows_tree = QtWidgets.QTreeWidget()
        self.flows_tree.setColumnCount(3)
        self.flows_tree.setHeaderLabels(
            ['Address/Name', 'Direction', 'Depth', 'Inverted', 'Enabled'])
        filter_flow_groupbox.layout().addWidget(self.flows_tree)
        # Populate groupbox with button
        add_flow_button = QtWidgets.QPushButton("Add Flow")
        add_flow_button.clicked.connect(self._add_flow_filter)
        filter_flow_groupbox.layout().addWidget(add_flow_button)
        # Align tree columns
        self.flows_tree.header().setStretchLastSection(False)
        self.flows_tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        self.flows_tree.header().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeToContents)
        self.flows_tree.header().setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeToContents)
        self.flows_tree.header().setSectionResizeMode(
            3, QtWidgets.QHeaderView.ResizeToContents)
        self.flows_tree.header().setSectionResizeMode(
            4, QtWidgets.QHeaderView.ResizeToContents)

        self.flows_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.flows_tree.customContextMenuRequested.connect(
            lambda event: self._setup_context_menu(self.flows_tree, event))

        self.filters_display_flows_checkbox.stateChanged.connect(
            lambda: self._on_widget_visible_state_toggled(filter_flow_groupbox))
        return filter_flow_groupbox

    def _add_flow_filter(self):
        flow_item = QtWidgets.QTreeWidgetItem(self.flows_tree)
        flow_item.setText(0, "")
        flow_item.setFlags(flow_item.flags() | QtCore.Qt.ItemIsEditable)
        combo = QtWidgets.QComboBox()
        combo.addItem('To')
        combo.addItem('From')
        flow_item.treeWidget().setItemWidget(flow_item, 1, combo)
        flow_item.setText(2, "3")
        flow_item.setCheckState(3, QtCore.Qt.Unchecked)
        flow_item.setCheckState(4, QtCore.Qt.Checked)
        # signature_item.setCheckState(7, QtCore.Qt.Unchecked) # Uncheck inverted

    def _create_analyze_groupbox(self) -> QtWidgets.QGroupBox:
        analyze_groupbox = QtWidgets.QGroupBox("Analyze")
        analyze_groupbox.setLayout(QtWidgets.QGridLayout())
        analyze_button = QtWidgets.QPushButton("Analyze")
        analyze_groupbox.layout().addWidget(analyze_button, 0, 0)
        analyze_only_current_checkbox = QtWidgets.QCheckBox(
            "Analyze Only Current Results")
        analyze_groupbox.layout().addWidget(analyze_only_current_checkbox, 0, 1)
        analyze_button.clicked.connect(
            lambda: self.on_analyze_clicked(
                analyze_only_current_checkbox.isChecked())
            if self.on_analyze_clicked else None)
        return analyze_groupbox

    def _create_results_groupbox(self) -> QtWidgets.QGroupBox:
        results_groupbox = QtWidgets.QGroupBox("Results: 0")
        results_groupbox.setLayout(QtWidgets.QVBoxLayout())
        results_groupbox.setMinimumWidth(300)
        self.results_tree = QtWidgets.QTreeWidget()
        self.results_tree.setColumnCount(2)
        self.results_tree.setHeaderLabels(['Address', 'Name'])
        undo_previous_analysis_button = QtWidgets.QPushButton(
            "Undo Previous Analysis")
        undo_previous_analysis_button.clicked.connect(
            self._on_undo_previous_analysis)
        results_groupbox.layout().addWidget(self.results_tree)
        results_groupbox.layout().addWidget(undo_previous_analysis_button)
        self.results_tree.itemClicked.connect(
            lambda item: self.on_result_item_clicked(int(item.text(0), 16)))
        self.results_tree.itemDoubleClicked.connect(
            lambda item: self.on_result_item_doubleclicked(int(item.text(0), 16)))
        return results_groupbox

    def _create_info_groupbox(self) -> QtWidgets.QGroupBox:
        info_groupbox = QtWidgets.QGroupBox("Info")
        info_groupbox.setLayout(QtWidgets.QVBoxLayout())
        splitter = QSplitter(QtCore.Qt.Vertical)
        info_configure_groupbox = self._create_info_configure_groupbox()
        splitter.addWidget(info_configure_groupbox)
        info_general_groupbox = self._create_info_general_groupbox()
        splitter.addWidget(info_general_groupbox)
        info_xrefs_from_groupbox = self._create_info_xrefs_from_groupbox()
        splitter.addWidget(info_xrefs_from_groupbox)
        info_xrefs_to_groupbox = self._create_info_xrefs_to_groupbox()
        splitter.addWidget(info_xrefs_to_groupbox)
        info_vmt_calls_groupbox = self._create_info_vmt_calls_groupbox()
        splitter.addWidget(info_vmt_calls_groupbox)
        info_groupbox.layout().addWidget(splitter)

        info_configure_groupbox.setMaximumHeight(
            info_configure_groupbox.sizeHint().height())
        info_general_groupbox.setMaximumHeight(
            info_general_groupbox.sizeHint().height())

        return info_groupbox

    def _create_info_configure_groupbox(self) -> QtWidgets.QGroupBox:
        info_configure_groupbox = QtWidgets.QGroupBox("Visible Sections")
        info_configure_groupbox.setLayout(QtWidgets.QHBoxLayout())
        info_configure_layout = QtWidgets.QHBoxLayout()
        self.info_dispaly_general_checkbox = QtWidgets.QCheckBox("General")
        self.info_dispaly_general_checkbox.setChecked(True)
        info_configure_layout.addWidget(self.info_dispaly_general_checkbox)
        self.info_xrefs_from_checkbox = QtWidgets.QCheckBox("Xrefs From")
        self.info_xrefs_from_checkbox.setChecked(True)
        info_configure_layout.addWidget(self.info_xrefs_from_checkbox)
        self.info_xrefs_to_checkbox = QtWidgets.QCheckBox("Xrefs To")
        self.info_xrefs_to_checkbox.setChecked(True)
        info_configure_layout.addWidget(self.info_xrefs_to_checkbox)
        self.info_vmt_calls_checkbox = QtWidgets.QCheckBox(
            "Potential VMT Calls")
        self.info_vmt_calls_checkbox.setChecked(True)
        info_configure_layout.addWidget(self.info_vmt_calls_checkbox)
        info_configure_groupbox.layout().addLayout(info_configure_layout)
        return info_configure_groupbox

    def _create_info_general_groupbox(self) -> QtWidgets.QGroupBox:
        general_info_groupbox = QtWidgets.QGroupBox("General")
        general_info_groupbox.setLayout(QtWidgets.QVBoxLayout())

        name_area = QtWidgets.QHBoxLayout()
        name_area.addWidget(QtWidgets.QLabel("Name:"))
        self.info_name = QtWidgets.QLabel()
        name_area.addWidget(self.info_name)
        general_info_groupbox.layout().addLayout(name_area)

        address_area = QtWidgets.QHBoxLayout()
        address_area.addWidget(QtWidgets.QLabel("Address:"))
        self.info_address = QtWidgets.QLabel()
        address_area.addWidget(self.info_address)
        general_info_groupbox.layout().addLayout(address_area)

        size_area = QtWidgets.QHBoxLayout()
        size_area.addWidget(QtWidgets.QLabel("Size:"))
        self.info_size = QtWidgets.QLabel()
        size_area.addWidget(self.info_size)
        general_info_groupbox.layout().addLayout(size_area)

        self.info_dispaly_general_checkbox.stateChanged.connect(
            lambda: self._on_widget_visible_state_toggled(general_info_groupbox))
        return general_info_groupbox

    def _create_info_xrefs_from_groupbox(self) -> QtWidgets.QGroupBox:
        # xrefs_from_groupbox = ClickableGroupBox("Xrefs From")
        xrefs_from_groupbox = QtWidgets.QGroupBox("Xrefs From")

        xrefs_from_groupbox.setLayout(QtWidgets.QVBoxLayout())
        xrefs_from_checkbox_layout = QtWidgets.QHBoxLayout()

        # Create horizontal line with 4 checkboxes
        xrefs_from_checkbox_layout.addWidget(QtWidgets.QLabel("Filter:"))
        self.info_xrefs_from_calls_checkbox = QtWidgets.QCheckBox("Call")
        self.info_xrefs_from_calls_checkbox.setChecked(True)
        xrefs_from_checkbox_layout.addWidget(
            self.info_xrefs_from_calls_checkbox)
        self.info_xrefs_from_reads_checkbox = QtWidgets.QCheckBox("Read")
        self.info_xrefs_from_reads_checkbox.setChecked(True)
        xrefs_from_checkbox_layout.addWidget(
            self.info_xrefs_from_reads_checkbox)
        self.info_xrefs_from_writes_checkbox = QtWidgets.QCheckBox("Write")
        self.info_xrefs_from_writes_checkbox.setChecked(True)
        xrefs_from_checkbox_layout.addWidget(
            self.info_xrefs_from_writes_checkbox)
        self.info_xrefs_from_offsets_checkbox = QtWidgets.QCheckBox("Offset")
        self.info_xrefs_from_offsets_checkbox.setChecked(True)
        xrefs_from_checkbox_layout.addWidget(
            self.info_xrefs_from_offsets_checkbox)
        xrefs_from_groupbox.layout().addLayout(xrefs_from_checkbox_layout)

        # Set up callback for checkboxes
        self.info_xrefs_from_calls_checkbox.stateChanged.connect(
            lambda: self._on_info_xrefs_from_filter_changed())
        self.info_xrefs_from_reads_checkbox.stateChanged.connect(
            lambda: self._on_info_xrefs_from_filter_changed())
        self.info_xrefs_from_writes_checkbox.stateChanged.connect(
            lambda: self._on_info_xrefs_from_filter_changed())
        self.info_xrefs_from_offsets_checkbox.stateChanged.connect(
            lambda: self._on_info_xrefs_from_filter_changed())

        # Create xrefs from tree
        self.info_xrefs_from_tree = QtWidgets.QTreeWidget()
        self.info_xrefs_from_tree.setColumnCount(5)
        self.info_xrefs_from_tree.setHeaderLabels(
            ['Offset', 'Address', 'Instruction', 'Name', 'Type'])
        xrefs_from_groupbox.layout().addWidget(self.info_xrefs_from_tree)
        self.info_xrefs_from_tree.itemDoubleClicked.connect(
            lambda item, column: self.on_info_xref_from_item_doubleclicked(item.text(column), column))
        self.info_xrefs_from_checkbox.stateChanged.connect(
            lambda: self._on_widget_visible_state_toggled(xrefs_from_groupbox))
        return xrefs_from_groupbox

    def _create_info_xrefs_to_groupbox(self) -> QtWidgets.QGroupBox:
        xrefs_to_groupbox = QtWidgets.QGroupBox("Xrefs To")
        xrefs_to_groupbox.setLayout(QtWidgets.QVBoxLayout())
        xrefs_to_checkbox_layout = QtWidgets.QHBoxLayout()

        # Create horizontal line with 4 checkboxes
        xrefs_to_checkbox_layout.addWidget(QtWidgets.QLabel("Filter:"))
        self.info_xrefs_to_calls_checkbox = QtWidgets.QCheckBox("Call")
        self.info_xrefs_to_calls_checkbox.setChecked(True)
        xrefs_to_checkbox_layout.addWidget(self.info_xrefs_to_calls_checkbox)
        self.info_xrefs_to_reads_checkbox = QtWidgets.QCheckBox("Read")
        self.info_xrefs_to_reads_checkbox.setChecked(True)
        xrefs_to_checkbox_layout.addWidget(self.info_xrefs_to_reads_checkbox)
        self.info_xrefs_to_writes_checkbox = QtWidgets.QCheckBox("Write")
        self.info_xrefs_to_writes_checkbox.setChecked(True)
        xrefs_to_checkbox_layout.addWidget(self.info_xrefs_to_writes_checkbox)
        self.info_xrefs_to_offsets_checkbox = QtWidgets.QCheckBox("Offset")
        self.info_xrefs_to_offsets_checkbox.setChecked(True)
        xrefs_to_checkbox_layout.addWidget(self.info_xrefs_to_offsets_checkbox)
        xrefs_to_groupbox.layout().addLayout(xrefs_to_checkbox_layout)

        # Set up callback for checkboxes
        self.info_xrefs_to_calls_checkbox.stateChanged.connect(
            lambda: self._on_info_xrefs_to_filter_changed())
        self.info_xrefs_to_reads_checkbox.stateChanged.connect(
            lambda: self._on_info_xrefs_to_filter_changed())
        self.info_xrefs_to_writes_checkbox.stateChanged.connect(
            lambda: self._on_info_xrefs_to_filter_changed())
        self.info_xrefs_to_offsets_checkbox.stateChanged.connect(
            lambda: self._on_info_xrefs_to_filter_changed())

        # Create xrefs to tree
        self.info_xrefs_to_tree = QtWidgets.QTreeWidget()
        self.info_xrefs_to_tree.setColumnCount(5)
        self.info_xrefs_to_tree.setHeaderLabels(
            ['Caller', 'Offset', 'Address', 'Instruction', 'Name', 'Type'])
        xrefs_to_groupbox.layout().addWidget(self.info_xrefs_to_tree)
        self.info_xrefs_to_tree.itemDoubleClicked.connect(
            lambda item, column: self.on_info_xref_to_item_doubleclicked(item.text(column), column))

        self.info_xrefs_to_checkbox.stateChanged.connect(
            lambda: self._on_widget_visible_state_toggled(xrefs_to_groupbox))
        return xrefs_to_groupbox

    def _create_info_vmt_calls_groupbox(self) -> QtWidgets.QGroupBox:
        vmt_calls_groupbox = QtWidgets.QGroupBox("Potential VMT Calls")
        vmt_calls_groupbox.setLayout(QtWidgets.QVBoxLayout())
        vmt_calls_checkbox_layout = QtWidgets.QHBoxLayout()

        # Create vmt calls tree
        self.info_vmt_calls_tree = QtWidgets.QTreeWidget()
        self.info_vmt_calls_tree.setColumnCount(2)
        self.info_vmt_calls_tree.setHeaderLabels(
            ['Offset', 'VMT Offset', 'Instruction'])
        vmt_calls_groupbox.layout().addWidget(self.info_vmt_calls_tree)
        self.info_vmt_calls_tree.itemDoubleClicked.connect(
            lambda item, column: self.on_potentional_vmt_calls_item_doubleclicked(item.text(column), column))
        self.info_vmt_calls_checkbox.stateChanged.connect(
            lambda: self._on_widget_visible_state_toggled(vmt_calls_groupbox))
        return vmt_calls_groupbox

    def _on_undo_previous_analysis(self) -> None:
        self.set_results(self.prev_results)

    def _on_info_xrefs_from_filter_changed(self) -> None:
        # Update xrefs from tree
        self.set_info(self.info)

    def _on_info_xrefs_to_filter_changed(self) -> None:
        # Update xrefs to tree
        self.set_info(self.info)

    def _on_widget_visible_state_toggled(self, widget) -> None:
        if (widget.isVisible()):
            widget.hide()
        else:
            widget.show()

    # API

    def set_on_analyze_clicked(self, callback) -> None:
        self.on_analyze_clicked = callback

    def set_on_result_item_clicked(self, callback) -> None:
        self.on_result_item_clicked = callback

    def set_on_result_item_doublelicked(self, callback) -> None:
        self.on_result_item_doubleclicked = callback

    def set_on_info_xrefs_from_item_doubleclicked(self, callback) -> None:
        self.on_info_xref_from_item_doubleclicked = callback

    def set_on_info_xrefs_to_item_doubleclicked(self, callback) -> None:
        self.on_info_xref_to_item_doubleclicked = callback

    def set_on_info_potentional_vmt_calls_item_doubleclicked(self, callback) -> None:
        self.on_potentional_vmt_calls_item_doubleclicked = callback

    def get_results(self) -> list[int]:
        results_list = []
        for idx in range(self.results_tree.topLevelItemCount()):
            result_item = self.results_tree.topLevelItem(idx)
            results_list.append(int(result_item.text(0), 16))
        return results_list

    def set_results(self, results_list: list[int, str]) -> None:
        # Update results
        self.prev_results = self.results
        self.results = results_list
        self.results_tree.clear()
        for function_info in results_list:
            result_item = QtWidgets.QTreeWidgetItem(self.results_tree)
            result_item.setText(0, hex(function_info[0]))
            result_item.setText(1, function_info[1])
        self.results_groupbox.setTitle("Results: %d" % len(results_list))

    def get_info(self) -> dict:
        return self.info

    def set_info(self, function_info: dict) -> None:
        # Update info
        self.info = function_info

        # Fill general information
        self.info_name.setText(function_info["name"])
        self.info_address.setText(hex(function_info["address"]))
        self.info_size.setText(hex(function_info["size"]))

        # Build single xrefs-from list
        xrefs_from = []
        if self.info_xrefs_from_calls_checkbox.isChecked():
            for call_from in function_info["calls_from"]:
                call_from["type"] = "call"
                xrefs_from.append(call_from)
        if self.info_xrefs_from_reads_checkbox.isChecked():
            for read_from in function_info["reads_from"]:
                read_from["type"] = "read"
                xrefs_from.append(read_from)
        if self.info_xrefs_from_writes_checkbox.isChecked():
            for write_from in function_info["writes_from"]:
                write_from["type"] = "write"
                xrefs_from.append(write_from)
        if self.info_xrefs_from_offsets_checkbox.isChecked():
            for offset_from in function_info["offsets_from"]:
                offset_from["type"] = "offset"
                xrefs_from.append(offset_from)

        # Sort it by "from_ea"
        xrefs_from.sort(key=lambda x: x["from_ea"])

        # Clear previous tree
        self.info_xrefs_from_tree.clear()

        # Add to tree
        for xref_from in xrefs_from:
            item = QtWidgets.QTreeWidgetItem(self.info_xrefs_from_tree)
            item.setText(
                0, hex(xref_from["from_ea"] - function_info["address"]))
            item.setText(1, hex(xref_from["to_ea"]))
            item.setText(2, get_instruction_by_ea(xref_from["from_ea"]))
            item.setText(3, fk.get_function_name(xref_from["to_ea"]))
            item.setText(4, xref_from["type"])

        # Adjust columns width
        for i in range(self.info_xrefs_from_tree.columnCount()):
            self.info_xrefs_from_tree.resizeColumnToContents(i)

        # Build single xrefs-to list
        xrefs_to = []
        if self.info_xrefs_to_calls_checkbox.isChecked():
            for call_to in function_info["calls_to"]:
                call_to["type"] = "call"
                xrefs_to.append(call_to)
        # if self.info_xrefs_to_reads_checkbox.isChecked():
        #     for read_to in function_info["reads_to"]:
        #         read_to["type"] = "read"
        #         xrefs_to.append(read_to)
        # if self.info_xrefs_to_writes_checkbox.isChecked():
        #     for write_to in function_info["writes_to"]:
        #         write_to["type"] = "write"
        #         xrefs_to.append(write_to)
        if self.info_xrefs_to_offsets_checkbox.isChecked():
            for offset_to in function_info["offsets_to"]:
                offset_to["type"] = "offset"
                xrefs_to.append(offset_to)

        # Sort it by "to_ea"
        xrefs_to.sort(key=lambda x: x["to_ea"])

        # Clear previous tree
        self.info_xrefs_to_tree.clear()

        # Add to tree
        for xref_to in xrefs_to:
            item = QtWidgets.QTreeWidgetItem(self.info_xrefs_to_tree)
            item.setText(0, hex(xref_to["from_func_ea"]))
            item.setText(1, hex(xref_to["from_ea"] - xref_to["from_func_ea"]))
            item.setText(2, hex(xref_to["from_ea"]))
            item.setText(3, get_instruction_by_ea(xref_to["from_ea"]))
            item.setText(4, fk.get_function_name(xref_to["from_ea"]))
            item.setText(5, xref_to["type"])

        # Adjust columns width
        for i in range(self.info_xrefs_to_tree.columnCount()):
            self.info_xrefs_to_tree.resizeColumnToContents(i)

        # Clear previous vmt calls tree
        self.info_vmt_calls_tree.clear()

        # Add to tree
        for vmt_call in function_info["vmt_calls"]:
            item = QtWidgets.QTreeWidgetItem(self.info_vmt_calls_tree)
            item.setText(0, hex(vmt_call["call_ea"]))
            item.setText(1, hex(vmt_call["vmt_offset"]))
            item.setText(2, get_instruction_by_ea(vmt_call["call_ea"]))

    def get_filters_configuration(self):
        filters_configuration = []
        # Process signatures filters
        for i in range(self.signatures_tree.topLevelItemCount()):
            item = self.signatures_tree.topLevelItem(i)
            data = item.text(0).strip()
            if item.checkState(2) == QtCore.Qt.Checked and data:
                filter_configuration = {
                    "type": "signature",
                    "invert": item.checkState(1) == QtCore.Qt.Checked,
                    "data": data
                }
                filters_configuration.append(filter_configuration)

        # Process xrefs filters
        for i in range(self.xrefs_tree.topLevelItemCount()):
            item = self.xrefs_tree.topLevelItem(i)
            data = item.text(0).strip()
            if item.checkState(7) == QtCore.Qt.Checked and data:
                combo = item.treeWidget().itemWidget(item, 1)
                filter_configuration = {
                    "type": "xrefs",
                    "to": combo.currentText().strip() == "To" or combo.currentText().strip() == "Bidirectional",
                    "from": combo.currentText().strip() == "From" or combo.currentText().strip() == "Bidirectional",
                    "call": item.checkState(2) == QtCore.Qt.Checked,
                    "read": item.checkState(3) == QtCore.Qt.Checked,
                    "write": item.checkState(4) == QtCore.Qt.Checked,
                    "access": item.checkState(5) == QtCore.Qt.Checked,
                    "invert": item.checkState(6) == QtCore.Qt.Checked,
                }
                try:
                    filter_configuration["data"] = int(data, 16)
                    filter_configuration["data_type"] = "ea"
                except:
                    filter_configuration["data_type"] = "name"
                    filter_configuration["data"] = data
                filters_configuration.append(filter_configuration)

        # Process flow filters
        for i in range(self.flows_tree.topLevelItemCount()):
            item = self.flows_tree.topLevelItem(i)
            data = item.text(0).strip()
            if item.checkState(4) == QtCore.Qt.Checked and data:
                combo = item.treeWidget().itemWidget(item, 1)
                filter_configuration = {
                    "type": "flow",
                    "to": combo.currentText().strip() == "To",
                    "from": combo.currentText().strip() == "From",
                    "depth": int(item.text(2)),
                    "invert": item.checkState(3) == QtCore.Qt.Checked,
                }
                try:
                    filter_configuration["data"] = int(data, 16)
                    filter_configuration["data_type"] = "ea"
                except:
                    filter_configuration["data_type"] = "name"
                    filter_configuration["data"] = data
                filters_configuration.append(filter_configuration)

        return filters_configuration
