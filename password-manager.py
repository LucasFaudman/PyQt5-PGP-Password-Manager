import sys
from unittest import TestCase
from PyQt5 import QtCore as qtc
from PyQt5 import QtSql as qsql
from PyQt5 import QtWidgets as qtw
from PyQt5 import QtGui as qtg
#from PyQt5.sip import T

from gnupg import GPG
from datetime import datetime
from functools import partial
from managerUI import Ui_MainWindow

from checkableComboBox import CheckableComboBox

USER_DB_INIT_SQL = """
CREATE TABLE IF NOT EXISTS categories (
	category_id INTEGER PRIMARY KEY ASC,
	category_name TEXT
);

CREATE TABLE IF NOT EXISTS services (
	service_id INTEGER PRIMARY KEY ASC,
    service_category_id INTEGER,
    service_name TEXT,
    service_description TEXT
);

CREATE TABLE IF NOT EXISTS logins (
	login_id INTEGER PRIMARY KEY ASC,
    login_category_id INTEGER,
    login_data TEXT
);

CREATE TABLE IF NOT EXISTS entries (
    service_id INTEGER,
    login_id INTEGER,
    timestamp INTEGER,
    password_data TEXT,
    password_recovery_data TEXT,
    PRIMARY KEY(service_id,login_id,timestamp)
);
"""



CATSERVS = {
    "Email": {
        "Gmail" : "Google Email",
        "Protonmail" : "Secure Email Based in Switzerland",
        "Outlook" : "Shitty Email by Microsoft"
        },
    
    "Banking & Credit Cards": {
        "Bofa" : "Bank of America",
        "Wells Fargo" : "Wells Fargo Banking Online",
        "BBVA" : "BBVA formerly Simple Bank",
        "OpenSky": "OpenSky Credit Card",
        "EDD" : "CA UI Online",
        },

    "Crypto Wallets": {
        "Ledger" : "Ledger Hardware Wallet",
        "Metamask" : "Metamask Ethereum Interface",
        "Monero" : "Monero Wallets",
        "SiaCoin": "SiaCoin Wallets",
        },

    "Exchanges & CeFi": {
        "Coinbase" : "Coinbase Pro",
        "BlockFi" : "BlockFi CeFi",
        "Celcius" : "Celciu Cefi",
        "Nexo" : "Nexo Cefi"
        },

    "Ecommerce": {
        "Amazon" : "Amazon Marketplace & Prime Streaming",
        "Ebay" : "Ebay",
        "StockX" : "After Market Luxury Goods",
        },

    "Social Media": {
        "Facebook" : "Facebook",
        "Instagram" : "Ig",
        "SnapChat" : "Sc",
        },

    "Tech & Software": {
        "Apple" : "Apple Id",
        "Express VPN" : "VPN",
        "Tesla" : "EV",
        },

}


DEFAULT_CATEGORIES="""
INSERT INTO categories
VALUES (1, "Email", "Email Accounts"),
VALUES (1, "Email", "Email Accounts"),
"""

class MainWindow(qtw.QMainWindow, Ui_MainWindow):

    def __init__(self, TESTS=[]):
        """MainWindow constructor.

        This widget will be our main window.
        We'll define all the UI components in here.
        """
        super(qtw.QMainWindow, self).__init__()
        self.setupUi(self)

        # Connect actions to slots
        self.actionSet_Key.triggered.connect(self.onSetKey)
        self.actionSet_Db.triggered.connect(self.onSetDb)
        self.actionCreate_New_Db.triggered.connect(self.onCreateNewDb)
        self.actionAdd_Db_Defaults.triggered.connect(self.onAddDbDefaults)
        self.actionAdd_Category.triggered.connect(self.onAddCategory)
        self.actionAdd_Service.triggered.connect(self.onAddService)
        self.actionAdd_Login.triggered.connect(self.onAddLogin)
        self.actionAdd_Entry.triggered.connect(self.onAddEntry)
        self.actionUpdate_Search_Filters_View.triggered.connect(self.onUpdateSearchFiltersView)
        # init GPG object
        self.gpg = GPG()

        #init dict for table models
        self.comboBoxTables = CheckableComboBox()
        self.comboBoxTables.dataChanged.connect(self.updateDbView)
        self.scrollArea = qtw.QScrollArea()

        self.table_models = {}
        self.table_views = {}
        self.table_grid = qtw.QGridLayout()
        self.scrollArea.setLayout(self.table_grid)
        self.gridLayout_2.addWidget(self.comboBoxTables, 5, 0, 1, 2)
        self.gridLayout_2.addWidget(self.scrollArea, 6, 0, 1, 2)

        self.search_filters = {}
        self.search_query_TableView = None
   

        self.show()
        self.onSetKey()
        self.onSetDb()
        

    def _encrypt(self, data):
        return str(self.gpg.encrypt(data,recipients=[self.key_fp]))

    def _decrypt(self, data):
        crypt =self.gpg.decrypt(data)
        dec_data =str(crypt.data)
        print(dec_data)
        return dec_data
    @qtc.pyqtSlot()
    def onSetKey(self):
        # Key name FP pairs as generator of strings
        key_options = (
            key['uids'][0] + f" FP: {key['fingerprint']}" for key in self.gpg.list_keys())

        # Open input dialog
        item, ok = qtw.QInputDialog.getItem(self,
                                            "Select PGP Key",
                                            "PGP Keys",
                                            key_options,
                                            0,
                                            False)
        if ok:
            self.key_fp = item.split()[-1]
            self.labelPGP.setText(f"PGP KEY:\n{item}")

    @qtc.pyqtSlot()
    def onCreateNewDb(self):
        db_name, ok = qtw.QInputDialog.getText(
            self, "Enter New Db Name", "Db Name", )
        if ok:
            db_dir = qtw.QFileDialog.getExistingDirectory(
                self, "Select Folder for Db")

            if db_name and db_dir:
                db_path = db_dir + "/" + db_name
                self._connectDb(db_path, db_name)
                self.db.exec()

    @qtc.pyqtSlot()
    def onSetDb(self):
        # Open File Dialog
        db_path, file_mode = qtw.QFileDialog.getOpenFileName(self,
                                                             "Select Db File",
                                                             filter="Database files (*.sqlite *.db)")
        if db_path:
            db_name = db_path.split("/")[-1]
            self._connectDb(db_path, db_name)

    @ qtc.pyqtSlot(str, str)
    def _connectDb(self, db_path, db_name):
        self.db_path=db_path
        self.db_name=db_name

        self.labelDbPath.setText(f"DATABASE {db_name} PATH:\n{db_path}")

        # init db object
        self.db_default_connection_name=f"default_sqlite_connection"
        self.db=qsql.QSqlDatabase.addDatabase(
            "QSQLITE", self.db_default_connection_name)
        self.db.setDatabaseName(db_name)

        # Try to open db show error message on fail
        if not self.db.open():
            error=self.db.lastError().text()
            qtw.QMessageBox.critical(
                None, 'DB Connection Error',
                'Could not open database file: '
                f'{error}')
            sys.exit(1)

        self.updateDbView()


    @qtc.pyqtSlot()
    def updateDbView(self):
        tables = self.db.tables()
        
        for table_num, table_name in enumerate(tables):
            model = self.table_models.get(table_name)
            if not model:
                model = qsql.QSqlTableModel(db=self.db)
                model.setTable(table_name)
                model.setEditStrategy(qsql.QSqlTableModel.OnFieldChange)
                self.table_models[table_name] = model

                view = qtw.QTableView()
                view.setModel(model)
                self.table_views[table_name] = view
                
                self.comboBoxTables.addItem(table_name, userData=view)
                self.table_grid.addWidget(view, table_num, 0)


            model.select()

            unchecked_views = list(self.table_views.values())
            for checked_view in self.comboBoxTables.currentData():
                checked_view.show()
                unchecked_views.remove(checked_view)
            
            for unchecked_view in unchecked_views:
                unchecked_view.hide()
            
        self.scrollArea.show()

    @qtc.pyqtSlot()
    def onAddDbDefaults(self):
        
        for create_sql in USER_DB_INIT_SQL.split(";"):
            print(self.db.exec(create_sql))

        for category, services in CATSERVS.items():
            query = qsql.QSqlQuery(self.db) 
            query.prepare("INSERT INTO categories (category_name) VALUES (?)")
            query.addBindValue(category)
            query.exec()
            
            category_id = query.lastInsertId()
            query.prepare(f"INSERT INTO services (service_category_id, service_name, service_description) VALUES (?,?,?)")
            query.addBindValue([category_id for _ in services])
            query.addBindValue(list(services.keys()))
            query.addBindValue(list(services.values()))
            if not query.execBatch():
                print(query.lastError().text())

        self.updateDbView()

    @qtc.pyqtSlot()
    def onAddCategory(self):
        category_name, ok = qtw.QInputDialog.getText(
            self, "Enter New Category Name", "Category Name", )
        if ok and category_name:
            query = qsql.QSqlQuery(self.db) 
            query.prepare("INSERT INTO categories (category_name) VALUES (?)")
            query.addBindValue(category_name)
            query.exec()    
        self.updateDbView()
        
    def get_comboBox(self,table_tag, checkable=False, checked=False):
        combo_dict = {}

        query = qsql.QSqlQuery(self.db)

        table_name = "categories"  if table_tag == "category" else table_tag + "s" 
        value_col = f"{table_tag}_data" if table_tag == "login" else f"{table_tag}_name" 
        query.exec(f"SELECT {table_tag}_id, {value_col} FROM {table_name}") 
        
        while(query.next()):
            combo_dict[query.value(1)] = query.value(0)
        
        print(combo_dict)
        
        if checkable:
            comboBox = CheckableComboBox()
            comboBox.addItems(texts=combo_dict.keys(), datalist=list(combo_dict.values()), checked=checked) 
        else:
            comboBox = qtw.QComboBox()
            for text, text_id in combo_dict.items():
                comboBox.addItem(text, userData=text_id)

        return comboBox
       
    @qtc.pyqtSlot()
    def onAddService(self):
        form_dialog = qtw.QDialog(self)
        form_layout = qtw.QFormLayout(form_dialog)

        category_comboBox = self.get_comboBox("category")
        form_layout.addRow("Service Category", category_comboBox)

        service_name_lineEdit = qtw.QLineEdit()
        form_layout.addRow("Service Name", service_name_lineEdit)

        service_description_lineEdit = qtw.QLineEdit()
        form_layout.addRow("Service Description", service_description_lineEdit)

        buttonBox = qtw.QDialogButtonBox(qtw.QDialogButtonBox.Ok)
        buttonBox.addButton(qtw.QDialogButtonBox.Cancel)
        buttonBox.accepted.connect(form_dialog.accept)
        buttonBox.rejected.connect(form_dialog.reject)
        form_layout.addRow(buttonBox)
        
        if form_dialog.exec():
            category_id = category_comboBox.currentData()
            service_name = service_name_lineEdit.text()
            service_description = service_description_lineEdit.text()
            
            print(category_id)
            print(service_name)
            print(service_description)

            query = qsql.QSqlQuery(self.db) 
            query.prepare(f"INSERT INTO services (service_category_id, service_name, service_description) VALUES (?,?,?)")
            query.addBindValue(category_id)
            query.addBindValue(service_name)
            query.addBindValue(service_description)
            
            if not query.exec():
                print(query.lastError().text())

        self.updateDbView()

    @qtc.pyqtSlot()
    def onAddLogin(self):
        form_dialog = qtw.QDialog(self)
        form_layout = qtw.QFormLayout(form_dialog)

        category_comboBox = self.get_comboBox("category")
        form_layout.addRow("Login/Username Category", category_comboBox)

        login_lineEdit = qtw.QLineEdit()
        form_layout.addRow("Login/Username", login_lineEdit)

        buttonBox = qtw.QDialogButtonBox(qtw.QDialogButtonBox.Ok)
        buttonBox.addButton(qtw.QDialogButtonBox.Cancel)
        buttonBox.accepted.connect(form_dialog.accept)
        buttonBox.rejected.connect(form_dialog.reject)
        form_layout.addRow(buttonBox)
        
        if form_dialog.exec():
            category_id = category_comboBox.currentData()
        
            login_data = login_lineEdit.text()
            # Encrypt_Here   

            print(category_id)
            print(login_data)
    

            query = qsql.QSqlQuery(self.db) 
            query.prepare(f"INSERT INTO logins (login_category_id, login_data) VALUES (?,?)")
            query.addBindValue(category_id)
            query.addBindValue(login_data)
            
            if not query.exec():
                print(query.lastError().text())

        self.updateDbView() 


    @qtc.pyqtSlot()
    def onAddEntry(self):
        form_dialog = qtw.QDialog(self)
        form_layout = qtw.QFormLayout(form_dialog)

        service_comboBox = self.get_comboBox("service")
        form_layout.addRow("Service", service_comboBox)
        
        login_comboBox = self.get_comboBox("login")
        form_layout.addRow("Login/Username", login_comboBox)

        password_data_lineEdit = qtw.QLineEdit()
        form_layout.addRow("Password", password_data_lineEdit)

        password_recovery_data_textEdit = qtw.QPlainTextEdit()
        form_layout.addRow("Recovery", password_recovery_data_textEdit)

        buttonBox = qtw.QDialogButtonBox(qtw.QDialogButtonBox.Ok)
        buttonBox.addButton(qtw.QDialogButtonBox.Cancel)
        buttonBox.accepted.connect(form_dialog.accept)
        buttonBox.rejected.connect(form_dialog.reject)
        form_layout.addRow(buttonBox)
        
        if form_dialog.exec():
            service_id = service_comboBox.currentData()
            login_id = login_comboBox.currentData()

            timestamp = int(datetime.now().timestamp())
            password_data = self._encrypt(password_data_lineEdit.text())
            password_recovery_data = self._encrypt(password_recovery_data_textEdit.toPlainText())
            
            query = qsql.QSqlQuery(self.db) 
            query.prepare(f"INSERT INTO entries (service_id, login_id, timestamp, password_data, password_recovery_data) VALUES (?,?,?,?,?)")
            query.addBindValue(service_id)
            query.addBindValue(login_id)
            query.addBindValue(timestamp)
            query.addBindValue(str(password_data))
            query.addBindValue(str(password_recovery_data))

            print(service_id, login_id)
            print(timestamp, str(datetime.fromtimestamp(timestamp)))
            print(password_data)
            print(password_recovery_data)


            if not query.exec():
                print(query.lastError().text())

        self.updateDbView()

    @qtc.pyqtSlot()
    def onUpdateSearchFiltersView(self):
        #Clear Form Prevent duplicates
        #while self.search_form.rowCount() > 0:
        #    self.search_form.removeRow(0)
        
        if self.search_query_TableView:
            self.gridLayout_3.removeWidget(self.search_query_TableView)
            
        #
        self.category_CheckableComboBox = self.get_comboBox("category", checkable=True, checked=True)
        self.category_CheckableComboBox.dataChanged.connect(self.onUpdateSearchTableView)
        self.categoriesPushButton.clicked.connect(self.onAddCategory)
        self.gridLayout_3.addWidget(self.category_CheckableComboBox, 1, 2, 1, 1)
        #self.search_form.addRow("Categories", self.category_CheckableComboBox)
        
        self.service_CheckableComboBox = self.get_comboBox("service", checkable=True, checked=True)
        self.service_CheckableComboBox.dataChanged.connect(self.onUpdateSearchTableView)
        self.servicesPushButton.clicked.connect(self.onAddService)
        self.gridLayout_3.addWidget(self.service_CheckableComboBox, 1, 5, 1, 1)
        #self.search_form.addRow("Services", self.service_CheckableComboBox)
        
        self.login_CheckableComboBox = self.get_comboBox("login", checkable=True, checked=True)
        self.login_CheckableComboBox.dataChanged.connect(self.onUpdateSearchTableView)
        self.loginsPushButton.clicked.connect(self.onAddLogin)
        self.gridLayout_3.addWidget(self.login_CheckableComboBox, 1, 7, 1, 1)
        #self.search_form.addRow("Logins", self.login_CheckableComboBox)


        self.search_query_TableView = qtw.QTableView()

        #Handle DoubleClicks
        self.search_query_TableView.setSelectionMode(qtw.QAbstractItemView.SingleSelection)
        self.search_query_TableView.setSelectionBehavior(qtw.QAbstractItemView.SelectRows)  
        self.search_query_TableView.doubleClicked.connect(self.onQueryItemDoubleClicked)
        
        #Handle Sorting From Headers
        self.search_query_TableView.horizontalHeader().setSortIndicator(0, qtc.Qt.DescendingOrder)
        self.search_query_TableView.setSortingEnabled(True)
        self.search_query_TableView.horizontalHeader().sortIndicatorChanged.connect(
            self.onUpdateSearchTableView
        )

        #self.search_form.addWidget(self.search_query_TableView)
        self.gridLayout_3.addWidget(self.search_query_TableView, 2,1,2,9)
        self.onUpdateSearchTableView()


    @qtc.pyqtSlot()
    def onUpdateSearchTableView(self):
        columns = [ "categories.category_name",
        	        "services.service_name",
        	        "logins.login_data",
        	        "entries.password_data",
        	        "entries.password_recovery_data",
        	        "entries.timestamp"]
        sql_query_string = f"""
        SELECT
        	categories.category_name,
        	services.service_name,
        	logins.login_data,
        	entries.password_data,
        	entries.password_recovery_data,
        	entries.timestamp
        FROM 
        	entries 
        JOIN 
            logins ON logins.login_id = entries.login_id
        JOIN 
            services ON services.service_id  = entries.service_id
        JOIN 
            categories ON categories.category_id = services.service_category_id
        WHERE 
            logins.login_id IN ({','.join(str(i) for i in self.login_CheckableComboBox.currentData())})
        AND 
            services.service_id IN ({','.join(str(i) for i in self.service_CheckableComboBox.currentData())})
        AND 
            categories.category_id IN ({','.join(str(i) for i in self.category_CheckableComboBox.currentData())})
        ORDER BY 
            {columns[self.search_query_TableView.horizontalHeader().sortIndicatorSection()]} 
            {'ASC' if self.search_query_TableView.horizontalHeader().sortIndicatorOrder() else 'DESC'}
        """

        print(sql_query_string)
        query_model = qsql.QSqlQueryModel()
        query_model.setQuery(sql_query_string, db=self.db)
        
        self.search_query_TableView.setModel(query_model)
        #query_model.select()

        
    @qtc.pyqtSlot(qtc.QModelIndex)
    def onQueryItemDoubleClicked(self, index):
        data= { column_name: index.siblingAtColumn(i).data()
                for i, column_name in enumerate((
                    "category_name" ,
        	        "service_name" ,
        	        "login_data" ,
                    "password_data" ,
    	            "password_recovery_data" ,
    	            "timestamp"))
                }
        
        form_dialog = qtw.QDialog(self)
        form_layout = qtw.QFormLayout(form_dialog)
        
        for k,v in data.items():
            val_label = qtw.QLabel()
            val_label.setTextInteractionFlags(qtc.Qt.TextSelectableByMouse)
            
            if k == "timestamp":
                val_label.setText(str(datetime.fromtimestamp(v)))
            else:
                val_label.setText(str(v))
            form_layout.addRow(k, val_label)

            if k.startswith("password"):
                decrypt_button = qtw.QPushButton(text=f"Decrypt {k}")
                decrypt_button.clicked.connect(partial(self.onDecryptItem,label=val_label, data=v))
                #self.onDecryptItem(val_label, v))    
                form_layout.addRow(decrypt_button)

            
        
        
        form_dialog.show()
        print(data)
    
    @qtc.pyqtSlot(str,str)
    def onDecryptItem(self, label, data):
        label.setText(self._decrypt(data))




if __name__ == '__main__':
    app=qtw.QApplication(sys.argv)
    # it's required to save a reference to MainWindow.
    # if it goes out of scope, it will be destroyed.
    mw=MainWindow()
    sys.exit(app.exec())
