from PyQt4 import QtCore
from PyQt4 import QtGui
from . import pending_csrs
from . import CertainForm
from . import DEFAULT_CONFIG_FILE
from . import parse_config
from . import config
import ConfigParser
import sys
import os


class MainWindow(QtGui.QMainWindow):

    class ActionList(QtGui.QComboBox):

        def __init__(self, obj):
            QtGui.QComboBox.__init__(self)
            self.obj = obj

        def act(self):
            if self.currentText() == 'Sign':
                self.obj.store()
            elif self.currentText() == 'Delete':
                self.obj.remove()

    class StoreList(QtGui.QCheckBox):

        def __init__(self, filename):
            QtGui.QCheckBox.__init__(self)
            self.filename = filename

        def act(self):
            if self.checkState():
                print "Deleting " + self.filename

    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = CertainForm.Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.csrList.setColumnCount(2)
        self.ui.certs.setColumnCount(2)
        self.ui.certs.setHorizontalHeaderLabels(QtCore.QStringList(
            ['Common Name', 'Delete?']))
        self.ui.csrList.setHorizontalHeaderLabels(QtCore.QStringList(
            ['Common Name', 'Action']))

        self.connect(self.ui.csrReset, QtCore.SIGNAL("clicked()"),
            self._resetCSR)

        self.connect(self.ui.certsReset, QtCore.SIGNAL("clicked()"),
            self._resetCerts)

        self.connect(self.ui.action_Open, QtCore.SIGNAL("activated()"),
            self._loadDialog)

        self.connect(self.ui.action_Fetch, QtCore.SIGNAL("activated()"),
            self._fetch)

        self.connect(self.ui.action_Make_certs, QtCore.SIGNAL("activated()"),
            self._makecerts)

        self.configFile = DEFAULT_CONFIG_FILE
        try:
            global config
            config = parse_config()
        except ConfigParser.Error, e:
            QtGui.QMessageBox.warning(self,
                self.windowTitle() + " - Missing config file",
                "Could not load default configuration file, "
                "please load one from the menu:\n\n" + str(e))
        except Exception, e:
            QtGui.QMessageBox.critical(self,
                self.windowTitle() + " - Error loading config",
                "There was an error while loading the config file. "
                "This usually indicates incorrect permissions or missing "
                "directories. Try to fix this error:\n\n" + str(e))
        else:
            self._reset()

    def _reset(self):
        self._resetCerts()
        self._resetCSR()
        self._resetConfig()

    def _resetCSR(self):
        for i, csr in enumerate(pending_csrs()):
            self.ui.csrList.setRowCount(i + 1)
            self.ui.csrList.setCellWidget(i, 0,
                QtGui.QLabel(csr.csr.get_subject().CN))

            actionlist = self.ActionList(csr)
            actionlist.insertItems(0, ['Ignore', 'Sign', 'Delete'])
            self.connect(self.ui.csrApply, QtCore.SIGNAL("clicked()"),
                actionlist.act)
            self.ui.csrList.setCellWidget(i, 1, actionlist)
            self.ui.csrList.resizeColumnToContents(0)
            self.ui.csrList.resizeColumnToContents(1)

    def _resetCerts(self):
        rowcount = 0
        for file in os.listdir(config.get('global', 'StoreDir')):
            self.ui.certs.setRowCount(rowcount + 1)
            self.ui.certs.setCellWidget(rowcount, 0,
                QtGui.QLabel(file))
            storelist = self.StoreList("data/store/file" + file)
            self.connect(self.ui.certsApply, QtCore.SIGNAL("clicked()"),
                storelist.act)
            self.ui.certs.setCellWidget(rowcount, 1, storelist)
            self.ui.certs.resizeColumnToContents(0)
            self.ui.certs.resizeColumnToContents(1)
            rowcount = rowcount + 1

    def _resetConfig(self):
        with open(self.configFile) as f:
            self.ui.config.insertPlainText(f.read())

    def _loadDialog(self):
        filename = QtGui.QFileDialog.getOpenFileName(self, "Open File",
            "", "Configuration files (*.cfg);;All files (*.*)")
        if filename:
            self.configFile = str(filename)
            try:
                global config
                config = parse_config(self.configFile)
            except ConfigParser.Error, e:
                QtGui.QMessageBox.warning(self,
                    self.windowTitle() + " - Missing config file",
                    "Could not load configuration file: " +
                    self.configFile + "\n\n" + str(e))
            except Exception, e:
                QtGui.QMessageBox.critical(self,
                    self.windowTitle() + " - Error loading config",
                    "There was an error while loading the config file. "
                    "This usually indicates incorrect permissions or missing "
                    "directories. Try to fix this error:\n\n" + str(e))
            else:
                self._reset()

    def _fetch(self):
        pass

    def _makecerts(self):
        pass

def main():
    app = QtGui.QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec_())
