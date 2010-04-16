from PyQt4 import QtCore
from PyQt4 import QtGui
from . import pending_csrs
from . import CertainForm
from . import DEFAULT_CONFIG_FILE
import sys
import os

class MainWindow(QtGui.QMainWindow):

    class ActionList(QtGui.QComboBox):
        def __init__(self, *args, **kwargs):
            #super(MainWindow.ActionList, self).__init__(*args, **kwargs)
            QtGui.QComboBox.__init__(self)
            if len(args) > 0:
                self.obj = args[0]

        def act(self):
            if self.currentText() == 'Sign':
                self.obj.store()
            elif self.currentText() == 'Delete':
                self.obj.remove()


    class StoreList(QtGui.QCheckBox):
        def __init__(self, *args, **kwargs):
            #super(MainWindow.ActionList, self).__init__(*args, **kwargs)
            QtGui.QCheckBox.__init__(self)
            if len(args) > 0:
                self.filename = args[0]

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

        self._resetCerts()
        self._resetCSR()

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
        #with open(DEFAULT_CONFIG_FILE) as f:
            #self.ui.config.insertPlainText(f.read())

    def _resetCerts(self):
        rowcount = 0
        for file in os.listdir("/data/etc/store/"):
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
            
            

def main():
    app = QtGui.QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec_())
