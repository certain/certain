from PyQt4 import QtCore
from PyQt4 import QtGui
from . import pending_csrs
from . import CertainForm
from . import DEFAULT_CONFIG_FILE
import sys


class MainWindow(QtGui.QMainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = CertainForm.Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.csrList.setColumnCount(2)
        self.ui.csrList.setHorizontalHeaderLabels(QtCore.QStringList(
            ['Common Name', 'Action']))

        self.connect(self.ui.resetButton,
                     QtCore.SIGNAL("clicked()"), self._reset)
        self._reset()

    def _reset(self):
        rowcount = 0
        colminwidth = 5
        self.ui.csrList.setColumnWidth(0, colminwidth)
        entries = ['a', 'b', 'long-named-cert']

        self.ui.csrList.setRowCount(len(entries))
        for entry in entries:
            actionlist = QtGui.QComboBox()
            actionlist.insertItems(0, ['', 'Sign', 'Delete'])
            if len(entry) * 10 > colminwidth:
                colminwidth = len(entry) * 10
                self.ui.csrList.setColumnWidth(0, colminwidth)
            self.ui.csrList.setCellWidget(
                entries.index(entry), 0, QtGui.QLabel(entry))
            self.ui.csrList.setCellWidget(
                entries.index(entry), 1, actionlist)
        for i, csr in enumerate(pending_csrs()):
            self.ui.csrList.setRowCount(i + 1)
            self.ui.csrList.setItem(i, 1, csr.CN)
        #with open(DEFAULT_CONFIG_FILE) as f:
        #    self.ui.config.insertPlainText(f.read())


def main():
    app = QtGui.QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec_())
