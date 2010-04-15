from PyQt4 import QtCore
from PyQt4 import QtGui
from . import CSRChoice
from . import CertainForm
from . import DEFAULT_CONFIG_FILE
import sys

class MainWindow(QtGui.QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = CertainForm.Ui_MainWindow()
        self.ui.setupUi(self)

        self._reset()

    def _reset(self):
        with open(DEFAULT_CONFIG_FILE) as f:
        self.ui.config.insertPlainText(f.read())
        self.ui.csrList.


def main():
    app = QtGui.QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec_())
