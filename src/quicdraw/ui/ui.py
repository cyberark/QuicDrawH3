# QuicDrawUI is a UI for QuicDraw(H3)
# QuicDraw is a client for fuzzing and racing HTTP/3 servers.
# It can send GET and POST requests.
# It is designed to be used with and based on the aioquic(https://github.com/aiortc/aioquic) library.
# GitHub: https://github.com/cyberark/quicdrawh3
# License: Apache-2.0 License
# Author: Maor Abutbul <CyberArk Labs>

# Version and description
__version__ = "0.9.0"
__description__ = "QuicDraw-UI: HTTP/3 Request Editor - A GUI for QuicDraw(H3): HTTP/3 Fuzzing and Racing (Client)"

import argparse
import subprocess
import sys

from PySide6.QtCore import QSize, QThread, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


def ui_main() -> None:
    app = QApplication(sys.argv)
    cli_params = parse_command_line_arguments()
    ui_window = QuicDrawUI(cli_params)
    ui_window.show()
    sys.exit(app.exec())


class QuicDrawWorker(QThread):
    """Worker thread for running QuicDraw commands"""

    output_signal = Signal(str)
    error_signal = Signal(str)
    finished_signal = Signal(str)

    def __init__(self, command):
        super().__init__()
        self.command = command

    def run(self):
        try:
            result = subprocess.run(
                self.command, shell=True, capture_output=True, text=True
            )
            if result.stdout:
                self.output_signal.emit(result.stdout)
            if result.stderr:
                self.error_signal.emit(result.stderr)
        except Exception as e:
            self.error_signal.emit(f"Error: {str(e)}")
        finally:
            self.finished_signal.emit(self.command)


def escapeStringSubprocess(source_str: str) -> str:
    out = []
    for ch in source_str:
        ord(ch)
        # Backslash and single quote must be escaped.
        if ch == '"':
            out.append('\\"')
        # Other C0 control (0x00-0x1F) or DEL (0x7F)
        else:
            # For printable ASCII and most Unicode, keep as-is.
            # If you prefer to force-escape all non-ASCII, you could use:
            # - \x for <= 0xFF, \u for <= 0xFFFF, \U otherwise.
            # Here, we leave Unicode printable characters unescaped for readability.
            out.append(ch)
    return "".join(out)


def escapeStringBash(source_str: str) -> str:
    """
    Escape a Python string into a Bash ANSI-C quoted payload (inside $'...').
    Follows bash-style C escapes for control characters and uses \\xNN / \\uNNNN / \\U00NNNNNN
    where appropriate. Also escapes backslash and single quote.
    """
    out = []
    for ch in source_str:
        code = ord(ch)
        # Backslash and single quote must be escaped.
        if ch == '"':
            out.append('"')
        # Other C0 control (0x00-0x1F) or DEL (0x7F)
        elif 0x00 <= code <= 0x1F or code == 0x7F:
            out.append(f"\\x{code:02x}")
        # C1 controls (0x80-0x9F)
        elif 0x80 <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        else:
            # For printable ASCII and most Unicode, keep as-is.
            # If you prefer to force-escape all non-ASCII, you could use:
            # - \x for <= 0xFF, \u for <= 0xFFFF, \U otherwise.
            # Here, we leave Unicode printable characters unescaped for readability.
            out.append(ch)
    return "".join(out)


class QuicDrawUI(QMainWindow):
    def __init__(self, params_dict=None):
        super().__init__()
        self.worker = None
        self.init_ui(params_dict=params_dict)

    def init_ui(self, params_dict=None):
        self.setWindowTitle("QuicDrawH3 - HTTP/3 Fuzzing & Racing Tool")
        self.setGeometry(100, 100, 1200, 800)
        self.setWindowIcon(QIcon(":icons/qd_icon.ico"))

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Create tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Add tabs
        self.tabs.addTab(self.create_request_editor_tab(), "HTTP/3 Request Editor")
        self.tabs.addTab(self.create_advanced_tab(), "Advanced")
        self.tabs.addTab(self.create_results_tab(), "Results")

        # Status bar
        self.status_label = QLabel("Ready")
        self.statusBar().addWidget(self.status_label)

        # Populate parameters if provided
        if params_dict is not None:
            self.populate_params(params_dict)

    def populate_params(self, params_dict):
        if "url" in params_dict:
            self.url_input.setText(params_dict.get("url", [""])[0])
        # Populate headers
        headers = ""
        if "headers" in params_dict:
            headers = params_dict.get("headers", [])
            headers = "\n".join([item for sublist in headers for item in sublist])
        if "cookie" in params_dict:
            cookie = params_dict.get("cookie", [""])[0]
            headers += "\ncookie: {0}".format(cookie)
        self.headers_input.setText(headers)
        if "data" in params_dict:
            self.data_input.setText(params_dict.get("data", ""))
        if "wordlist" in params_dict:
            self.wordlist_check.setChecked(True)
            self.wordlist_input.setText(params_dict.get("wordlist", ""))
        if "total_requests" in params_dict:
            self.total_requests_check.setChecked(True)
            self.total_requests.setValue(int(params_dict.get("total_requests", 12)))
        if "secrets_log" in params_dict:
            self.secrets_check.setChecked(True)
            self.secrets_log.setText(params_dict.get("secrets_log", ""))
        if "verbose" in params_dict:
            (
                self.verbose_check.setChecked(True)
                if int(params_dict.get("verbose", 0)) > 0
                else False
            )

    def create_request_editor_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # URL Input
        url_group = QGroupBox("Target URL")
        url_layout = QVBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://cyberark.com/path")
        url_layout.addWidget(self.url_input)
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)

        # Headers
        headers_group = QGroupBox("Custom Headers")
        headers_layout = QVBoxLayout()
        self.headers_input = QTextEdit()
        self.headers_input.setPlaceholderText("Add headers (one per line)")
        headers_layout.addWidget(self.headers_input)
        headers_group.setLayout(headers_layout)
        headers_group.setMaximumHeight(250)
        layout.addWidget(headers_group)

        # Request Data
        data_group = QGroupBox("Request Configuration")
        data_layout = QVBoxLayout()

        self.data_label = QLabel("Data:")
        self.data_input = QTextEdit()
        self.data_input.setPlaceholderText('{"key":"value"}')
        data_layout.addWidget(self.data_label)
        data_layout.addWidget(self.data_input)
        data_group.setLayout(data_layout)
        data_group.setMaximumHeight(300)
        layout.addWidget(data_group)

        # Wordlist Configuration
        wordlist_group = QGroupBox("Fuzzing Configuration")
        wordlist_layout = QFormLayout()

        wordlist_layout.addRow(QLabel("Wordlist File:"))
        self.wordlist_check = QCheckBox("Wordlist (-w)")
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("wordlist.txt")
        wordlist_layout.addRow(self.wordlist_check, self.wordlist_input)

        wordlist_group.setLayout(wordlist_layout)
        layout.addWidget(wordlist_group)

        # Race Configuration
        race_group = QGroupBox("Race Configuration")
        race_layout = QFormLayout()

        race_layout.addRow(QLabel("Total Requests:"))
        self.total_requests_check = QCheckBox("Repeat Request (-tr)")
        self.total_requests = QSpinBox()
        self.total_requests.setRange(1, 1000)
        self.total_requests.setValue(12)
        race_layout.addRow(self.total_requests_check, self.total_requests)

        race_group.setLayout(race_layout)
        layout.addWidget(race_group)

        # Run Button
        button_layout = QHBoxLayout()
        self.send_btn = QPushButton("Run QuicDraw")
        self.send_btn.setIcon(QIcon(":icons/qd_icon.ico"))
        self.send_btn.setIconSize(QSize(24, 24))
        self.send_btn.clicked.connect(self.do_send_request)
        button_layout.addWidget(self.send_btn)
        layout.addLayout(button_layout)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_advanced_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # Command Preview
        preview_group = QGroupBox("Command Preview (bash)")
        preview_layout = QVBoxLayout()
        self.command_preview = QTextEdit()
        self.command_preview.setReadOnly(True)
        preview_layout.addWidget(self.command_preview)
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        # Logging
        logging_group = QGroupBox("Logging Options")
        logging_layout = QFormLayout()

        self.verbose_check = QCheckBox("Verbose Output (-v)")
        logging_layout.addRow(self.verbose_check)

        logging_layout.addRow(QLabel("TLS Secrets Log File:"))
        self.secrets_log = QLineEdit()
        self.secrets_check = QCheckBox("Log TLS Secrets (-l)")
        self.secrets_log.setPlaceholderText("secrets.log")
        logging_layout.addRow(self.secrets_check, self.secrets_log)

        logging_group.setLayout(logging_layout)
        layout.addWidget(logging_group)

        # buttons
        # Update preview button
        buttons_advanced_layout = QFormLayout()

        self.update_preview_btn = QPushButton("Update Preview")
        self.update_preview_btn.clicked.connect(self.do_update_preview)
        # Run Button
        self.send_btn = QPushButton("Run QuicDraw")
        self.send_btn.setIcon(QIcon(":icons/qd_icon.ico"))
        self.send_btn.clicked.connect(self.do_send_request)
        buttons_advanced_layout.addRow(self.update_preview_btn, self.send_btn)
        layout.addLayout(buttons_advanced_layout)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_results_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        # Buttons
        button_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Output")
        self.clear_btn.clicked.connect(lambda: self.output_text.clear())
        # self.save_btn = QPushButton("Save Results")
        # self.save_btn.clicked.connect(self.save_results)
        button_layout.addWidget(self.clear_btn)
        # button_layout.addWidget(self.save_btn)
        layout.addLayout(button_layout)

        widget.setLayout(layout)
        return widget

    def do_send_request(self):
        cmd = self.do_collect_and_build_command()
        self.update_command_preview(self.do_collect_and_build_command(bash_escape=True))
        self.run_command(cmd)

    def do_update_preview(self):
        cmd_preview = self.do_collect_and_build_command(bash_escape=True)
        self.update_command_preview(cmd_preview)

    def do_collect_and_build_command(self, bash_escape=False):
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a URL")
            return
        data_plain = self.data_input.toPlainText()
        data = data_plain
        headers = self.headers_input.toPlainText().strip()
        total_requests = (
            self.total_requests.value() if self.total_requests_check.isChecked() else 0
        )
        wordlist = (
            self.wordlist_input.text().strip()
            if self.wordlist_check.isChecked()
            else ""
        )
        vebose = self.verbose_check.isChecked()
        secrets_log = (
            self.secrets_log.text().strip() if self.secrets_check.isChecked() else ""
        )

        cmd = self.do_build_command(
            url,
            data,
            headers,
            total_requests,
            wordlist,
            secrets_log,
            vebose,
            bash_escape,
        )
        print(cmd)
        return cmd

    def do_build_command(
        self,
        url,
        data="",
        headers="",
        total_requests=0,
        wordlist="",
        secrets_log="",
        vebose=False,
        bash_escape=False,
    ):
        cmd = f"quicdraw {url}"
        if secrets_log:
            cmd += f' -l "{secrets_log}"'
        if headers:
            for header in headers.split("\n"):
                if header:
                    cmd += f' -H "{header}"'
        if data:
            if bash_escape:
                cmd += f" --data-raw $'{escapeStringBash(data)}'"
            else:
                cmd += f' --data-raw "{escapeStringSubprocess(data)}"'
        if wordlist:
            cmd += f' -w "{wordlist}"'
        if total_requests > 0:
            cmd += f" -tr {total_requests}"
        if vebose:
            cmd += " -v"
        return cmd

    def update_command_preview(self, cmd):
        self.command_preview.setText(cmd)

    def run_command(self, cmd):
        self.tabs.setCurrentIndex(2)  # Switch to Results tab
        self.output_text.append(f"Executing: {cmd}\n" + "=" * 60 + "\n")
        self.status_label.setText("Running...")

        self.worker = QuicDrawWorker(cmd)
        self.worker.output_signal.connect(self.append_output)
        self.worker.error_signal.connect(self.append_error)
        self.worker.finished_signal.connect(self.on_command_finished)
        self.worker.start()

    def append_output(self, text):
        self.output_text.append(text)

    def append_error(self, text):
        self.output_text.append(f"(Log): {text}")

    def on_command_finished(self):  # , finished_command):
        self.status_label.setText("Ready")
        self.output_text.append("\n" + "=" * 60 + "\nExecution Finished.\n" + "=" * 60)
        # todo commandline


logo = rf"""
    -----------
    {__description__}
    -----------
               _         _
              (_)       | |                            __  ______
    __ _ _   _ _  ___ __| |_ __ __ ___      __        / / / /  _/
   / _` | | | | |/ __/ _` | '__/ _` \ \ /\ / / _____ / / / // /
  | (_| | |_| | | (_| (_| | | | (_| |\ V  V / /____// /_/ // /
   \__, |\__,_|_|\___\__,_|_|  \__,_| \_/\_/        \____/___/
      |_|    _______
         \  |QFS____| -------------------- HTTP/3
          \ |_//
            |_|

    GitHub: https://github.com/cyberark/QuicDrawH3/QuicDraw-UI
    License: Apache-2.0 License
    Author: Maor Abutbul <CyberArk Labs>
    QuicDraw-UI Version: {__version__}
    -----------
"""


def print_logo():
    print(logo)


class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        # Add the logo at the top of the help message
        print_logo()
        return super().add_usage(
            prefix=("Usage: \n"), usage=usage, actions=actions, groups=groups
        )


def parse_command_line_arguments():

    parser = argparse.ArgumentParser(
        formatter_class=CustomHelpFormatter, epilog="Version: " + __version__
    )
    parser.add_argument(
        "url",
        type=str,
        help="the URL to query (must be HTTPS)",
        nargs="+",  # we do not support multiple URLs in this version
    )
    parser.add_argument(
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        type=str,
        help="send the specified data in a POST request",
    )
    parser.add_argument(
        "-H",
        "--header",
        type=str,
        action="append",
        nargs="+",
        help="add the following header to each request, can be used more then once. e.g. -H 'X-Header: header_value'",
    )
    parser.add_argument(
        "-b",
        "--cookie",
        type=str,
        action="append",
        help="add the following cookie to each request -b 'cookie_value'",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        type=str,
        help="use the specified wordlist to generate data for POST requests,"
        "e.g. -w wordlist.txt. The wordlist should contain one word per line.",
    )
    parser.add_argument(
        "-tr",
        "--total-requests",
        type=int,
        help="Number of requests to send, the a provided wordlist overrides this argument, will use the number of words (lines) in the wordlist file (default: 1)",
        default=0,
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        help="increase logging verbosity -vv=debug",
        default=0,
    )

    args = parser.parse_args()

    arg_dict = dict()
    if args.url:
        arg_dict["url"] = args.url
    if args.data:
        arg_dict["data"] = args.data

    # Handle headers and cookies
    if args.header:
        arg_dict["headers"] = args.header

    if args.cookie:
        arg_dict["cookie"] = args.cookie
    if args.wordlist:
        arg_dict["wordlist"] = args.wordlist
    if args.total_requests:
        arg_dict["total_requests"] = args.total_requests
    if args.secrets_log:
        arg_dict["secrets_log"] = args.secrets_log
    if args.verbose:
        arg_dict["verbose"] = args.verbose

    return arg_dict


if __name__ == "__main__":
    try:
        ui_main()
    except KeyboardInterrupt:
        print("\nQuicDraw interrupted by user.")
    except Exception as e:
        print(
            "An error occurred: {0} : {1}".format(
                e.__class__.__name__ if e.__class__ is not None else "",
                str(e),
            )
        )
        exit(1)
