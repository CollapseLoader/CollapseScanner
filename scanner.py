import ctypes
import os
import re
from ctypes import wintypes
from zipfile import ZipFile

from pyvis.network import Network
from rich.console import Console
from rich.progress import Progress, TaskID
from webview import Window, create_window, start
from webview.platforms.winforms import BrowserView

from database import good_links

console = Console()

class Scanner:
    def __init__(self, file: str, progress_bar: Progress, task_id: TaskID) -> None:
        self.file = file.replace('file:///', '')  # remove protocol
        self.progress_bar = progress_bar
        self.task_id = task_id
        self.options = {}
        self.links = []
        self.good_links = good_links
        self.linux = os.name == 'posix'

    def log(self, msg: str) -> None:
        self.progress_bar.print(msg, highlight=False)

    def info(self, msg: str) -> None:
        self.progress_bar.print(f'[cyan]{msg}[/]')

    def report(self) -> str:
        options_view = '\n'.join(f'{str(key).title().replace('_', ' ')}: {"Yes" if value else "No"}' for key, value in self.options.items())
        
        return f'''
Links: {len(self.links)} 
{options_view}
'''

    def scan(self) -> str:
        self.log(f'Scanning: {self.file}...')

        if not self.file.endswith('.jar'):
            self.info('File is not a jar executable!')
            return ''
        
        with ZipFile(self.file, 'r') as zip:
            self._process_manifest(zip)
            self._process_files(zip)

        return self.report()

    def _process_manifest(self, zip: ZipFile) -> None:
        try:
            manifest = zip.read('META-INF/MANIFEST.MF').decode()
            if 'Main-Class' in manifest:
                main_class_info = manifest[manifest.find('Main-Class:'):manifest.find('\nDev:')]
                self.log(main_class_info)
        except Exception as e:
            self.log(f"Error processing manifest: {e}")

    def _process_files(self, zip: ZipFile) -> None:
        index = 0
        
        for file in zip.filelist:
            filename = file.filename.lower()
            index += 1
            
            if 'net/minecraft' in filename and not self.options.get('minecraft'):
                self.options['minecraft'] = True

            if 'fabric.mod.json' in filename:
                self.options['fabric'] = True

            if 'mods.toml' in filename:
                self.options['forge'] = True

            if any(keyword in filename for keyword in ['rpc']) and not self.options.get('discord_RPC'):
                self.options['discord_RPC'] = True

            if file.filename.endswith('.class'):
                self._process_class_file(zip, file.filename)

    def _process_class_file(self, zip: ZipFile, filename: str) -> None:
        try:
            data = zip.read(filename).decode(errors='ignore')
            self._extract_links(data, filename)
        except Exception as e:
            self.log(f"Error processing class file {filename}: {e}")

    def _extract_links(self, data: str, filename: str) -> None:
        try:
            # Regex for URLs
            url_match = re.search(r'\b(?:https?|ftp|ssh|telnet|file):\/\/[^\s/$.?#].[^\s]*\b', data)
            
            if url_match:
                link = ''.join(letter for letter in url_match.group(0) if letter.isprintable())
                if not any(g in link for g in self.good_links):
                    self.links.append((filename, link))
                    self.info(f'Found link: {link} | {filename}')
            
            # Regex for IP addresses
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', data)
            
            if ip_match:
                ip_address = ip_match.group(0)
                self.links.append((filename, ip_address))
                self.info(f'Found IP address: {ip_address} | {filename}')
        except Exception as e:
            self.log(f"Error extracting links from {filename}: {e}")

    def configure_window(self, window: Window) -> None:
        dwmapi = ctypes.windll.LoadLibrary("dwmapi")
        hwnd = BrowserView.instances[window.uid].Handle.ToInt32()

        dwmapi.DwmSetWindowAttribute(
            hwnd,
            20,
            ctypes.byref(ctypes.c_bool(True)),
            ctypes.sizeof(wintypes.BOOL),
        )

    def visualize_links(self):
        net = Network(directed=True, bgcolor="#333333", font_color="white", layout=True)

        for filename, link in self.links:
            net.add_node(filename, label=filename)
            net.add_node(link, label=link)
            net.add_edge(filename, link)

        html_file = "links_visualization.html"
        
        net.options = {
            "physics": {
                "repulsion": {
                    "centralGravity": 0.6,
                },
                "solver": "repulsion"
            }
        }
        
        net.show(html_file)
        
        css_file_path = os.path.join("assets", "custom_styles.css")

        with open(css_file_path, "r") as css_file:
            css_content = css_file.read()

        with open(html_file, "r+") as buffer:
            html_content = buffer.read()
            buffer.seek(0, 0)
            buffer.write(f"""<style>{css_content}</style>\n{html_content}""")
            
        window = create_window('Links visualization', html_file)
        
        if not self.linux:
            window.events.shown += lambda: self.configure_window(window)
        
        start()