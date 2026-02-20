"""Main SubBrute Advanced GUI application class."""
import csv
import json
import platform
import socket
import subprocess
import threading
import tkinter as tk
import traceback
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

from subbrute.gui_logger import AdvancedLogger
from subbrute.gui_widgets import AdvancedTooltip, SecurityValidator


class ResultWindow:
    """
    Fenetre popup dediee a l'affichage detaille des resultats.

    Features:
    - Affichage en temps reel des resultats
    - Filtrage et recherche avances
    - Export direct depuis la fenetre
    - Statistiques integrees
    - Interface redimensionnable
    """

    def __init__(self, parent, logger, title="Resultats d'Enumeration"):
        """
        Initialise la fenetre de resultats.

        Args:
            parent: Fenetre parent
            logger: Instance de AdvancedLogger
            title (str): Titre de la fenetre
        """
        try:
            self.parent = parent
            self.logger = logger
            self.results = []
            self.filtered_results = []

            # Creer la fenetre
            self.window = tk.Toplevel(parent)
            self.window.title(title)
            self.window.geometry("1000x600")
            self.window.minsize(800, 400)

            # Configurer l'icone et les attributs
            try:
                self.window.iconbitmap(default='subbrute.ico')
            except Exception:
                pass  # Ignore si l'icone n'existe pas

            self.window.transient(parent)
            self.window.grab_set()

            # Variables
            self.filter_var = tk.StringVar()
            self.filter_type_var = tk.StringVar(value="all")
            self.results_count_var = tk.StringVar(value="Resultats: 0")

            # Creer l'interface
            self._create_interface()
            self._setup_bindings()

            # Centrer la fenetre
            self._center_window()

            self.logger.info("ResultWindow initialized", module="ResultWindow")

        except Exception:
            self.logger.exception("Failed to initialize ResultWindow", module="ResultWindow")
            raise

    def _create_interface(self):
        """Cree l'interface de la fenetre de resultats."""
        try:
            # Frame principal
            main_frame = ttk.Frame(self.window)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Barre d'outils
            toolbar = ttk.Frame(main_frame)
            toolbar.pack(fill=tk.X, pady=(0, 10))

            # Filtres
            filter_frame = ttk.LabelFrame(toolbar, text="Filtres", padding=5)
            filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

            ttk.Label(filter_frame, text="Recherche:").pack(side=tk.LEFT, padx=(0, 5))

            self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
            self.filter_entry.pack(side=tk.LEFT, padx=(0, 10))
            self.filter_entry.bind('<KeyRelease>', self._on_filter_change)

            AdvancedTooltip(
                self.filter_entry,
                "Rechercher dans les hostnames et adresses IP\nSupportes les expressions regulieres"
            )

            # Options de filtre
            ttk.Radiobutton(
                filter_frame, text="Tout", variable=self.filter_type_var,
                value="all", command=self._apply_filter
            ).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Radiobutton(
                filter_frame, text="Hostnames", variable=self.filter_type_var,
                value="hostname", command=self._apply_filter
            ).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Radiobutton(
                filter_frame, text="IPs", variable=self.filter_type_var,
                value="ip", command=self._apply_filter
            ).pack(side=tk.LEFT, padx=(0, 5))

            # Actions
            actions_frame = ttk.LabelFrame(toolbar, text="Actions", padding=5)
            actions_frame.pack(side=tk.RIGHT)

            ttk.Button(
                actions_frame, text="Export CSV", command=self._export_csv
            ).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(
                actions_frame, text="Export JSON", command=self._export_json
            ).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(
                actions_frame, text="Copier Selection", command=self._copy_selection
            ).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(
                actions_frame, text="Rafraichir", command=self._refresh
            ).pack(side=tk.LEFT)

            # Statistiques
            stats_frame = ttk.Frame(main_frame)
            stats_frame.pack(fill=tk.X, pady=(0, 10))

            ttk.Label(
                stats_frame, textvariable=self.results_count_var,
                font=('Segoe UI', 10, 'bold')
            ).pack(side=tk.LEFT)

            self.status_var = tk.StringVar(value="Pret")
            ttk.Label(stats_frame, textvariable=self.status_var).pack(side=tk.RIGHT)

            # TreeView pour les resultats
            tree_frame = ttk.Frame(main_frame)
            tree_frame.pack(fill=tk.BOTH, expand=True)

            # Colonnes
            columns = ("hostname", "record_type", "addresses", "timestamp", "response_time", "ttl")
            self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)

            # Configuration des colonnes
            self.tree.heading(
                "hostname", text="Hostname",
                command=lambda: self._sort_column("hostname")
            )
            self.tree.heading(
                "record_type", text="Type",
                command=lambda: self._sort_column("record_type")
            )
            self.tree.heading(
                "addresses", text="Adresses IP",
                command=lambda: self._sort_column("addresses")
            )
            self.tree.heading(
                "timestamp", text="Timestamp",
                command=lambda: self._sort_column("timestamp")
            )
            self.tree.heading(
                "response_time", text="Temps (ms)",
                command=lambda: self._sort_column("response_time")
            )
            self.tree.heading(
                "ttl", text="TTL",
                command=lambda: self._sort_column("ttl")
            )

            self.tree.column("hostname", width=250, minwidth=150)
            self.tree.column("record_type", width=80, minwidth=60)
            self.tree.column("addresses", width=200, minwidth=120)
            self.tree.column("timestamp", width=120, minwidth=100)
            self.tree.column("response_time", width=100, minwidth=80)
            self.tree.column("ttl", width=80, minwidth=60)

            # Scrollbars
            v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
            h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
            self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

            # Pack TreeView et scrollbars
            self.tree.grid(row=0, column=0, sticky="nsew")
            v_scrollbar.grid(row=0, column=1, sticky="ns")
            h_scrollbar.grid(row=1, column=0, sticky="ew")

            tree_frame.rowconfigure(0, weight=1)
            tree_frame.columnconfigure(0, weight=1)

            # Barre de statut
            status_frame = ttk.Frame(main_frame)
            status_frame.pack(fill=tk.X, pady=(10, 0))

            self.progress_var = tk.DoubleVar()
            self.progress_bar = ttk.Progressbar(
                status_frame, variable=self.progress_var, maximum=100
            )
            self.progress_bar.pack(fill=tk.X)

        except Exception:
            self.logger.exception("Error creating ResultWindow interface", module="ResultWindow")
            raise

    def _setup_bindings(self):
        """Configure les evenements et raccourcis."""
        try:
            # Double-clic pour details
            self.tree.bind("<Double-1>", self._on_item_double_click)

            # Menu contextuel
            self.tree.bind("<Button-3>", self._show_context_menu)

            # Raccourcis clavier
            self.window.bind('<Control-f>', lambda e: self.filter_entry.focus())
            self.window.bind('<Control-c>', lambda e: self._copy_selection())
            self.window.bind('<Control-s>', lambda e: self._export_csv())
            self.window.bind('<F5>', lambda e: self._refresh())
            self.window.bind('<Escape>', lambda e: self.window.destroy())

            # Gestion de la fermeture
            self.window.protocol("WM_DELETE_WINDOW", self._on_closing)

        except Exception:
            self.logger.exception("Error setting up ResultWindow bindings", module="ResultWindow")

    def _center_window(self):
        """Centre la fenetre sur l'ecran."""
        try:
            self.window.update_idletasks()
            width = self.window.winfo_width()
            height = self.window.winfo_height()
            x = (self.window.winfo_screenwidth() - width) // 2
            y = (self.window.winfo_screenheight() - height) // 2
            self.window.geometry("{}x{}+{}+{}".format(width, height, x, y))
        except Exception as e:
            self.logger.error("Error centering ResultWindow", module="ResultWindow", error=str(e))

    def add_result(self, result):
        """Ajoute un resultat a la fenetre."""
        try:
            if not isinstance(result, dict):
                self.logger.warning(
                    "Invalid result format", module="ResultWindow", result_type=type(result)
                )
                return

            required_fields = ['hostname', 'record_type', 'addresses', 'timestamp']
            for field in required_fields:
                if field not in result:
                    self.logger.warning(
                        "Missing required field in result", module="ResultWindow", field=field
                    )
                    return

            enriched_result = result.copy()
            enriched_result['response_time'] = result.get('response_time', 'N/A')
            enriched_result['ttl'] = result.get('ttl', 'N/A')
            enriched_result['id'] = len(self.results) + 1

            self.results.append(enriched_result)
            self._apply_filter()
            self._update_stats()

            if self.tree.get_children():
                self.tree.see(self.tree.get_children()[-1])

            self.logger.debug(
                "Result added to ResultWindow", module="ResultWindow",
                hostname=result['hostname']
            )

        except Exception:
            self.logger.exception(
                "Error adding result to ResultWindow", module="ResultWindow",
                result=str(result)
            )

    def _on_filter_change(self, event=None):
        """Gere les changements de filtre avec delai."""
        try:
            if hasattr(self, '_filter_timer'):
                self.window.after_cancel(self._filter_timer)
            self._filter_timer = self.window.after(300, self._apply_filter)
        except Exception as e:
            self.logger.error(
                "Error in filter change handler", module="ResultWindow", error=str(e)
            )

    def _apply_filter(self):
        """Applique le filtre aux resultats."""
        try:
            filter_text = self.filter_var.get().lower().strip()
            filter_type = self.filter_type_var.get()

            for item in self.tree.get_children():
                self.tree.delete(item)

            self.filtered_results = []

            for result in self.results:
                show_result = False

                if not filter_text:
                    show_result = True
                else:
                    if filter_type == "all":
                        if (filter_text in result['hostname'].lower() or
                                any(filter_text in addr.lower() for addr in result['addresses']) or
                                filter_text in result['record_type'].lower()):
                            show_result = True
                    elif filter_type == "hostname":
                        if filter_text in result['hostname'].lower():
                            show_result = True
                    elif filter_type == "ip":
                        if any(filter_text in addr.lower() for addr in result['addresses']):
                            show_result = True

                if show_result:
                    self.filtered_results.append(result)
                    self.tree.insert("", tk.END, values=(
                        result['hostname'],
                        result['record_type'],
                        ', '.join(result['addresses']),
                        result['timestamp'],
                        result.get('response_time', 'N/A'),
                        result.get('ttl', 'N/A')
                    ))

            self.results_count_var.set("Resultats: {} / {}".format(
                len(self.filtered_results), len(self.results)))

            self.logger.debug(
                "Filter applied", module="ResultWindow",
                total=len(self.results), filtered=len(self.filtered_results)
            )

        except Exception:
            self.logger.exception("Error applying filter", module="ResultWindow")

    def _sort_column(self, col):
        """Trie les resultats par colonne."""
        try:
            self.logger.debug("Sorting by column", module="ResultWindow", column=col)
        except Exception:
            self.logger.exception("Error sorting column", module="ResultWindow", column=col)

    def _on_item_double_click(self, event):
        """Gere le double-clic sur un element."""
        try:
            selection = self.tree.selection()
            if not selection:
                return
            item = self.tree.item(selection[0])
            hostname = item['values'][0]
            result = next(
                (r for r in self.filtered_results if r['hostname'] == hostname), None
            )
            if result:
                self._show_result_details(result)
        except Exception:
            self.logger.exception("Error handling double-click", module="ResultWindow")

    def _show_result_details(self, result):
        """Affiche les details d'un resultat dans une popup."""
        try:
            details_window = tk.Toplevel(self.window)
            details_window.title("Details - {}".format(result['hostname']))
            details_window.geometry("600x500")
            details_window.transient(self.window)
            details_window.grab_set()

            main_frame = ttk.Frame(details_window, padding=20)
            main_frame.pack(fill=tk.BOTH, expand=True)

            info_frame = ttk.LabelFrame(main_frame, text="Informations Principales", padding=10)
            info_frame.pack(fill=tk.X, pady=(0, 10))

            ttk.Label(
                info_frame, text="Hostname:", font=('Segoe UI', 10, 'bold')
            ).grid(row=0, column=0, sticky=tk.W, pady=2)
            ttk.Label(
                info_frame, text=result['hostname']
            ).grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)

            ttk.Label(
                info_frame, text="Type d'enregistrement:", font=('Segoe UI', 10, 'bold')
            ).grid(row=1, column=0, sticky=tk.W, pady=2)
            ttk.Label(
                info_frame, text=result['record_type']
            ).grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)

            ttk.Label(
                info_frame, text="Timestamp:", font=('Segoe UI', 10, 'bold')
            ).grid(row=2, column=0, sticky=tk.W, pady=2)
            ttk.Label(
                info_frame, text=result['timestamp']
            ).grid(row=2, column=1, sticky=tk.W, padx=(10, 0), pady=2)

            ip_frame = ttk.LabelFrame(main_frame, text="Adresses IP", padding=10)
            ip_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

            ip_text = scrolledtext.ScrolledText(ip_frame, height=8, width=60)
            ip_text.pack(fill=tk.BOTH, expand=True)

            for i, addr in enumerate(result['addresses']):
                ip_text.insert(tk.END, "{}. {}\n".format(i+1, addr))
            ip_text.config(state=tk.DISABLED)

            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X, pady=(10, 0))

            ttk.Button(
                button_frame, text="Copier Hostname",
                command=lambda: self._copy_to_clipboard(result['hostname'])
            ).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(
                button_frame, text="Copier IPs",
                command=lambda: self._copy_to_clipboard('\n'.join(result['addresses']))
            ).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(
                button_frame, text="Whois",
                command=lambda: self._show_whois(result['hostname'])
            ).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(
                button_frame, text="Fermer",
                command=details_window.destroy
            ).pack(side=tk.RIGHT)

        except Exception:
            self.logger.exception("Error showing result details", module="ResultWindow")

    def _show_context_menu(self, event):
        """Affiche le menu contextuel."""
        try:
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                context_menu = tk.Menu(self.window, tearoff=0)
                context_menu.add_command(
                    label="Voir details",
                    command=lambda: self._on_item_double_click(None)
                )
                context_menu.add_command(label="Copier hostname", command=self._copy_hostname)
                context_menu.add_command(label="Copier IPs", command=self._copy_ips)
                context_menu.add_separator()
                context_menu.add_command(label="Whois", command=self._whois_selected)
                context_menu.add_command(label="Port scan", command=self._port_scan_selected)
                context_menu.tk_popup(event.x_root, event.y_root)
        except Exception:
            self.logger.exception("Error showing context menu", module="ResultWindow")

    def _copy_to_clipboard(self, text):
        """Copie du texte vers le presse-papier."""
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(text)
            display_text = text[:50] + "..." if len(text) > 50 else text
            self.status_var.set("Copie: {}".format(display_text))
            self.window.after(3000, lambda: self.status_var.set("Pret"))
        except Exception:
            self.logger.exception("Error copying to clipboard", module="ResultWindow")

    def _copy_selection(self):
        """Copie la selection vers le presse-papier."""
        try:
            selection = self.tree.selection()
            if not selection:
                messagebox.showwarning(
                    "Aucune selection", "Veuillez selectionner un element a copier."
                )
                return
            text_lines = []
            for item_id in selection:
                item = self.tree.item(item_id)
                values = item['values']
                text_lines.append("\t".join(str(v) for v in values))
            text_to_copy = "\n".join(text_lines)
            self._copy_to_clipboard(text_to_copy)
        except Exception:
            self.logger.exception("Error copying selection", module="ResultWindow")

    def _copy_hostname(self):
        """Copie le hostname selectionne."""
        try:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                hostname = item['values'][0]
                self._copy_to_clipboard(hostname)
        except Exception:
            self.logger.exception("Error copying hostname", module="ResultWindow")

    def _copy_ips(self):
        """Copie les IPs selectionnees."""
        try:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                ips = item['values'][2]
                self._copy_to_clipboard(ips)
        except Exception:
            self.logger.exception("Error copying IPs", module="ResultWindow")

    def _whois_selected(self):
        """Lance une requete whois sur l'element selectionne."""
        try:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                hostname = item['values'][0]
                self._show_whois(hostname)
        except Exception:
            self.logger.exception("Error in whois", module="ResultWindow")

    def _show_whois(self, hostname):
        """Affiche les informations whois."""
        try:
            whois_window = tk.Toplevel(self.window)
            whois_window.title("Whois - {}".format(hostname))
            whois_window.geometry("700x500")
            whois_window.transient(self.window)

            main_frame = ttk.Frame(whois_window, padding=10)
            main_frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(
                main_frame,
                text="Informations Whois pour: {}".format(hostname),
                font=('Segoe UI', 12, 'bold')
            ).pack(pady=(0, 10))

            whois_text = scrolledtext.ScrolledText(main_frame, font=('Consolas', 9))
            whois_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X)

            ttk.Button(
                button_frame, text="Actualiser",
                command=lambda: self._update_whois(hostname, whois_text)
            ).pack(side=tk.LEFT)
            ttk.Button(
                button_frame, text="Fermer",
                command=whois_window.destroy
            ).pack(side=tk.RIGHT)

            self._update_whois(hostname, whois_text)

        except Exception:
            self.logger.exception(
                "Error showing whois", module="ResultWindow", hostname=hostname
            )

    def _update_whois(self, hostname, text_widget):
        """Met a jour les informations whois."""
        try:
            text_widget.delete('1.0', tk.END)
            text_widget.insert(tk.END, "Recuperation des informations whois...\n")

            def whois_thread():
                try:
                    if platform.system().lower() == 'windows':
                        cmd = ['nslookup', hostname]
                    else:
                        cmd = ['whois', hostname]

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                    if result.returncode == 0:
                        whois_info = result.stdout
                    else:
                        whois_info = "Erreur lors de la requete whois:\n{}".format(result.stderr)

                    def update_ui():
                        text_widget.delete('1.0', tk.END)
                        text_widget.insert(tk.END, whois_info)

                    text_widget.after(0, update_ui)

                except subprocess.TimeoutExpired:
                    def update_ui():
                        text_widget.delete('1.0', tk.END)
                        text_widget.insert(tk.END, "Timeout lors de la requete whois")
                    text_widget.after(0, update_ui)

                except Exception as exc:
                    def update_ui(err=exc):
                        text_widget.delete('1.0', tk.END)
                        text_widget.insert(tk.END, "Erreur: {}".format(str(err)))
                    text_widget.after(0, update_ui)

            threading.Thread(target=whois_thread, daemon=True).start()

        except Exception:
            self.logger.exception(
                "Error updating whois", module="ResultWindow", hostname=hostname
            )

    def _port_scan_selected(self):
        """Lance un scan de ports sur l'element selectionne."""
        try:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                ips = item['values'][2].split(', ')
                if ips:
                    self._show_port_scan(ips[0])
        except Exception:
            self.logger.exception("Error in port scan", module="ResultWindow")

    def _show_port_scan(self, ip_address):
        """Affiche une fenetre de scan de ports."""
        try:
            scan_window = tk.Toplevel(self.window)
            scan_window.title("Port Scan - {}".format(ip_address))
            scan_window.geometry("600x500")
            scan_window.transient(self.window)

            main_frame = ttk.Frame(scan_window, padding=10)
            main_frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(
                main_frame,
                text="Scan de ports pour: {}".format(ip_address),
                font=('Segoe UI', 12, 'bold')
            ).pack(pady=(0, 10))

            options_frame = ttk.LabelFrame(main_frame, text="Options", padding=5)
            options_frame.pack(fill=tk.X, pady=(0, 10))

            ports_var = tk.StringVar(value="22,80,443,8080,8443")
            ttk.Label(options_frame, text="Ports:").pack(side=tk.LEFT, padx=(0, 5))
            ttk.Entry(options_frame, textvariable=ports_var, width=30).pack(
                side=tk.LEFT, padx=(0, 10)
            )

            scan_text = scrolledtext.ScrolledText(main_frame, font=('Consolas', 9))
            scan_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

            scan_button = ttk.Button(
                options_frame, text="Scanner",
                command=lambda: self._run_port_scan(ip_address, ports_var.get(), scan_text)
            )
            scan_button.pack(side=tk.LEFT)

            ttk.Button(main_frame, text="Fermer", command=scan_window.destroy).pack()

        except Exception:
            self.logger.exception(
                "Error showing port scan", module="ResultWindow", ip=ip_address
            )

    def _run_port_scan(self, ip_address, ports_str, text_widget):
        """Execute un scan de ports simple."""
        try:
            text_widget.delete('1.0', tk.END)
            text_widget.insert(
                tk.END, "Demarrage du scan de ports pour {}...\n".format(ip_address)
            )

            def scan_thread():
                try:
                    ports = [
                        int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()
                    ]
                    open_ports = []

                    for port in ports:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            result = sock.connect_ex((ip_address, port))
                            sock.close()

                            if result == 0:
                                open_ports.append(port)
                                status = "OUVERT"
                            else:
                                status = "FERME"

                            def update_ui(p=port, s=status):
                                text_widget.insert(tk.END, "Port {}: {}\n".format(p, s))
                                text_widget.see(tk.END)

                            text_widget.after(0, update_ui)

                        except Exception:
                            def update_ui(p=port):
                                text_widget.insert(tk.END, "Port {}: ERREUR\n".format(p))
                            text_widget.after(0, update_ui)

                    def final_update():
                        text_widget.insert(tk.END, "\n--- Resume ---\n")
                        text_widget.insert(tk.END, "Ports ouverts: {}\n".format(
                            ", ".join(map(str, open_ports)) if open_ports else "Aucun"))
                        text_widget.insert(tk.END, "Scan termine.\n")

                    text_widget.after(0, final_update)

                except Exception as exc:
                    def error_update(err=exc):
                        text_widget.insert(
                            tk.END, "Erreur lors du scan: {}\n".format(str(err))
                        )
                    text_widget.after(0, error_update)

            threading.Thread(target=scan_thread, daemon=True).start()

        except Exception:
            self.logger.exception(
                "Error running port scan", module="ResultWindow",
                ip=ip_address, ports=ports_str
            )

    def _export_csv(self):
        """Exporte les resultats filtres en CSV."""
        try:
            if not self.filtered_results:
                messagebox.showwarning("Aucun resultat", "Aucun resultat a exporter.")
                return

            filename = filedialog.asksaveasfilename(
                title="Exporter en CSV",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )

            if filename:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        'Hostname', 'Record Type', 'IP Addresses',
                        'Timestamp', 'Response Time', 'TTL'
                    ])
                    for result in self.filtered_results:
                        writer.writerow([
                            result['hostname'],
                            result['record_type'],
                            ', '.join(result['addresses']),
                            result['timestamp'],
                            result.get('response_time', 'N/A'),
                            result.get('ttl', 'N/A')
                        ])

                messagebox.showinfo(
                    "Export reussi", "Resultats exportes vers:\n{}".format(filename)
                )
                self.logger.info(
                    "Results exported to CSV", module="ResultWindow", filename=filename
                )

        except Exception as e:
            self.logger.exception("Error exporting to CSV", module="ResultWindow")
            messagebox.showerror(
                "Erreur d'export", "Erreur lors de l'export CSV:\n{}".format(str(e))
            )

    def _export_json(self):
        """Exporte les resultats filtres en JSON."""
        try:
            if not self.filtered_results:
                messagebox.showwarning("Aucun resultat", "Aucun resultat a exporter.")
                return

            filename = filedialog.asksaveasfilename(
                title="Exporter en JSON",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )

            if filename:
                export_data = {
                    'metadata': {
                        'export_time': datetime.now().isoformat(),
                        'total_results': len(self.filtered_results),
                        'export_source': 'SubBrute Advanced GUI'
                    },
                    'results': self.filtered_results
                }

                with open(filename, 'w', encoding='utf-8') as jsonfile:
                    json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)

                messagebox.showinfo(
                    "Export reussi", "Resultats exportes vers:\n{}".format(filename)
                )
                self.logger.info(
                    "Results exported to JSON", module="ResultWindow", filename=filename
                )

        except Exception as e:
            self.logger.exception("Error exporting to JSON", module="ResultWindow")
            messagebox.showerror(
                "Erreur d'export", "Erreur lors de l'export JSON:\n{}".format(str(e))
            )

    def _refresh(self):
        """Actualise l'affichage."""
        try:
            self._apply_filter()
            self._update_stats()
            self.status_var.set("Actualise a {}".format(datetime.now().strftime("%H:%M:%S")))
        except Exception:
            self.logger.exception("Error refreshing ResultWindow", module="ResultWindow")

    def _update_stats(self):
        """Met a jour les statistiques affichees."""
        try:
            total = len(self.results)
            filtered = len(self.filtered_results)
            self.results_count_var.set("Resultats: {} / {}".format(filtered, total))
            if total > 0:
                progress = (filtered / total) * 100
                self.progress_var.set(progress)
        except Exception:
            self.logger.exception("Error updating stats", module="ResultWindow")

    def _on_closing(self):
        """Gere la fermeture de la fenetre."""
        try:
            self.logger.info(
                "ResultWindow closing", module="ResultWindow",
                total_results=len(self.results)
            )
            self.window.destroy()
        except Exception:
            self.logger.exception("Error closing ResultWindow", module="ResultWindow")


def main():
    """Point d'entree principal pour tester la fenetre de resultats."""
    try:
        logger = AdvancedLogger(debug=True)
        root = tk.Tk()
        root.withdraw()

        result_window = ResultWindow(root, logger)

        test_results = [
            {
                'hostname': 'www.example.com',
                'record_type': 'A',
                'addresses': ['192.168.1.1', '192.168.1.2'],
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'response_time': '50ms',
                'ttl': '300'
            },
            {
                'hostname': 'mail.example.com',
                'record_type': 'A',
                'addresses': ['192.168.1.10'],
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'response_time': '75ms',
                'ttl': '600'
            }
        ]

        for result in test_results:
            result_window.add_result(result)

        root.mainloop()

    except Exception as e:
        print("Erreur lors du test: {}".format(str(e)))
        print("Traceback: {}".format(traceback.format_exc()))


def main_advanced():
    """Point d'entree principal pour l'interface avancee complete."""
    try:
        print("SubBrute Advanced GUI v2.1 - Demarrage...")
        print("Interface complete avec recherche de proprietaires et fonctionnalites avancees")

        root = tk.Tk()
        logger = AdvancedLogger("SubBrute_Complete", debug=True)

        logger.success("SubBrute Advanced GUI v2.1 starting", module="Main")
        logger.info(
            "All advanced features enabled: WHOIS, Email search, Geolocation",
            module="Main"
        )

        from subbrute_gui import SubBruteGUI
        app = SubBruteGUI(root)

        app.logger = logger
        app.security_validator = SecurityValidator(logger)

        logger.success("SubBrute Advanced GUI initialized successfully", module="Main")
        root.mainloop()
        logger.success("Application terminated successfully", module="Main")
        return 0

    except KeyboardInterrupt:
        print("\nApplication interrompue par l'utilisateur")
        return 0
    except Exception as e:
        print("Erreur fatale: {}".format(str(e)))
        print("Traceback: {}".format(traceback.format_exc()))
        return 1
