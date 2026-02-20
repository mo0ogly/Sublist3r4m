"""Custom widget classes for SubBrute Advanced GUI."""
import re
import tkinter as tk


class SecurityValidator:
    """
    Validateur de securite pour les entrees utilisateur.

    Verifie et sanitise toutes les entrees pour eviter les injections
    et autres attaques de securite.
    """

    # Patterns dangereux
    DANGEROUS_PATTERNS = [
        r'[;&|`$()\\]',  # Caracteres d'injection shell
        r'<script[^>]*>',  # Injection XSS
        r'javascript:',  # URL javascript
        r'vbscript:',  # URL vbscript
        r'\.\.[\/\\]',  # Directory traversal
        r'\x00',  # Null bytes
    ]

    # Patterns valides pour domaines
    DOMAIN_PATTERN = (
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )

    def __init__(self, logger=None):
        """Initialise le validateur de securite."""
        self.logger = logger
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.DANGEROUS_PATTERNS
        ]
        self.domain_regex = re.compile(self.DOMAIN_PATTERN)

        # Listes noires de securite
        self.blocked_domains = {
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            'local', 'internal', 'private'
        }

        self.dangerous_chars = ['<', '>', '&', '"', "'", '`', ';', '|', '&', '$']

        self.ip_regex = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )

    def _log_security_event(self, event_type, message, data=None):
        """Log d'evenement de securite."""
        if self.logger:
            self.logger.security(
                "SECURITY_EVENT: {} - {}".format(event_type, message),
                module="SecurityValidator",
                event_type=event_type,
                input_data=str(data)[:100] if data else None
            )

    def validate_domain(self, domain):
        """
        Valide un nom de domaine.

        Args:
            domain (str): Domaine a valider

        Returns:
            tuple: (is_valid, sanitized_domain, error_message)
        """
        try:
            if not domain or not isinstance(domain, str):
                return False, "", "Domain must be a non-empty string"

            # Nettoyer les espaces
            clean_domain = domain.strip().lower()

            # Verifier la longueur
            if len(clean_domain) > 253:
                self._log_security_event(
                    "INVALID_DOMAIN_LENGTH", "Domain too long", clean_domain
                )
                return False, "", "Domain name too long (max 253 characters)"

            if len(clean_domain) < 1:
                return False, "", "Domain name too short"

            # Verifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(clean_domain):
                    self._log_security_event(
                        "DANGEROUS_PATTERN_DETECTED",
                        "Dangerous pattern in domain",
                        clean_domain
                    )
                    return False, "", "Domain contains dangerous characters"

            # Verifier le format du domaine
            if not self.domain_regex.match(clean_domain):
                self._log_security_event(
                    "INVALID_DOMAIN_FORMAT", "Invalid domain format", clean_domain
                )
                return False, "", "Invalid domain name format"

            # Verifier la liste noire
            if clean_domain in self.blocked_domains:
                self._log_security_event(
                    "BLOCKED_DOMAIN", "Blocked domain attempted", clean_domain
                )
                return False, "", "Domain is blocked for security reasons"

            # Verifier les parties du domaine
            parts = clean_domain.split('.')
            if len(parts) < 2:
                return False, "", "Domain must have at least two parts"

            for part in parts:
                if not part or len(part) > 63:
                    return False, "", "Invalid domain part length"
                if part.startswith('-') or part.endswith('-'):
                    return False, "", "Domain parts cannot start or end with hyphen"

            return True, clean_domain, None

        except Exception as e:
            self._log_security_event(
                "VALIDATION_ERROR", "Exception during domain validation", str(e)
            )
            return False, "", "Validation error: {}".format(str(e))

    def validate_file_path(self, filepath, must_exist=True, readable=True):
        """
        Valide un chemin de fichier.

        Args:
            filepath (str): Chemin a valider
            must_exist (bool): Le fichier doit exister
            readable (bool): Le fichier doit etre lisible

        Returns:
            tuple: (is_valid, sanitized_path, error_message)
        """
        try:
            import os

            if not filepath or not isinstance(filepath, str):
                return False, "", "File path must be a non-empty string"

            # Nettoyer le chemin
            clean_path = filepath.strip()

            # Verifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(clean_path):
                    self._log_security_event(
                        "DANGEROUS_PATH_PATTERN",
                        "Dangerous pattern in path",
                        clean_path
                    )
                    return False, "", "File path contains dangerous characters"

            # Verifier directory traversal
            if ".." in clean_path:
                self._log_security_event(
                    "DIRECTORY_TRAVERSAL_ATTEMPT",
                    "Directory traversal in path",
                    clean_path
                )
                return False, "", "Directory traversal not allowed"

            # Verifier les caracteres dangereux
            for char in ['<', '>', '|', '"', '?', '*']:
                if char in clean_path:
                    self._log_security_event(
                        "DANGEROUS_PATH_CHAR",
                        "Dangerous character in file path",
                        clean_path
                    )
                    return False, "", "File path contains dangerous character: {}".format(char)

            # Normaliser le chemin
            try:
                normalized_path = os.path.normpath(clean_path)
                # Verifier que le chemin normalise ne sort pas du repertoire courant
                if normalized_path.startswith('..'):
                    self._log_security_event(
                        "PATH_ESCAPE_ATTEMPT", "Path escape attempt", clean_path
                    )
                    return False, "", "Path escape not allowed"
            except Exception as e:
                return False, "", "Path normalization failed: {}".format(str(e))

            # Verifier l'existence si requis
            if must_exist and not os.path.exists(normalized_path):
                return False, "", "File does not exist: {}".format(normalized_path)

            # Verifier la lisibilite si requis
            if readable and os.path.exists(normalized_path) and not os.access(normalized_path, os.R_OK):
                return False, "", "File is not readable: {}".format(normalized_path)

            # Verifier que c'est bien un fichier et non un repertoire
            if os.path.exists(normalized_path) and not os.path.isfile(normalized_path):
                return False, "", "Path is not a regular file: {}".format(normalized_path)

            return True, normalized_path, None

        except Exception as e:
            self._log_security_event(
                "PATH_VALIDATION_ERROR",
                "Exception during path validation",
                str(e)
            )
            return False, "", "Path validation error: {}".format(str(e))

    def validate_integer(self, value, min_val=None, max_val=None, field_name="value"):
        """
        Valide une valeur entiere.

        Args:
            value: Valeur a valider
            min_val (int): Valeur minimale
            max_val (int): Valeur maximale
            field_name (str): Nom du champ pour les messages d'erreur

        Returns:
            tuple: (is_valid, validated_int, error_message)
        """
        try:
            if value is None:
                return False, 0, "{} cannot be None".format(field_name)

            # Conversion en entier
            try:
                if isinstance(value, str):
                    clean_value = value.strip()
                    int_value = int(clean_value)
                else:
                    int_value = int(value)
            except (ValueError, TypeError):
                return False, 0, "{} must be a valid integer".format(field_name)

            # Verifier les limites
            if min_val is not None and int_value < min_val:
                return False, min_val, "{} must be at least {}".format(field_name, min_val)

            if max_val is not None and int_value > max_val:
                return False, max_val, "{} must be at most {}".format(field_name, max_val)

            return True, int_value, None

        except Exception as e:
            return False, 0, "Integer validation error: {}".format(str(e))

    def sanitize_text(self, text, max_length=1000):
        """
        Sanitise du texte libre.

        Args:
            text (str): Texte a sanitiser
            max_length (int): Longueur maximale

        Returns:
            str: Texte sanitise
        """
        try:
            if not text or not isinstance(text, str):
                return ""

            # Nettoyer et limiter la longueur
            clean_text = text.strip()[:max_length]

            # Supprimer les caracteres de controle sauf \n, \r, \t
            clean_text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', clean_text)

            return clean_text

        except Exception as e:
            if self.logger:
                self.logger.error(
                    "Text sanitization error: {}".format(str(e)),
                    module="SecurityValidator"
                )
            return ""


class AdvancedTooltip:
    """
    Systeme de tooltip avance avec positionnement intelligent et style moderne.

    Features:
    - Multi-lignes avec formatage
    - Delai personnalisable
    - Position intelligente
    - Style moderne avec ombres
    - Support des raccourcis clavier
    """

    def __init__(self, widget, text, delay=500, wraplength=300):
        """
        Initialise le tooltip avance.

        Args:
            widget: Widget parent
            text (str): Texte du tooltip (peut contenir \\n)
            delay (int): Delai avant affichage en ms
            wraplength (int): Largeur max du texte
        """
        try:
            self.widget = widget
            self.text = text
            self.delay = delay
            self.wraplength = wraplength
            self.tooltip_window = None
            self.after_id = None

            # Bind events
            self.widget.bind("<Enter>", self.on_enter)
            self.widget.bind("<Leave>", self.on_leave)
            self.widget.bind("<Motion>", self.on_motion)
            self.widget.bind('<Button-1>', self.on_click)

        except Exception as e:
            print("Error initializing AdvancedTooltip: {}".format(str(e)))

    def on_enter(self, event=None):
        """Gestionnaire d'entree de souris."""
        try:
            self.schedule_tooltip()
        except Exception as e:
            print("Error in tooltip on_enter: {}".format(str(e)))

    def on_leave(self, event=None):
        """Gestionnaire de sortie de souris."""
        try:
            self.cancel_tooltip()
            self.hide_tooltip()
        except Exception as e:
            print("Error in tooltip on_leave: {}".format(str(e)))

    def on_motion(self, event=None):
        """Gestionnaire de mouvement de souris."""
        try:
            self.cancel_tooltip()
            self.schedule_tooltip()
        except Exception as e:
            print("Error in tooltip on_motion: {}".format(str(e)))

    def on_click(self, event=None):
        """Gere le clic (cache le tooltip)."""
        try:
            self.hide_tooltip()
        except Exception as e:
            print("Error in tooltip on_click: {}".format(str(e)))

    def schedule_tooltip(self):
        """Programme l'affichage du tooltip."""
        try:
            self.cancel_tooltip()
            self.after_id = self.widget.after(self.delay, self.show_tooltip)
        except Exception as e:
            print("Error scheduling tooltip: {}".format(str(e)))

    def cancel_tooltip(self):
        """Annule l'affichage du tooltip."""
        try:
            if self.after_id:
                self.widget.after_cancel(self.after_id)
                self.after_id = None
        except Exception as e:
            print("Error canceling tooltip: {}".format(str(e)))

    def show_tooltip(self):
        """Affiche le tooltip."""
        try:
            if self.tooltip_window or not self.text:
                return

            # Obtenir la position de la souris
            x = self.widget.winfo_rootx() + 25
            y = self.widget.winfo_rooty() + 25

            # Creer la fenetre tooltip
            self.tooltip_window = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            tw.wm_attributes("-topmost", True)
            tw.wm_attributes('-alpha', 0.95)  # Transparence

            # Creer le contenu avec style moderne
            frame = tk.Frame(tw, background='#2c3e50', relief='solid', borderwidth=1)
            frame.pack()

            label = tk.Label(
                frame, text=self.text, justify='left',
                background='#2c3e50', foreground='#ecf0f1',
                font=('Segoe UI', 9), padx=8, pady=6,
                wraplength=self.wraplength
            )
            label.pack()

            # Ajuster la position si necessaire
            tw.update_idletasks()
            tooltip_width = tw.winfo_reqwidth()
            tooltip_height = tw.winfo_reqheight()

            screen_width = tw.winfo_screenwidth()
            screen_height = tw.winfo_screenheight()

            if x + tooltip_width > screen_width:
                x = screen_width - tooltip_width - 10
            if y + tooltip_height > screen_height:
                y = y - tooltip_height - 30

            tw.wm_geometry("+{}+{}".format(x, y))

        except Exception as e:
            print("Error showing tooltip: {}".format(str(e)))

    def hide_tooltip(self):
        """Cache le tooltip."""
        if self.tooltip_window:
            try:
                self.tooltip_window.destroy()
            except Exception:
                pass
            finally:
                self.tooltip_window = None

    def update_text(self, new_text):
        """Met a jour le texte du tooltip."""
        self.text = new_text
