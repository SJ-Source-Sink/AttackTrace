"""
Code classification — distinguishes application code from third-party libraries.

The biggest source of false positives in static analysis is reporting
"vulnerabilities" inside dependency code (Apache HttpClient, OkHttp,
Firebase, R8/ProGuard-obfuscated SDKs, etc.). Those issues belong to the
library maintainers, not the app under review.

This module provides:
  - is_library_code(path): returns True for known framework/library paths
  - classify_path(path): returns 'app' | 'library' | 'obfuscated' | 'framework'
  - confidence_for_path(path): returns 'high' | 'medium' | 'low'
"""

from __future__ import annotations

import re
from typing import Set

# ──────────────────────────────────────────────────────────────────────
# Library / framework path prefixes (within decompiled `sources/`).
# Anything underneath these is considered third-party code.
# ──────────────────────────────────────────────────────────────────────
LIBRARY_PREFIXES = (
    # AndroidX / Support library
    "androidx/", "android/support/", "android/arch/", "android/databinding/",

    # Kotlin
    "kotlin/", "kotlinx/",

    # Google
    "com/google/", "com/firebase/", "com/android/", "com/android/installreferrer/",
    "com/google/firebase/", "com/google/android/gms/", "com/google/android/material/",
    "com/google/android/play/", "com/google/android/datatransport/",
    "com/google/protobuf/", "com/google/gson/", "com/google/common/",
    "com/google/zxing/", "com/google/crypto/",

    # Networking
    "okhttp3/", "okio/", "retrofit2/",
    "org/apache/http/", "org/apache/commons/", "org/apache/log4j/",
    "io/grpc/", "io/netty/",

    # Reactive / async
    "io/reactivex/", "rx/", "kotlinx/coroutines/", "io/realm/",

    # Facebook / Twitter / Square
    "com/facebook/", "com/twitter/", "com/squareup/", "com/jakewharton/",

    # Microsoft / Adobe / Stripe / etc
    "com/microsoft/", "com/adobe/", "com/stripe/", "com/braintreepayments/",
    "com/paypal/", "com/amazon/", "com/amplitude/", "com/mixpanel/",
    "com/segment/", "com/bugsnag/", "com/crashlytics/", "io/sentry/",
    "io/intercom/", "com/zendesk/", "com/salesforce/", "com/onesignal/",

    # Common Java/JVM libs
    "javax/", "java/", "org/json/", "org/junit/", "org/mockito/",
    "org/hamcrest/", "org/objectweb/", "org/intellij/", "org/jetbrains/",
    "org/koin/", "org/threeten/", "org/slf4j/", "org/checkerframework/",

    # Charting, image loading, UI
    "com/github/", "com/airbnb/", "com/squareup/picasso/",
    "com/squareup/okhttp/", "com/bumptech/glide/", "com/nostra13/",

    # Dependency injection / annotation processors
    "dagger/", "javax/inject/", "javax/annotation/",

    # Misc framework
    "META-INF/", "junit/", "perfetto/", "okio/",
    "kotlinx/serialization/", "org/yaml/",
)

# Java reserved single-letter packages produced by R8/ProGuard obfuscation:
# matches `A0/`, `B12/`, `s1/`, etc. as a top-level package directory.
_OBFUSCATED_TOP_RE = re.compile(r"sources/[A-Za-z][0-9]{0,3}/")

# Inside obfuscated packages, classes look like `A`, `Cf`, `AbstractC1234a`, etc.
_OBFUSCATED_CLASS_RE = re.compile(r"/[A-Z][a-zA-Z]?[0-9]*\.(java|kt)$|/AbstractC[0-9]+[a-z]?\.(java|kt)$")

# Strong obfuscation marker that's recognizable regardless of where the class
# lives (R8 generates class names like `AbstractC1234`, `C0123A`, etc. when
# desugaring lambdas / merging classes from third-party deps).
_R8_GENERATED_CLASS_RE = re.compile(r"/(AbstractC[0-9]+[a-z]?|[A-Z][0-9]{4,}[A-Z]?|C[0-9]{3,}[A-Za-z]?)\.(java|kt)$")

# ──────────────────────────────────────────────────────────────────────


def _normalize(path: str) -> str:
    """Strip leading dirs to get the path starting at `sources/...`."""
    p = path.replace("\\", "/")
    idx = p.find("sources/")
    return p[idx:] if idx >= 0 else p


def is_library_code(file_path: str) -> bool:
    """Return True if a path is inside a known third-party library."""
    p = _normalize(file_path)
    if "sources/" not in p:
        return False
    rel = p.split("sources/", 1)[1]
    for prefix in LIBRARY_PREFIXES:
        if rel.startswith(prefix):
            return True
    return False


def is_obfuscated_code(file_path: str) -> bool:
    """
    Return True if the file appears to be R8/ProGuard-obfuscated dependency code.

    Detection paths:
      1. Top-level package is a 1-2 char name (`A0/`, `s1/`, `Cf/`) AND the
         class basename also looks obfuscated.
      2. Class basename matches the strong R8-generated marker
         (`AbstractC1234`, `C0123A`, etc.) regardless of directory.
    """
    p = _normalize(file_path)
    if _R8_GENERATED_CLASS_RE.search(p):
        return True
    if _OBFUSCATED_TOP_RE.search(p) and _OBFUSCATED_CLASS_RE.search(p):
        return True
    return False


def classify_path(file_path: str) -> str:
    """Return one of: 'library' | 'obfuscated' | 'app' | 'manifest' | 'resource'."""
    p = _normalize(file_path)
    if "AndroidManifest.xml" in p:
        return "manifest"
    if p.endswith(".xml"):
        return "resource"
    if is_library_code(p):
        return "library"
    if is_obfuscated_code(p):
        return "obfuscated"
    return "app"


def confidence_for_path(file_path: str) -> str:
    """
    Return finding confidence based on where the file lives.
      app        → high
      manifest   → high
      resource   → medium
      obfuscated → low
      library    → low
    """
    cat = classify_path(file_path)
    if cat in ("app", "manifest"):
        return "high"
    if cat == "resource":
        return "medium"
    return "low"


def extract_app_top_packages(manifest_package: str) -> Set[str]:
    """
    Given the AndroidManifest <manifest package="x.y.z">, return the set
    of top-level package directories that belong to the app itself.
    For `atws.app` returns {'atws'}; for `com.example.foo` returns {'com'}.
    Used as a fallback when classify_path is uncertain.
    """
    if not manifest_package:
        return set()
    return {manifest_package.split(".", 1)[0]}


def is_app_code_for_package(file_path: str, app_top_packages: Set[str]) -> bool:
    """Check if a file lives under one of the app's own top-level package dirs."""
    p = _normalize(file_path)
    if "sources/" not in p:
        return False
    rel = p.split("sources/", 1)[1]
    top = rel.split("/", 1)[0] if "/" in rel else rel
    return top in app_top_packages
