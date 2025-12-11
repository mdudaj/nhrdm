# -*- coding: utf-8 -*-
# Copyright (C) 2025 National Institute for Medical Research (NIMR)
# This file is part of NHRDM.

import re
import unicodedata

USERNAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{2,}$")


def slugify_name(name: str) -> str:
    # Normalize unicode (remove accents, etc.)
    name = unicodedata.normalize("NFKD", name)
    name = "".join(c for c in name if not unicodedata.combining(c))

    # Lowercase for consistency
    name = name.lower()

    # Replace spaces & invalid characters with underscore
    name = re.sub(r"[^a-z0-9_-]", "_", name)

    # Ensure starts with a letter; if not, prefix 'u'
    if not name or not name[0].isalpha():
        name = "u" + name

    # Ensure minimum length of 3
    if len(name) < 3:
        name = name.ljust(3, "_")

    return name


def generate_unique_username(base_name: str, existing_usernames: set) -> str:
    base = slugify_name(base_name)

    # If base is valid and unused, return directly
    if USERNAME_PATTERN.match(base) and base not in existing_usernames:
        return base

    # Otherwise add numeric suffixes until unique
    counter = 1
    while True:
        candidate = f"{base}_{counter}"
        if USERNAME_PATTERN.match(candidate) and candidate not in existing_usernames:
            return candidate
        counter += 1
