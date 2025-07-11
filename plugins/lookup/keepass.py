# Copyright (c) Stanislav Romanov
# GNU General Public License v3.0+
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
lookup: keepass
author: Stanislav Romanov (@zaeb)
version_added: "2.0.0"
short_description: Retrieve passwords from KeePass database
description:
  - This lookup plugin retrieves passwords from KeePass database files (.kdbx)
  - Supports authentication via master password, key file, or combination of both
  - Allows searching within specific groups by UUID
  - Search is not recursive - searches only in root or specified group directly
requirements:
  - pykeepass >= 4.0.0
options:
  entry_uuid:
    description: UUID of the entry to retrieve password from
    type: str
    required: true
  database:
    description: Path to KeePass database file (.kdbx)
    type: str
    required: true
  password:
    description: Master password for the database
    type: str
    required: false
  keyfile:
    description: Path to key file for database authentication
    type: str
    required: false
  group_uuid:
    description: UUID of the group to limit search scope
    type: str
    required: false
  errors:
    description: How to handle errors (strict, warn, ignore)
    type: str
    default: strict
    choices: ['strict', 'warn', 'ignore']
notes:
  - Either password, keyfile, or both must be provided for authentication
  - Plugin returns only the password field from the found entry
  - Search is not recursive within groups
"""

EXAMPLES = r"""
# Basic usage with master password
- name: Get database password
  debug:
    var: "{{ lookup('keepass', entry_uuid='12345678-1234-1234-1234-123456789abc', database='/path/to/db.kdbx', password='master_password') }}"

# Usage with key file
- name: Get server password using keyfile
  debug:
    var: "{{ lookup('keepass', entry_uuid='12345678-1234-1234-1234-123456789abc', database='/path/to/db.kdbx', keyfile='/path/to/key.key') }}"

# Usage with group limitation
- name: Get password from specific group
  debug:
    var: "{{ lookup('keepass', entry_uuid='12345678-1234-1234-1234-123456789abc', database='/path/to/db.kdbx', password='master_password', group_uuid='87654321-4321-4321-4321-cba987654321') }}"

# Combined authentication (password + keyfile)
- name: Get password with combined auth
  debug:
    var: "{{ lookup('keepass', entry_uuid='12345678-1234-1234-1234-123456789abc', database='/path/to/db.kdbx', password='master_password', keyfile='/path/to/key.key') }}"

# Using with Ansible Vault for master password
- name: Get password with vaulted master password
  debug:
    var: "{{ lookup('keepass', entry_uuid='12345678-1234-1234-1234-123456789abc', database='/path/to/db.kdbx', password=vault_keepass_password) }}"
"""

RETURN = r"""
_raw:
  description: The password from the KeePass entry
  type: list
  elements: str
  returned: success
"""

import os
import uuid

from ansible.errors import AnsibleError, AnsibleFileNotFound
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()

try:
    from pykeepass import PyKeePass
    from pykeepass.exceptions import CredentialsError, HeaderChecksumError

    HAS_PYKEEPASS = True
except ImportError as e:
    HAS_PYKEEPASS = False
    PYKEEPASS_IMPORT_ERROR = str(e)


class LookupModule(LookupBase):
    """KeePass lookup plugin for Ansible"""

    def run(self, terms, variables=None, **kwargs):
        """
        Main entry point for the lookup plugin

        Args:
            terms: Not used for this plugin, but validated for proper usage
            variables: Ansible variables (not used directly)
            **kwargs: Plugin parameters (entry_uuid, database, password, etc.)

        Returns:
            list: List containing the password string
        """

        # Check if pykeepass is available
        if not HAS_PYKEEPASS:
            error_msg = (
                "The pykeepass library is required for the keepass lookup plugin. "
            )
            error_msg += "Install it with: pip install pykeepass"
            if "PYKEEPASS_IMPORT_ERROR" in globals():
                error_msg += f". Import error: {PYKEEPASS_IMPORT_ERROR}"
            raise AnsibleError(error_msg)

        # Validate terms parameter
        if terms:
            raise AnsibleError(
                "The keepass lookup plugin does not accept positional arguments. "
                "Use named parameters instead: entry_uuid, database, password, keyfile, group_uuid"
            )

        # Get and validate required parameters
        entry_uuid = kwargs.get("entry_uuid")
        database_path = kwargs.get("database")

        if not entry_uuid:
            raise AnsibleError("Parameter 'entry_uuid' is required for keepass lookup")

        if not database_path:
            raise AnsibleError("Parameter 'database' is required for keepass lookup")

        # Validate entry_uuid is a string
        if not isinstance(entry_uuid, str) or not entry_uuid.strip():
            raise AnsibleError("Parameter 'entry_uuid' must be a non-empty string")

        # Validate database_path is a string
        if not isinstance(database_path, str) or not database_path.strip():
            raise AnsibleError("Parameter 'database' must be a non-empty string")

        # Get optional authentication parameters
        password = kwargs.get("password")
        keyfile = kwargs.get("keyfile")
        group_uuid = kwargs.get("group_uuid")

        # Get error handling mode (standard Ansible parameter)
        errors = kwargs.get("errors", "strict")
        if errors not in ["strict", "warn", "ignore"]:
            raise AnsibleError(
                "Parameter 'errors' must be one of: strict, warn, ignore"
            )

        # Validate optional string parameters
        if password is not None and (
            not isinstance(password, str) or not password.strip()
        ):
            raise AnsibleError(
                "Parameter 'password' must be a non-empty string if provided"
            )

        if keyfile is not None and (
            not isinstance(keyfile, str) or not keyfile.strip()
        ):
            raise AnsibleError(
                "Parameter 'keyfile' must be a non-empty string if provided"
            )

        if group_uuid is not None and (
            not isinstance(group_uuid, str) or not group_uuid.strip()
        ):
            raise AnsibleError(
                "Parameter 'group_uuid' must be a non-empty string if provided"
            )

        # Validate authentication parameters
        if not password and not keyfile:
            raise AnsibleError(
                "Either 'password', 'keyfile', or both must be provided for authentication"
            )

        display.vvvv(
            f"KeePass lookup: searching for entry {entry_uuid} in {database_path}"
        )

        kp = None
        try:
            # Open database with appropriate authentication method
            kp = self._open_database(database_path, password, keyfile)

            # Find entry by UUID (with optional group limitation)
            entry = self._find_entry(kp, entry_uuid, group_uuid)

            # Extract password from entry
            password_value = self._get_password(entry)

            # Clear password from local variables for security
            # (Python will garbage collect, but this is explicit)
            display.vvvv("KeePass lookup completed successfully")
            return [password_value]

        except Exception as e:
            # Handle errors according to the errors parameter
            error_msg = (
                str(e)
                if not isinstance(e, AnsibleError)
                else str(e).replace("AnsibleError: ", "")
            )

            if errors == "ignore":
                display.vvvv(f"KeePass lookup error ignored: {error_msg}")
                return []
            elif errors == "warn":
                display.warning(f"KeePass lookup warning: {error_msg}")
                return []
            else:  # strict (default)
                if isinstance(e, AnsibleError):
                    raise
                else:
                    raise AnsibleError(f"KeePass lookup failed: {error_msg}")
        finally:
            # Ensure database is properly closed and cleared from memory
            if kp is not None:
                try:
                    # PyKeePass doesn't have explicit close method
                    # but we can clear the reference to help with cleanup
                    del kp
                    display.vvvv("KeePass database reference cleared")
                except Exception:
                    # Ignore cleanup errors
                    pass

    def _open_database(self, database_path, password=None, keyfile=None):
        """
        Open KeePass database with provided authentication credentials

        Args:
            database_path (str): Path to the .kdbx file
            password (str, optional): Master password
            keyfile (str, optional): Path to key file

        Returns:
            PyKeePass: Opened database instance

        Raises:
            AnsibleError: On authentication or file access errors
        """

        # Check if database file exists and is readable
        if not os.path.exists(database_path):
            raise AnsibleError(f"KeePass database file not found: {database_path}")

        if not os.path.isfile(database_path):
            raise AnsibleError(f"KeePass database path is not a file: {database_path}")

        if not os.access(database_path, os.R_OK):
            raise AnsibleError(
                f"KeePass database file is not readable: {database_path}"
            )

        # Check keyfile if provided
        if keyfile:
            if not os.path.exists(keyfile):
                raise AnsibleError(f"KeePass key file not found: {keyfile}")

            if not os.path.isfile(keyfile):
                raise AnsibleError(f"KeePass key file path is not a file: {keyfile}")

            if not os.access(keyfile, os.R_OK):
                raise AnsibleError(f"KeePass key file is not readable: {keyfile}")

        display.vvvv(f"Opening KeePass database: {database_path}")
        if keyfile:
            display.vvvv(f"Using key file: {keyfile}")
        if password:
            display.vvvv("Using master password (value hidden)")

        try:
            # Open database with PyKeePass
            kp = PyKeePass(filename=database_path, password=password, keyfile=keyfile)

            display.vvvv("KeePass database opened successfully")
            return kp

        except CredentialsError as e:
            # Authentication failed
            auth_method = []
            if password:
                auth_method.append("password")
            if keyfile:
                auth_method.append("keyfile")

            raise AnsibleError(
                f"KeePass authentication failed using {' + '.join(auth_method)}: {str(e)}"
            )

        except HeaderChecksumError as e:
            # Database file is corrupted or invalid
            raise AnsibleError(
                f"KeePass database file is corrupted or invalid: {str(e)}"
            )

        except Exception as e:
            # Catch any other PyKeePass exceptions
            raise AnsibleError(f"Failed to open KeePass database: {str(e)}")

    def _find_entry(self, kp, entry_uuid, group_uuid=None):
        """
        Find entry by UUID in KeePass database

        Args:
            kp (PyKeePass): Opened KeePass database instance
            entry_uuid (str): UUID of the entry to find
            group_uuid (str, optional): UUID of the group to limit search

        Returns:
            Entry: Found KeePass entry object

        Raises:
            AnsibleError: If entry or group is not found
        """

        display.vvvv(f"Searching for entry UUID: {entry_uuid}")

        try:
            search_group = None

            # If group_uuid is specified, find the group first
            if group_uuid:
                display.vvvv(f"Limiting search to group UUID: {group_uuid}")

                try:
                    # Convert string UUID to uuid.UUID object
                    group_uuid_obj = uuid.UUID(group_uuid)
                    search_group = kp.find_groups(uuid=group_uuid_obj, first=True)
                    if not search_group:
                        raise AnsibleError(
                            f"Group with UUID '{group_uuid}' not found in KeePass database"
                        )

                    display.vvvv(f"Found group: {search_group.name}")

                except ValueError as e:
                    # Invalid UUID format
                    raise AnsibleError(
                        f"Invalid group UUID format '{group_uuid}': {str(e)}"
                    )

            # Search for entry by UUID
            try:
                # Convert string UUID to uuid.UUID object
                entry_uuid_obj = uuid.UUID(entry_uuid)

                if search_group:
                    # Search within specific group (non-recursive as per requirements)
                    entry = kp.find_entries(
                        uuid=entry_uuid_obj, group=search_group, recursive=False, first=True
                    )
                else:
                    # Search in root of database only (non-recursive as per requirements)
                    entry = kp.find_entries(
                        uuid=entry_uuid_obj,
                        group=kp.root_group,
                        recursive=False,
                        first=True,
                    )

                if not entry:
                    search_location = (
                        f"group '{search_group.name}'"
                        if search_group
                        else "root of database"
                    )
                    raise AnsibleError(
                        f"Entry with UUID '{entry_uuid}' not found in {search_location}"
                    )

                display.vvvv(f"Found entry: {entry.title}")
                return entry

            except ValueError as e:
                # Invalid UUID format
                raise AnsibleError(
                    f"Invalid entry UUID format '{entry_uuid}': {str(e)}"
                )

        except Exception as e:
            # Re-raise AnsibleError as-is, wrap others
            if isinstance(e, AnsibleError):
                raise
            else:
                raise AnsibleError(f"Error searching for entry: {str(e)}")

    def _get_password(self, entry):
        """
        Extract password from KeePass entry

        Args:
            entry: KeePass entry object

        Returns:
            str: Password from the entry

        Raises:
            AnsibleError: If password field is not available
        """

        try:
            password_value = entry.password

            if password_value is None:
                raise AnsibleError(
                    f"Entry '{entry.title}' does not have a password field"
                )

            display.vvvv(f"Retrieved password for entry: {entry.title}")
            return password_value

        except Exception as e:
            if isinstance(e, AnsibleError):
                raise
            else:
                raise AnsibleError(f"Error retrieving password from entry: {str(e)}")
