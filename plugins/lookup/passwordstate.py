# Copyright (c) Stanislav Romanov
# GNU General Public License v3.0+
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
lookup: passwordstate
author: Stanislav Romanov (@zaeb)
version_added: "1.0.0"
short_description: Retrieve passwords from PasswordState
description:
  - Retrieve password values from PasswordState via REST API
  - Returns only the password value from the API response
options:
  api_url:
    description: Base URL of PasswordState instance
    required: true
    type: str
  api_key:
    description: API key for authentication
    required: true
    type: str
  password_id:
    description: ID of the password entry to retrieve
    required: true
    type: int
  validate_certs:
    description: Verify SSL certificates
    default: true
    type: bool
    required: false
  timeout:
    description: Request timeout in seconds
    default: 30
    type: int
    required: false
notes:
  - This plugin returns a list containing a single string (the password value)
  - Always secure API keys using Ansible Vault
  - Ensure proper permissions for the API key in PasswordState
"""

EXAMPLES = r"""
- name: Get password
  debug:
    msg: "{{ lookup('passwordstate',
                   api_url='https://passwordstate.example.com',
                   api_key='actual_api_key_here',
                   password_id=12345) }}"
"""

RETURN = r"""
_raw:
  description:
    - List containing the password value as a single string
  type: list
  elements: str
"""

import json
from urllib.parse import urljoin

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.module_utils.urls import Request
from ansible.utils.display import Display

display = Display()

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        try:
            # Validate and prepare parameters
            api_url = kwargs.get('api_url', '').rstrip('/')
            api_key = kwargs.get('api_key')

            if not api_url or not api_key:
                raise AnsibleError("Both api_url and api_key are required parameters")

            # Validate password_id is provided
            password_id = kwargs.get('password_id')
            if not password_id:
                raise AnsibleError("password_id parameter is required")

            # Build API URL
            url = urljoin(api_url + '/', f"api/passwords/{password_id}")
            headers = {
                'Content-Type': 'application/json',
                'APIKey': api_key,
                'User-Agent': 'Ansible PasswordState Lookup'
            }

            display.vvvv(f"PasswordState API Request URL: {url}")

            # Make API request
            req = Request(
                timeout=int(kwargs.get('timeout', 30)),
                validate_certs=kwargs.get('validate_certs', True),
                headers=headers
            )

            response = req.get(url)
            if response.code != 200:
                body = response.read().decode('utf-8', errors='replace')
                raise AnsibleError(
                    f"API request failed (HTTP {response.code})\n"
                    f"URL: {url}\n"
                    f"Response: {body}"
                )

            # Parse response and extract password
            result = json.loads(response.read().decode('utf-8'))
            if isinstance(result, list):
                result = result[0]  # Take first item if response is array

            password = result.get('Password')
            if not password:
                raise AnsibleError("Password field not found in API response")

            return [password]  # Return as single-element list

        except json.JSONDecodeError as e:
            raise AnsibleError(f"Failed to parse API response: {str(e)}")
        except Exception as e:
            raise AnsibleError(f"PasswordState lookup error: {str(e)}")
