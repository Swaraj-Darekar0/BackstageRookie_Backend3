#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirement.txt

# Install Playwright system dependencies and Chromium
playwright install --with-deps chromium