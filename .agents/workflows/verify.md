---
description: Verify that the style and tests are still passing
---

// turbo-all
1. `moon run :format` (Ensures consistent formatting)
2. `moon run :lint` (Checks for errors and style issues)
3. `moon run kest-core-python:test` (Unit tests)
4. `moon run kest-core-python:test-live` (Integration tests in the lab)