import unittest
from unittest.mock import patch

from app import main


class StartupBehaviorTests(unittest.TestCase):
    @patch.object(main.keycloak, "bootstrap", side_effect=main.KeycloakError("Keycloak unavailable"))
    def test_initialize_application_does_not_fail_when_keycloak_is_unavailable(self, _bootstrap_mock):
        try:
            main.initialize_application()
        except Exception as exc:  # pragma: no cover - the regression check is the real assertion
            self.fail(f"Startup should not fail when Keycloak is unavailable: {exc}")


if __name__ == "__main__":
    unittest.main()
