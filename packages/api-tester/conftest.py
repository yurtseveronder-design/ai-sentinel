import pytest
import logging
from utils.api_client import APIClient

ENV_URLS = {
    "dev": "https://jsonplaceholder.typicode.com",
    "staging": "https://jsonplaceholder.typicode.com",
    "prod": "https://jsonplaceholder.typicode.com"
}

def pytest_addoption(parser):
    parser.addoption(
        "--env",
        action="store",
        default="dev",
        help="Target environment: dev, staging, or prod"
    )

@pytest.fixture(scope="session")
def base_url(request):
    env = request.config.getoption("--env").lower()
    return ENV_URLS.get(env, ENV_URLS["dev"])

@pytest.fixture(scope="session")
def api_client(base_url):
    return APIClient(base_url=base_url)

@pytest.fixture
def sample_user_payload():
    return {
        "name": "Leanne Graham",
        "username": "Bret",
        "email": "Sincere@april.biz"
    }

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    extra = getattr(report, "extra", [])
    if report.when == "call" and report.failed:
        # Attach standard output/logging details into the HTML report on failure
        pytest_html = item.config.pluginmanager.getplugin("html")
        if pytest_html:
            extra.append(pytest_html.extras.text("Test failed during execution. Check logs above for API payloads.", name="Failure Context"))
            report.extra = extra