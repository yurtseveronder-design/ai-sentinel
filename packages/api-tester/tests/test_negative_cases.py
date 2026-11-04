import pytest

@pytest.mark.parametrize("endpoint, expected_status", [
    ("/users/999999", 404),
    ("/posts/999999", 404),
    ("/comments/999999", 404),
    ("/invalid_endpoint", 404),
])
def test_non_existent_resources_return_404(api_client, endpoint, expected_status):
    response = api_client.get(endpoint)
    assert response.status_code == expected_status