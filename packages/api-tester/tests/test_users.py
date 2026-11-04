import pytest
import allure
from schemas.user_schema import UserSchema

@allure.feature("User Management")
@allure.story("Get User List")
def test_get_users_status_code_and_schema(api_client):
    with allure.step("Send GET request to /users"):
        response = api_client.get("/users")
    
    with allure.step("Verify status code is 200"):
        assert response.status_code == 200
    
    with allure.step("Validate response against Pydantic UserSchema"):
        users = response.json()
        assert isinstance(users, list)
        assert len(users) > 0
        validated_user = UserSchema(**users[0])
        assert validated_user.id == users[0]["id"]

@allure.feature("User Management")
@allure.story("Create User")
def test_create_user_response_data(api_client):
    payload = {"name": "Jane Doe", "username": "janedoe", "email": "jane@example.com"}
    with allure.step("Send POST request to /users with valid payload"):
        response = api_client.post("/users", json=payload)
    
    with allure.step("Verify 201 Created and payload matching"):
        assert response.status_code == 201
        created_user = response.json()
        assert created_user["name"] == payload["name"]

@allure.feature("User Management")
@allure.story("Update User")
def test_update_user_returns_updated_data(api_client):
    payload = {"name": "Jane Updated"}
    with allure.step("Send PUT request to /users/1"):
        response = api_client.put("/users/1", json=payload)
    
    with allure.step("Verify 200 OK and updated fields"):
        assert response.status_code == 200
        updated_user = response.json()
        assert updated_user["name"] == payload["name"]

@allure.feature("User Management")
@allure.story("Delete User")
def test_delete_user_returns_200(api_client):
    with allure.step("Send DELETE request to /users/1"):
        response = api_client.delete("/users/1")
    
    with allure.step("Verify 200 OK deletion response"):
        assert response.status_code == 200