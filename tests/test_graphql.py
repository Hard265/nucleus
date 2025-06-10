import pytest
from fastapi.testclient import TestClient
import json


class TestGraphQLQueries:
    """Test GraphQL query operations"""
    
    def test_users_query(self, client: TestClient, test_user):
        """Test fetching all users"""
        query = """
        query {
            users {
                id
                email
                isActive
            }
        }
        """
        response = client.post("/graphql", json={"query": query})
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "users" in data["data"]
        assert len(data["data"]["users"]) >= 1
        
        # Check user data structure
        user_data = data["data"]["users"][0]
        assert "id" in user_data
        assert "email" in user_data
        assert "isActive" in user_data
    
    def test_get_user_query(self, client: TestClient, test_user):
        """Test fetching a specific user"""
        query = f"""
        query {{
            getUser(id: "{test_user.id}") {{
                id
                email
                isActive
            }}
        }}
        """
        response = client.post("/graphql", json={"query": query})
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["data"]["getUser"]["id"] == str(test_user.id)
        assert data["data"]["getUser"]["email"] == test_user.email
    
    def test_get_user_not_found(self, client: TestClient):
        """Test fetching non-existent user"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        query = f"""
        query {{
            getUser(id: "{fake_id}") {{
                id
                email
            }}
        }}
        """
        response = client.post("/graphql", json={"query": query})
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["getUser"] is None
    
    def test_me_query_authenticated(self, client: TestClient, auth_headers):
        """Test me query with authentication"""
        query = """
        query {
            me {
                id
                email
                isActive
                roles {
                    role {
                        id
                        name
                        scope
                    }
                    scopeId
                }
            }
        }
        """
        response = client.post("/graphql", json={"query": query}, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "me" in data["data"]
        assert data["data"]["me"]["email"] == "test@example.com"
    
    def test_me_query_unauthenticated(self, client: TestClient):
        """Test me query without authentication"""
        query = """
        query {
            me {
                id
                email
            }
        }
        """
        response = client.post("/graphql", json={"query": query})
        assert response.status_code == 200
        data = response.json()
        assert "errors" in data
        assert "Missing or invalid token" in str(data["errors"])


class TestGraphQLMutations:
    """Test GraphQL mutation operations"""
    
    def test_create_user_mutation(self, client: TestClient):
        """Test creating user via GraphQL"""
        mutation = """
        mutation {
            createUser(input: {
                email: "graphql@example.com"
                password: "securepassword123"
            }) {
                id
                email
                isActive
            }
        }
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["data"]["createUser"]["email"] == "graphql@example.com"
        assert data["data"]["createUser"]["isActive"] is True
    
    def test_create_user_duplicate_email(self, client: TestClient, test_user):
        """Test creating user with duplicate email via GraphQL"""
        mutation = f"""
        mutation {{
            createUser(input: {{
                email: "{test_user.email}"
                password: "anotherpassword123"
            }}) {{
                id
                email
            }}
        }}
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "errors" in data
        assert "already exist" in str(data["errors"]).lower()
    
    def test_login_mutation(self, client: TestClient, test_user):
        """Test login via GraphQL"""
        mutation = """
        mutation {
            login(input: {
                email: "test@example.com"
                password: "testpassword123"
            }) {
                accessToken
                refreshToken
            }
        }
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "accessToken" in data["data"]["login"]
        assert "refreshToken" in data["data"]["login"]
    
    def test_login_invalid_credentials(self, client: TestClient):
        """Test login with invalid credentials via GraphQL"""
        mutation = """
        mutation {
            login(input: {
                email: "nonexistent@example.com"
                password: "wrongpassword"
            }) {
                accessToken
                refreshToken
            }
        }
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "errors" in data
        assert "Invalid credentials" in str(data["errors"])
    
    def test_create_role_mutation(self, client: TestClient):
        """Test creating role via GraphQL"""
        mutation = """
        mutation {
            createRole(input: {
                name: "test_role_graphql"
                scope: GLOBAL_SCOPE
            }) {
                id
                name
                scope
            }
        }
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["data"]["createRole"]["name"] == "test_role_graphql"
        assert data["data"]["createRole"]["scope"] == "GLOBAL_SCOPE"
    
    def test_create_permission_mutation(self, client: TestClient):
        """Test creating permission via GraphQL"""
        mutation = """
        mutation {
            createPermission(input: {
                action: "read:test"
            }) {
                id
                action
                resourceId
            }
        }
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["data"]["createPermission"]["action"] == "read:test"
        assert data["data"]["createPermission"]["resourceId"] is None
    
    def test_assign_role_to_user_mutation(self, client: TestClient, test_user, test_role):
        """Test assigning role to user via GraphQL"""
        mutation = f"""
        mutation {{
            assignRoleToUser(input: {{
                userId: "{test_user.id}"
                roleId: "{test_role.id}"
                scopeId: "{test_user.id}"
            }})
        }}
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["data"]["assignRoleToUser"] is True
    
    def test_assign_role_duplicate(self, client: TestClient, test_user, test_role):
        """Test assigning same role twice to user"""
        # First assignment
        mutation = f"""
        mutation {{
            assignRoleToUser(input: {{
                userId: "{test_user.id}"
                roleId: "{test_role.id}"
                scopeId: "{test_user.id}"
            }})
        }}
        """
        client.post("/graphql", json={"query": mutation})
        
        # Second assignment (should fail)
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "errors" in data
        assert "already has this role" in str(data["errors"])
    
    def test_link_permission_to_role_mutation(self, client: TestClient, test_role, test_permission):
        """Test linking permission to role via GraphQL"""
        mutation = f"""
        mutation {{
            linkPermissionToRole(input: {{
                roleId: "{test_role.id}"
                permissionId: "{test_permission.id}"
            }})
        }}
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["data"]["linkPermissionToRole"] is True


class TestGraphQLSchema:
    """Test GraphQL schema validation"""
    
    def test_invalid_query_syntax(self, client: TestClient):
        """Test invalid GraphQL syntax"""
        invalid_query = """
        query {
            users {
                id
                email
                # Missing closing brace
        """
        response = client.post("/graphql", json={"query": invalid_query})
        assert response.status_code == 400
    
    def test_unknown_field(self, client: TestClient):
        """Test querying unknown field"""
        query = """
        query {
            users {
                id
                email
                unknownField
            }
        }
        """
        response = client.post("/graphql", json={"query": query})
        assert response.status_code == 400
    
    def test_missing_required_argument(self, client: TestClient):
        """Test mutation with missing required argument"""
        mutation = """
        mutation {
            createUser(input: {
                email: "test@example.com"
                # Missing password
            }) {
                id
            }
        }
        """
        response = client.post("/graphql", json={"query": mutation})
        assert response.status_code == 400