from app.core.scim_transformer import ScimTransformer


def test_keycloak_to_scim_minimal():
    scim_user = ScimTransformer.keycloak_to_scim({"id": "abc", "username": "alice"})
    assert scim_user["id"] == "abc"
    assert scim_user["userName"] == "alice"
    assert scim_user["meta"]["location"].endswith("/Users/abc")
    assert scim_user["active"] is True


def test_keycloak_to_scim_full_payload_converts_names_and_dates():
    scim_user = ScimTransformer.keycloak_to_scim(
        {
            "id": "abc",
            "username": "alice",
            "firstName": "Alice",
            "lastName": "Smith",
            "email": "alice@example.com",
            "enabled": False,
            "createdTimestamp": 1_700_000_000_000,
        },
        base_url="https://api/scim/v2",
    )
    assert scim_user["active"] is False
    assert scim_user["name"]["givenName"] == "Alice"
    assert scim_user["name"]["familyName"] == "Smith"
    assert scim_user["emails"][0]["value"] == "alice@example.com"
    assert scim_user["meta"]["created"].endswith("Z")
    assert scim_user["meta"]["location"] == "https://api/scim/v2/Users/abc"


def test_scim_to_keycloak_extracts_primary_email():
    kc_user = ScimTransformer.scim_to_keycloak(
        {
            "id": "xyz",
            "userName": "bob",
            "active": False,
            "name": {"givenName": "Bob", "familyName": "Jones"},
            "emails": [
                {"value": "secondary@example.com"},
                {"value": "primary@example.com", "primary": True},
            ],
        }
    )
    assert kc_user["username"] == "bob"
    assert kc_user["enabled"] is False
    assert kc_user["firstName"] == "Bob"
    assert kc_user["email"] == "primary@example.com"
    assert kc_user["id"] == "xyz"


def test_scim_to_keycloak_handles_missing_values():
    kc_user = ScimTransformer.scim_to_keycloak({"userName": "bob"})
    assert kc_user["username"] == "bob"
    assert kc_user["enabled"] is True
    assert "email" not in kc_user


def test_extract_role_from_extensions_and_groups():
    scim_user = {
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"role": "manager"}
    }
    assert ScimTransformer.extract_role_from_scim(scim_user) == "manager"

    scim_user.pop("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
    scim_user["urn:ietf:params:scim:schemas:extension:iam:2.0:User"] = {"role": "operator"}
    assert ScimTransformer.extract_role_from_scim(scim_user) == "operator"

    scim_user.pop("urn:ietf:params:scim:schemas:extension:iam:2.0:User")
    scim_user["groups"] = [{"display": "analyst"}]
    assert ScimTransformer.extract_role_from_scim(scim_user) == "analyst"

    scim_user["groups"] = []
    assert ScimTransformer.extract_role_from_scim(scim_user) == "analyst"


def test_add_role_to_scim_adds_extension_schema():
    scim_user = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"]}
    updated = ScimTransformer.add_role_to_scim(scim_user, "manager")
    assert "urn:ietf:params:scim:schemas:extension:iam:2.0:User" in updated["schemas"]
    assert updated["urn:ietf:params:scim:schemas:extension:iam:2.0:User"]["role"] == "manager"
