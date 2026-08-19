from tests.conftest import TEST_PASSWORD


def test_login_page_loads(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"password" in resp.data.lower()


def test_clients_requires_login(client):
    resp = client.get("/clients")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_with_correct_credentials_redirects_to_clients(client):
    resp = client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients"


def test_login_with_wrong_credentials_reshows_form(client):
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data


def test_logout_requires_login(client):
    resp = client.get("/logout")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
