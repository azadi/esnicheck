from unittest.mock import patch

import app


def test_has_esni():
    with patch("esnicheck.check.ESNICheck.has_tls13") as mock_tls, \
            patch("esnicheck.check.ESNICheck.has_dns") as mock_dns, \
            patch("esnicheck.check.ESNICheck.has_esni") as mock_esni:
        mock_tls.side_effect = [[True, "TLSv1.3"],
                                [False, "Test supports TLSv1.2"]]
        mock_dns.side_effect = [[True, None, {}],
                                [True, None, {}]]
        mock_esni.side_effect = [True, False]
        assert {'tls13': {'enabled': True, 'output': 'TLSv1.3'},
                'dns': {'enabled': True, 'output': {}, 'error': None},
                'hostname': 'Test',
                'has_esni': True} == app.has_esni("Test")
        assert {'tls13': {'enabled': False, 'output': 'Test supports TLSv1.2'},
                'dns': {'enabled': True, 'output': {}, 'error': None},
                'hostname': 'Test',
                'has_esni': False} == app.has_esni("Test")


def test_landing():
    client = app.app.test_client()
    response = client.get("/", content_type="html/text")
    assert response.status_code == 200


def test_check():
    client = app.app.test_client()
    with patch("app.has_esni", return_value={"has_esni": "False"}):
        post = client.post("/check", json={"q": "domain"})
        assert post.status_code == 200
        incorrect_post = client.post("/check", json={"domain": "domain"})
        assert incorrect_post.status_code == 404
