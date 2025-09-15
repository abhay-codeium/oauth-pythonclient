#!/usr/bin/env python3
"""
Test script to verify SSL retry logic in get_discovery_doc function.
This script simulates SSL connection errors to test the retry mechanism.
"""

import time
import mock
import requests
from unittest.mock import patch

from intuitlib.utils import get_discovery_doc
from intuitlib.exceptions import AuthClientError


def test_ssl_retry_logic():
    """Test that SSL errors trigger retry logic with exponential backoff."""
    print("Testing SSL retry logic...")
    
    ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
    
    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'issuer': 'https://oauth.platform.intuit.com/op/v1',
        'authorization_endpoint': 'https://appcenter.intuit.com/connect/oauth2',
        'token_endpoint': 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
        'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo',
        'revocation_endpoint': 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke',
        'jwks_uri': 'https://oauth.platform.intuit.com/op/v1/jwks'
    }
    
    with patch('requests.get') as mock_get:
        mock_get.side_effect = [ssl_error, ssl_error, mock_response]
        
        start_time = time.time()
        result = get_discovery_doc('sandbox')
        end_time = time.time()
        
        assert mock_get.call_count == 3
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        
        elapsed_time = end_time - start_time
        assert elapsed_time >= 3.0, f"Expected at least 3s delay, got {elapsed_time:.2f}s"
        
        print(f"✓ SSL retry test passed. Retried {mock_get.call_count} times, took {elapsed_time:.2f}s")

    with patch('requests.get') as mock_get:
        mock_get.side_effect = [ssl_error, ssl_error, ssl_error]
        
        try:
            get_discovery_doc('sandbox')
            assert False, "Expected SSL error to be raised after all retries"
        except requests.exceptions.SSLError as e:
            assert mock_get.call_count == 3
            print(f"✓ SSL retry exhaustion test passed. Failed after {mock_get.call_count} attempts")

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    with patch('requests.get') as mock_get:
        mock_get.side_effect = [conn_error, mock_response]
        
        result = get_discovery_doc('sandbox')
        assert mock_get.call_count == 2
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        print(f"✓ Connection error retry test passed. Retried {mock_get.call_count} times")

    with patch('requests.get') as mock_get:
        error_response = mock.Mock()
        error_response.status_code = 500
        mock_get.return_value = error_response
        
        try:
            get_discovery_doc('sandbox')
            assert False, "Expected AuthClientError to be raised"
        except AuthClientError:
            assert mock_get.call_count == 1  # Should not retry HTTP errors
            print("✓ HTTP error no-retry test passed. Did not retry HTTP errors")

    print("\n🎉 All SSL retry tests passed!")


def test_normal_operation():
    """Test that normal successful requests work without retries."""
    print("\nTesting normal operation...")
    
    with patch('requests.get') as mock_get:
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'authorization_endpoint': 'https://appcenter.intuit.com/connect/oauth2',
            'token_endpoint': 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo',
            'revocation_endpoint': 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke',
            'jwks_uri': 'https://oauth.platform.intuit.com/op/v1/jwks'
        }
        mock_get.return_value = mock_response
        
        start_time = time.time()
        result = get_discovery_doc('sandbox')
        end_time = time.time()
        
        assert mock_get.call_count == 1
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        
        elapsed_time = end_time - start_time
        assert elapsed_time < 1.0, f"Normal operation took too long: {elapsed_time:.2f}s"
        
        print(f"✓ Normal operation test passed. Single call, took {elapsed_time:.3f}s")


if __name__ == '__main__':
    test_ssl_retry_logic()
    test_normal_operation()
    print("\n✅ All tests completed successfully!")
