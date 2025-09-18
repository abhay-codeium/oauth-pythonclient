 # Copyright (c) 2018 Intuit
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #  http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.

"""Test module for intuitlib.utils
"""

import json
import pytest
import mock
import requests
import time
from unittest.mock import patch

from intuitlib.utils import (
    get_discovery_doc,
    scopes_to_string,
    set_attributes,
    send_request,
    generate_token,
    get_jwk,
    validate_id_token,
)
from intuitlib.enums import Scopes
from intuitlib.client import AuthClient
from intuitlib.exceptions import AuthClientError
from tests.helper import MockResponse

class TestUtils():

    auth_client = AuthClient('client_id','client_secret','redirect_uri','sandbox')

    def mock_request(self, status=200, content=None):
        return MockResponse(status=status, content=content)

    def test_get_discovery_doc_sandbox(self):
        discovery_doc = get_discovery_doc('sandbox')
        
        assert discovery_doc['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert discovery_doc['userinfo_endpoint'] == 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'

    def test_get_discovery_doc_production(self):
        discovery_doc = get_discovery_doc('production')
        
        assert discovery_doc['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert discovery_doc['userinfo_endpoint'] == 'https://accounts.platform.intuit.com/v1/openid_connect/userinfo'

    def test_get_discovery_doc_custom_url_input(self):
        discovery_doc = get_discovery_doc('https://developer.intuit.com/.well-known/openid_sandbox_configuration/')
        
        assert discovery_doc['issuer'] =='https://oauth.platform.intuit.com/op/v1'
        assert discovery_doc['userinfo_endpoint'] == 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
    
    @mock.patch('intuitlib.utils.requests.get')
    def test_get_discovery_doc_bad_response(self, mock_get):
        mock_resp = self.mock_request(status=400)
        mock_get.return_value = mock_resp

        with pytest.raises(AuthClientError):
            get_discovery_doc('sandbox')

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_ssl_error_retry_success(self, mock_sleep, mock_get):
        """Test SSL error triggers retry logic and eventually succeeds"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'authorization_endpoint': 'https://appcenter.intuit.com/connect/oauth2',
            'token_endpoint': 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo',
            'revocation_endpoint': 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke',
            'jwks_uri': 'https://oauth.platform.intuit.com/op/v1/jwks'
        })
        
        mock_get.side_effect = [ssl_error, ssl_error, success_response]
        
        result = get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 3
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(1)  # First retry: 1 * (2^0) = 1s
        mock_sleep.assert_any_call(2)  # Second retry: 1 * (2^1) = 2s

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_ssl_error_retry_exhausted(self, mock_sleep, mock_get):
        """Test SSL error retries are exhausted and original error is raised"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        mock_get.side_effect = [ssl_error, ssl_error, ssl_error]
        
        with pytest.raises(requests.exceptions.SSLError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 3
        assert mock_sleep.call_count == 2

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_connection_error_retry(self, mock_sleep, mock_get):
        """Test ConnectionError also triggers retry logic"""
        conn_error = requests.exceptions.ConnectionError("Connection failed")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        
        mock_get.side_effect = [conn_error, success_response]
        
        result = get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 2
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert mock_sleep.call_count == 1
        mock_sleep.assert_called_with(1)  # First retry: 1s

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_http_error_no_retry(self, mock_sleep, mock_get):
        """Test HTTP errors do NOT trigger retry logic (preserve existing behavior)"""
        error_response = self.mock_request(status=500)
        mock_get.return_value = error_response
        
        with pytest.raises(AuthClientError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.Session.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_ssl_error_with_session(self, mock_sleep, mock_session_get):
        """Test SSL error retry logic works with provided session"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        
        mock_session_get.side_effect = [ssl_error, success_response]
        session = requests.Session()
        
        result = get_discovery_doc('sandbox', session=session)
        
        assert mock_session_get.call_count == 2
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert mock_sleep.call_count == 1

    @mock.patch('intuitlib.utils.requests.get')
    def test_get_discovery_doc_normal_operation_no_delay(self, mock_get):
        """Test normal successful requests work without retries or delays"""
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        mock_get.return_value = success_response
        
        start_time = time.time()
        result = get_discovery_doc('sandbox')
        end_time = time.time()
        
        assert mock_get.call_count == 1
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        
        elapsed_time = end_time - start_time
        assert elapsed_time < 0.1  # Should be nearly instantaneous

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_mixed_errors(self, mock_sleep, mock_get):
        """Test mixed SSL and connection errors both trigger retries"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        conn_error = requests.exceptions.ConnectionError("Connection failed")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        
        mock_get.side_effect = [ssl_error, conn_error, success_response]
        
        result = get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 3
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(1)  # After first failure
        mock_sleep.assert_any_call(2)  # After second failure

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_different_ssl_error_types(self, mock_sleep, mock_get):
        """Test different types of SSL errors all trigger retries"""
        ssl_cert_error = requests.exceptions.SSLError("SSL: CERTIFICATE_VERIFY_FAILED")
        ssl_handshake_error = requests.exceptions.SSLError("SSL: SSLV3_ALERT_HANDSHAKE_FAILURE")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        
        mock_get.side_effect = [ssl_cert_error, ssl_handshake_error, success_response]
        
        result = get_discovery_doc('production')
        
        assert mock_get.call_count == 3
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert mock_sleep.call_count == 2

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_timeout_error_no_retry(self, mock_sleep, mock_get):
        """Test timeout errors do NOT trigger retry logic (current implementation)"""
        timeout_error = requests.exceptions.Timeout("Request timed out")
        mock_get.side_effect = [timeout_error]
        
        with pytest.raises(requests.exceptions.Timeout):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_different_connection_errors(self, mock_sleep, mock_get):
        """Test different types of connection errors trigger retries"""
        dns_error = requests.exceptions.ConnectionError("Name or service not known")
        refused_error = requests.exceptions.ConnectionError("Connection refused")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        
        mock_get.side_effect = [dns_error, refused_error, success_response]
        
        result = get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 3
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert mock_sleep.call_count == 2

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_multiple_http_status_codes_no_retry(self, mock_sleep, mock_get):
        """Test various HTTP error status codes don't trigger retries"""
        test_cases = [400, 401, 403, 404, 429, 500, 502, 503, 504]
        
        for status_code in test_cases:
            mock_get.reset_mock()
            mock_sleep.reset_mock()
            
            error_response = self.mock_request(status=status_code)
            mock_get.return_value = error_response
            
            with pytest.raises(AuthClientError):
                get_discovery_doc('sandbox')
            
            assert mock_get.call_count == 1, f"Status {status_code} should not retry"
            assert mock_sleep.call_count == 0, f"Status {status_code} should not sleep"

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_custom_url_retry(self, mock_sleep, mock_get):
        """Test retry logic works with custom discovery URLs"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://custom-accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        
        mock_get.side_effect = [ssl_error, success_response]
        
        custom_url = 'https://custom.intuit.com/.well-known/openid_configuration/'
        result = get_discovery_doc(custom_url)
        
        assert mock_get.call_count == 2
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert mock_sleep.call_count == 1

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_non_retryable_after_retryable(self, mock_sleep, mock_get):
        """Test non-retryable exception after retryable ones stops retry loop"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        value_error = ValueError("Invalid JSON response")
        
        mock_get.side_effect = [ssl_error, value_error]
        
        with pytest.raises(ValueError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 2
        assert mock_sleep.call_count == 1

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_exact_backoff_timing(self, mock_sleep, mock_get):
        """Test exact exponential backoff timing calculations"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        mock_get.side_effect = [ssl_error, ssl_error, ssl_error]
        
        with pytest.raises(requests.exceptions.SSLError):
            get_discovery_doc('sandbox')
        
        assert mock_sleep.call_count == 2
        expected_calls = [mock.call(1), mock.call(2)]
        mock_sleep.assert_has_calls(expected_calls, any_order=False)

    @mock.patch('intuitlib.utils.Session.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_invalid_session_object(self, mock_sleep, mock_session_get):
        """Test retry logic with invalid session object falls back to requests.get"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        
        with mock.patch('intuitlib.utils.requests.get') as mock_requests_get:
            success_response = self.mock_request(status=200, content={
                'issuer': 'https://oauth.platform.intuit.com/op/v1',
                'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
            })
            
            mock_requests_get.side_effect = [ssl_error, success_response]
            
            invalid_session = "not_a_session"
            result = get_discovery_doc('sandbox', session=invalid_session)
            
            assert mock_requests_get.call_count == 2
            assert mock_session_get.call_count == 0
            assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
            assert mock_sleep.call_count == 1

    @mock.patch('intuitlib.utils.requests.get')
    def test_get_discovery_doc_json_parsing_error_after_success(self, mock_get):
        """Test JSON parsing error after successful HTTP response"""
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response
        
        with pytest.raises(ValueError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_ssl_error_then_http_error(self, mock_sleep, mock_get):
        """Test SSL error followed by HTTP error - should not retry HTTP error"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        http_error_response = self.mock_request(status=500)
        
        mock_get.side_effect = [ssl_error, http_error_response]
        
        with pytest.raises(AuthClientError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 2
        assert mock_sleep.call_count == 1

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_http_error_then_ssl_error_no_retry(self, mock_sleep, mock_get):
        """Test HTTP error first - should not retry at all, even if SSL error would follow"""
        http_error_response = self.mock_request(status=404)
        mock_get.return_value = http_error_response
        
        with pytest.raises(AuthClientError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_environment_case_sensitivity(self, mock_sleep, mock_get):
        """Test retry logic works with different environment case variations"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        
        test_environments = ['PRODUCTION', 'Production', 'PROD', 'Prod', 'SANDBOX', 'Sandbox', 'SAND', 'Sand']
        
        for env in test_environments:
            mock_get.reset_mock()
            mock_sleep.reset_mock()
            mock_get.side_effect = [ssl_error, success_response]
            
            result = get_discovery_doc(env)
            
            assert mock_get.call_count == 2, f"Environment {env} should retry"
            assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
            assert mock_sleep.call_count == 1

    @mock.patch('intuitlib.utils.Session.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_session_ssl_error_exhausted(self, mock_sleep, mock_session_get):
        """Test session-based retry exhaustion with all SSL errors"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        mock_session_get.side_effect = [ssl_error, ssl_error, ssl_error]
        session = requests.Session()
        
        with pytest.raises(requests.exceptions.SSLError):
            get_discovery_doc('sandbox', session=session)
        
        assert mock_session_get.call_count == 3
        assert mock_sleep.call_count == 2

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_connection_error_exhausted(self, mock_sleep, mock_get):
        """Test connection error retry exhaustion"""
        conn_error = requests.exceptions.ConnectionError("Connection failed")
        mock_get.side_effect = [conn_error, conn_error, conn_error]
        
        with pytest.raises(requests.exceptions.ConnectionError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 3
        assert mock_sleep.call_count == 2

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_mixed_retryable_errors_exhausted(self, mock_sleep, mock_get):
        """Test mixed retryable errors all fail"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        conn_error = requests.exceptions.ConnectionError("Connection failed")
        ssl_error2 = requests.exceptions.SSLError("SSL: CERTIFICATE_VERIFY_FAILED")
        
        mock_get.side_effect = [ssl_error, conn_error, ssl_error2]
        
        with pytest.raises(requests.exceptions.SSLError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 3
        assert mock_sleep.call_count == 2

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_request_exception_no_retry(self, mock_sleep, mock_get):
        """Test generic RequestException does not trigger retries"""
        request_error = requests.exceptions.RequestException("Generic request error")
        mock_get.side_effect = [request_error]
        
        with pytest.raises(requests.exceptions.RequestException):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_http_error_no_retry(self, mock_sleep, mock_get):
        """Test HTTPError does not trigger retries"""
        http_error = requests.exceptions.HTTPError("HTTP error occurred")
        mock_get.side_effect = [http_error]
        
        with pytest.raises(requests.exceptions.HTTPError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_url_required_no_retry(self, mock_sleep, mock_get):
        """Test URLRequired does not trigger retries"""
        url_error = requests.exceptions.URLRequired("URL is required")
        mock_get.side_effect = [url_error]
        
        with pytest.raises(requests.exceptions.URLRequired):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_too_many_redirects_no_retry(self, mock_sleep, mock_get):
        """Test TooManyRedirects does not trigger retries"""
        redirect_error = requests.exceptions.TooManyRedirects("Too many redirects")
        mock_get.side_effect = [redirect_error]
        
        with pytest.raises(requests.exceptions.TooManyRedirects):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_keyboard_interrupt_no_retry(self, mock_sleep, mock_get):
        """Test KeyboardInterrupt is not caught by retry logic"""
        keyboard_interrupt = KeyboardInterrupt("User interrupted")
        mock_get.side_effect = [keyboard_interrupt]
        
        with pytest.raises(KeyboardInterrupt):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_system_exit_no_retry(self, mock_sleep, mock_get):
        """Test SystemExit is not caught by retry logic"""
        system_exit = SystemExit("System exit")
        mock_get.side_effect = [system_exit]
        
        with pytest.raises(SystemExit):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_empty_response_content(self, mock_sleep, mock_get):
        """Test successful response with empty/None content"""
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response
        
        result = get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert result == {}
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_malformed_json_response(self, mock_sleep, mock_get):
        """Test response with malformed JSON after successful HTTP"""
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "doc", 0)
        mock_get.return_value = mock_response
        
        with pytest.raises(json.JSONDecodeError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_chunked_encoding_error_no_retry(self, mock_sleep, mock_get):
        """Test ChunkedEncodingError does not trigger retries"""
        chunked_error = requests.exceptions.ChunkedEncodingError("Connection broken: Invalid chunk encoding")
        mock_get.side_effect = [chunked_error]
        
        with pytest.raises(requests.exceptions.ChunkedEncodingError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_content_decoding_error_no_retry(self, mock_sleep, mock_get):
        """Test ContentDecodingError does not trigger retries"""
        decoding_error = requests.exceptions.ContentDecodingError("Failed to decode response content")
        mock_get.side_effect = [decoding_error]
        
        with pytest.raises(requests.exceptions.ContentDecodingError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_stream_consumed_error_no_retry(self, mock_sleep, mock_get):
        """Test StreamConsumedError does not trigger retries"""
        stream_error = requests.exceptions.StreamConsumedError("The content for this response was already consumed")
        mock_get.side_effect = [stream_error]
        
        with pytest.raises(requests.exceptions.StreamConsumedError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_retry_error_no_retry(self, mock_sleep, mock_get):
        """Test RetryError does not trigger retries"""
        retry_error = requests.exceptions.RetryError("Max retries exceeded")
        mock_get.side_effect = [retry_error]
        
        with pytest.raises(requests.exceptions.RetryError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_unwindable_body_error_no_retry(self, mock_sleep, mock_get):
        """Test UnrewindableBodyError does not trigger retries"""
        unwindable_error = requests.exceptions.UnrewindableBodyError("The file-like object could not be rewound")
        mock_get.side_effect = [unwindable_error]
        
        with pytest.raises(requests.exceptions.UnrewindableBodyError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_ssl_error_with_none_session(self, mock_sleep, mock_get):
        """Test retry logic with explicitly None session"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        success_response = self.mock_request(status=200, content={
            'issuer': 'https://oauth.platform.intuit.com/op/v1',
            'userinfo_endpoint': 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo'
        })
        
        mock_get.side_effect = [ssl_error, success_response]
        
        result = get_discovery_doc('sandbox', session=None)
        
        assert mock_get.call_count == 2
        assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
        assert mock_sleep.call_count == 1

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_boundary_max_retries_verification(self, mock_sleep, mock_get):
        """Test exact boundary condition of max_retries = 3"""
        ssl_error = requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        mock_get.side_effect = [ssl_error, ssl_error, ssl_error, ssl_error]
        
        with pytest.raises(requests.exceptions.SSLError):
            get_discovery_doc('sandbox')
        
        assert mock_get.call_count == 3
        assert mock_sleep.call_count == 2
        expected_calls = [mock.call(1), mock.call(2)]
        mock_sleep.assert_has_calls(expected_calls, any_order=False)

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_ssl_error_types_comprehensive(self, mock_sleep, mock_get):
        """Test comprehensive SSL error types all trigger retries"""
        ssl_errors = [
            requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING"),
            requests.exceptions.SSLError("SSL: CERTIFICATE_VERIFY_FAILED"),
            requests.exceptions.SSLError("SSL: SSLV3_ALERT_HANDSHAKE_FAILURE"),
            requests.exceptions.SSLError("SSL: WRONG_VERSION_NUMBER"),
            requests.exceptions.SSLError("SSL: BAD_RECORD_MAC"),
            requests.exceptions.SSLError("SSL: TLSV1_ALERT_PROTOCOL_VERSION")
        ]
        
        for ssl_error in ssl_errors:
            mock_get.reset_mock()
            mock_sleep.reset_mock()
            
            success_response = self.mock_request(status=200, content={
                'issuer': 'https://oauth.platform.intuit.com/op/v1'
            })
            mock_get.side_effect = [ssl_error, success_response]
            
            result = get_discovery_doc('sandbox')
            
            assert mock_get.call_count == 2, f"SSL error {ssl_error} should trigger retry"
            assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
            assert mock_sleep.call_count == 1

    @mock.patch('intuitlib.utils.requests.get')
    @mock.patch('intuitlib.utils.time.sleep')
    def test_get_discovery_doc_connection_error_types_comprehensive(self, mock_sleep, mock_get):
        """Test comprehensive connection error types all trigger retries"""
        connection_errors = [
            requests.exceptions.ConnectionError("Connection refused"),
            requests.exceptions.ConnectionError("Name or service not known"),
            requests.exceptions.ConnectionError("Network is unreachable"),
            requests.exceptions.ConnectionError("Connection timed out"),
            requests.exceptions.ConnectionError("No route to host"),
            requests.exceptions.ConnectionError("Connection reset by peer")
        ]
        
        for conn_error in connection_errors:
            mock_get.reset_mock()
            mock_sleep.reset_mock()
            
            success_response = self.mock_request(status=200, content={
                'issuer': 'https://oauth.platform.intuit.com/op/v1'
            })
            mock_get.side_effect = [conn_error, success_response]
            
            result = get_discovery_doc('sandbox')
            
            assert mock_get.call_count == 2, f"Connection error {conn_error} should trigger retry"
            assert result['issuer'] == 'https://oauth.platform.intuit.com/op/v1'
            assert mock_sleep.call_count == 1

    def test_scopes_to_string_input_string(self):
        with pytest.raises(TypeError):
            scopes_to_string('openid')

    def test_scopes_to_string_input_list(self):
        with pytest.raises(TypeError):
            scopes_to_string(['openid'])

    def test_scopes_to_string_input_correct(self):
        scope = scopes_to_string([Scopes.OPENID, Scopes.EMAIL])  
        
        assert scope == 'openid email'

    def test_set_attributes(self):
        response = {
            'refresh_token': 'testrefresh',
            'access_token': 'testaccess',
            'test': 'testing',
            'id_token': 'token'
        }
        set_attributes(self.auth_client, response)
        
        assert self.auth_client.refresh_token == response['refresh_token']
        assert self.auth_client.access_token == response['access_token']
        assert not self.auth_client.id_token
    
    @mock.patch('intuitlib.utils.requests.request')
    def test_send_request_bad_request(self, mock_post):
        mock_resp = self.mock_request(status=400)
        mock_post.return_value = mock_resp

        with pytest.raises(AuthClientError):
            send_request('POST', 'url', {}, '', body={})

    @mock.patch('intuitlib.utils.requests.request')
    def test_send_request_ok(self, mock_post):
        mock_resp = self.mock_request(status=200, content={'access_token': 'testaccess'})
        mock_post.return_value = mock_resp

        send_request('POST', 'url', {}, self.auth_client, body={})
        assert self.auth_client.access_token == 'testaccess'
    
    @mock.patch('intuitlib.utils.Session.request')
    def test_send_request_session_ok(self, mock_post):
        mock_resp = self.mock_request(status=200, content={'access_token': 'testaccess'})
        mock_post.return_value = mock_resp
        session = requests.Session()

        send_request('POST', 'url', {}, self.auth_client, body={}, session=session)
        assert self.auth_client.access_token == 'testaccess'

    @mock.patch('intuitlib.utils.Session.request')
    def test_send_request_session_bad(self, mock_post):
        mock_resp = self.mock_request(status=400, content={'access_token': 'testaccess'})
        mock_post.return_value = mock_resp
        session = requests.Session()

        with pytest.raises(AuthClientError):
            send_request('POST', 'url', {}, self.auth_client, body={}, session=session)

    def test_generate_token(self):
        token = generate_token()

        assert len(token) == 30

    @mock.patch('intuitlib.utils.requests.get')
    def test_get_jwk_bad_request(self, mock_get):
        mock_resp = self.mock_request(status=400)
        mock_get.return_value = mock_resp

        with pytest.raises(AuthClientError):
            get_jwk('', 'test_uri')
    
    def test_validate_id_token_bad_idtoken(self):
        id_token = 'firstcomp.secondcomp'
        client_id = 'test'
        intuit_issuer = 'test'
        jwk_uri = 'test_uri'

        is_valid = validate_id_token(id_token, client_id, intuit_issuer, jwk_uri)
        assert not is_valid

    def test_validate_id_token_bad_issuer(self):
        sample_id_token = 'eyJraWQiOiJyNHA1U2JMMnFhRmVoRnpoajhnSSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJiMDUzZDk5NC0wN2Q1LTQ2OGQtYjdlZS0yMmUzNDlkMmU3MzkiLCJhdWQiOlsiTDM5ZWxTdWJGeGpQT1NwZFpvWVdSS2lDQ0U2VElOanY2N1JvYUU4ekJxYkl4eGI0bEsiXSwicmVhbG1pZCI6IjExMDgwMzM0NzEiLCJhdXRoX3RpbWUiOjE0NjI1NTQ0NzUsImlzcyI6Imh0dHBzOlwvXC9vYXV0aC1lMmUucGxhdGZvcm0uaW50dWl0LmNvbVwvb2F1dGgyXC92MVwvb3BcL3YxIiwiZXhwIjoxNDYyNTYxMzI4LCJpYXQiOjE0NjI1NTc3Mjh9.BIJ9x_WPEOZsLJfQE3mGji_Q15j_rdlTyFYELiJM-W92fWSLC-TLEwCp5IrRhDWMvyvrLSMZCEdQALYQpbVy8uKI22JgGWYvkwNEDweOjbYzyt33F4xtn3GGcW9nAwRtA3M19qquWyi7G0kcCZUDN8RfUXz2qKMJ6KPOfLVe2UQ'
        client_id = 'test'
        intuit_issuer = 'test'
        jwk_uri = 'test_uri'

        is_valid = validate_id_token(sample_id_token, client_id, intuit_issuer, jwk_uri)
        assert not is_valid 

if __name__ == '__main__':
    pytest.main()
