//
// Copyright (c) 2022 Matthew Penner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

export interface TokenError {
	error: string;
	error_description?: string;
	error_uri?: string;
}

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
export interface AuthorizationError {
	error:
		| 'access_denied'
		| 'invalid_request'
		| 'invalid_scope'
		| 'server_error'
		| 'temporarily_unavailable'
		| 'unauthorized_client'
		| 'unsupported_response_type'
		// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
		| 'interaction_required'
		| 'login_required'
		| 'account_selection_required'
		| 'consent_required'
		| 'invalid_request_uri'
		| 'invalid_request_object'
		| 'request_not_supported'
		| 'request_uri_not_supported'
		| 'registration_not_supported';
	error_description?: string;
	error_uri?: string;
	state?: string;

	// This is used internally for redirecting the request.
	redirectUri?: string;
}
