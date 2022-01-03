//
// Copyright (c) 2021 Matthew Penner
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

// https://openid.net/specs/openid-connect-discovery-1_0.html

import type { ChallengeMethod } from '../pkce';

export const JWE_ALGORITHMS = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'] as const;
export type JWEAlgorithm = typeof JWE_ALGORITHMS[number];
export const isJWEAlgorithm = (x: any): x is JWEAlgorithm => JWE_ALGORITHMS.includes(x);

export const JWE_ENCRYPTIONS = [
	'A128GCM',
	'A192GCM',
	'A256GCM',
	'A128CBC-HS256',
	'A192CBC-HS384',
	'A256CBC-HS512',
] as const;
export type JWEEncryption = typeof JWE_ENCRYPTIONS[number];
export const isJWEEncryption = (x: any): x is JWEEncryption => JWE_ENCRYPTIONS.includes(x);

export const SIGNING_ALGORITHMS = [
	'ES256',
	'ES384',
	'ES512',
	'PS256',
	'PS384',
	'PS512',
	'RS256',
	'RS384',
	'RS512',
	'EdDSA',
	'none',
] as const;
export type SigningAlgorithm = typeof SIGNING_ALGORITHMS[number];
export const isSigningAlgorithm = (x: any): x is SigningAlgorithm => SIGNING_ALGORITHMS.includes(x);

export const CLAIM_TYPES = ['aggregated', 'distributed', 'normal'] as const;
export type ClaimType = typeof CLAIM_TYPES[number];
export const isClaimType = (x: any): x is ClaimType => CLAIM_TYPES.includes(x);

export const GRANT_TYPES = ['authorization_code', 'implicit', 'refresh_token'] as const;
export type GrantType = typeof GRANT_TYPES[number];
export const isGrantType = (x: any): x is GrantType => GRANT_TYPES.includes(x);

const DISPLAY_VALUES = ['page', 'popup', 'touch', 'wap'] as const;
export type DisplayValue = typeof DISPLAY_VALUES[number];
export const isDisplayValue = (x: any): x is DisplayValue => DISPLAY_VALUES.includes(x);

export const RESPONSE_MODES = ['fragment', 'query'] as const;
export type ResponseMode = typeof RESPONSE_MODES[number];
export const isResponseMode = (x: any): x is ResponseMode => RESPONSE_MODES.includes(x);

export const RESPONSE_TYPES = [
	'code',
	'id_token',
	'id_token token',
	'code id_token',
	'code id_token token',
] as const;
export type ResponseType = typeof RESPONSE_TYPES[number];
export const isResponseType = (x: any): x is ResponseType => RESPONSE_TYPES.includes(x);

export const SUBJECT_TYPES = ['pairwise', 'public'] as const;
export type SubjectType = typeof SUBJECT_TYPES[number];
export const isSubjectType = (x: any): x is SubjectType => SUBJECT_TYPES.includes(x);

export const TOKEN_AUTH_METHODS = [
	'client_secret_basic',
	'client_secret_post',
	'client_secret_jwt',
	'private_key_jwt',
	'none',
] as const;
export type TokenAuthMethod = typeof TOKEN_AUTH_METHODS[number];
export const isTokenAuthMethod = (x: any): x is TokenAuthMethod => TOKEN_AUTH_METHODS.includes(x);

export interface Configuration {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint?: string;
	jwks_uri: string;
	registration_endpoint?: string;
	scopes_supported?: string[];
	response_types_supported: ResponseType[];
	response_modes_supported?: ResponseMode[];
	grant_types_supported?: GrantType[];
	acr_values_supported?: string[];
	subject_types_supported: SubjectType[];
	id_token_signing_alg_values_supported: SigningAlgorithm[];
	id_token_encryption_alg_values_supported?: JWEAlgorithm[];
	id_token_encryption_enc_values_supported?: JWEEncryption[];
	userinfo_signing_alg_values_supported?: SigningAlgorithm[];
	userinfo_encryption_alg_values_supported?: JWEAlgorithm[];
	userinfo_encryption_enc_values_supported?: JWEEncryption[];
	request_object_signing_alg_values_supported?: SigningAlgorithm[];
	request_object_encryption_alg_values_supported?: JWEAlgorithm[];
	request_object_encryption_enc_values_supported?: JWEEncryption[];
	token_endpoint_auth_methods_supported?: TokenAuthMethod[];
	token_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
	display_values_supported?: DisplayValue[];
	claim_types_supported?: ClaimType[];
	claims_supported?: string[];
	service_documentation?: string;
	claims_locales_supported?: string[];
	ui_locales_supported?: string[];
	claims_parameter_supported?: boolean;
	request_parameter_supported?: boolean;
	request_uri_parameter_supported?: boolean;
	require_request_uri_registration?: boolean;
	op_policy_uri?: string;
	op_tos_uri?: string;

	// PKCE
	code_challenge_methods_supported?: ChallengeMethod[];

	// NON-OFFICIAL FIELDS
	introspection_endpoint?: string;
	end_session_endpoint?: string;
	revocation_endpoint?: string;
	revocation_endpoint_auth_methods_supported?: string[];
	revocation_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
}

export function getConfiguration(issuer: string): Configuration {
	return {
		issuer,
		authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
		token_endpoint: `${issuer}/protocol/openid-connect/token`,
		userinfo_endpoint: `${issuer}/protocol/openid-connect/userinfo`,
		jwks_uri: `${issuer}/protocol/openid-connect/certs`,
		registration_endpoint: `${issuer}/client-registrations/openid-connect`,
		scopes_supported: ['openid'],
		response_types_supported: [
			'code',
			'id_token',
			'id_token token',
			'code id_token',
			'code id_token token',
		],
		grant_types_supported: ['authorization_code'],
		subject_types_supported: ['public'],
		id_token_signing_alg_values_supported: [
			// 'ES256',
			// 'ES384',
			// 'ES512',
			// 'PS256',
			// 'PS384',
			// 'PS512',
			'RS256',
			// 'RS384',
			// 'RS512',
			// 'EdDSA',
		],
		token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
		claims_supported: [
			'aud',
			'exp',
			'iat',
			'iss',
			'sub',
			'email',
			'preferred_username',
			'name',
			'given_name',
			'family_name',
			'groups',
		],

		code_challenge_methods_supported: ['plain', 'S256'],

		// introspection_endpoint: `${issuer}/protocol/openid-connect/token/introspect`,
		// revocation_endpoint: `${issuer}/protocol/openid-connect/revoke`,
		// revocation_endpoint_auth_methods_supported: [
		// 	'private_key_jwt',
		// 	'client_secret_basic',
		// 	'client_secret_post',
		// 	'tls_client_auth',
		// 	'client_secret_jwt',
		// ],
		// revocation_endpoint_auth_signing_alg_values_supported: ['RS256'],
	};
}
