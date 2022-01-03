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

import type { JWK } from 'jose';

import type {
	GrantType,
	JWEAlgorithm,
	JWEEncryption,
	ResponseType,
	SigningAlgorithm,
	SubjectType,
	TokenAuthMethod,
} from '../discovery';
import {
	isGrantType,
	isJWEAlgorithm,
	isJWEEncryption,
	isResponseType,
	isSigningAlgorithm,
	isSubjectType,
	isTokenAuthMethod,
} from '../discovery';

export type AppType = 'native' | 'web';

export interface ClientError {
	error: string;
	error_description?: string;
}

// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
export interface ClientMetadata {
	// REQUIRED
	redirectUris: string[];
	// OPTIONAL, defaults to `['code']`
	responseTypes: ResponseType[];
	// OPTIONAL
	grantTypes?: GrantType[];
	// OPTIONAL, defaults to `'web'`
	//
	// Web clients MUST only use `https:` as the scheme and MUST not use `localhost` as the hostname.
	// Native clients MUST only use custom URI schemes or URLs using the `http:` scheme with `localhost` as the hostname.
	applicationType: AppType;
	// OPTIONAL
	contacts?: string[];
	// OPTIONAL
	clientName?: string;
	// OPTIONAL
	logoUri?: string;
	// OPTIONAL
	clientUri?: string;
	// OPTIONAL
	policyUri?: string;
	// OPTIONAL
	tosUri?: string;
	// OPTIONAL, mutually exclusive with `jwks`
	jwksUri?: string;
	// OPTIONAL, mutually exclusive with `jwksUri`
	jwks?: JWK[];
	// OPTIONAL
	sectorIdentifierUri?: string;
	// OPTIONAL
	subjectType?: SubjectType;
	// OPTIONAL
	idTokenSignedResponseAlg: SigningAlgorithm;
	// OPTIONAL
	idTokenEncryptedResponseAlg?: JWEAlgorithm;
	// OPTIONAL
	idTokenEncryptedResponseEnc?: JWEEncryption;
	// OPTIONAL
	userinfoSignedResponseAlg?: SigningAlgorithm;
	// OPTIONAL
	userinfoEncryptedResponseAlg?: JWEAlgorithm;
	// OPTIONAL
	userinfoEncryptedResponseEnc?: JWEEncryption;
	// OPTIONAL
	requestObjectSigningAlg?: SigningAlgorithm;
	// OPTIONAL
	requestObjectEncryptionAlg?: JWEAlgorithm;
	// OPTIONAL
	requestObjectEncryptionEnc?: JWEEncryption;
	// OPTIONAL
	tokenEndpointAuthMethod: TokenAuthMethod;
	// OPTIONAL
	tokenEndpointAuthSigningAlg?: SigningAlgorithm;
	// OPTIONAL
	defaultMaxAge?: number;
	// OPTIONAL, defaults to `false`.
	requireAuthTime: boolean;
	// OPTIONAL
	defaultAcrValues?: string[];
	// OPTIONAL
	initiateLoginUri?: string;
	// OPTIONAL
	requestUris?: string[];
}

export type Client = ClientMetadata & {
	clientId: string;
	clientIdIssuedAt: Date;
	clientSecret?: string;
	clientSecretExpiresAt?: Date;
};

function isBoolean(x: any): boolean {
	return typeof x === 'boolean';
}

function isNumber(x: any): boolean {
	return typeof x === 'number';
}

function isString(x: any): boolean {
	return typeof x === 'string';
}

function validateUri(uri: string): URL | undefined {
	try {
		return new URL(uri);
	} catch {
		return undefined;
	}
}

function isUri(x: any): boolean {
	return isString(x) && validateUri(x as string) !== undefined;
}

function validateArray<T>(
	body: Record<string, unknown>,
	field: string,
	validator: (x: any) => boolean,
): T[] | ClientError | undefined {
	if (!(field in body)) {
		return undefined;
	}

	const value = body[field];
	if (!Array.isArray(value)) {
		return {
			error: 'invalid_client_metadata',
			error_description: `${field} must be an array`,
		};
	}

	if (!value.every(v => validator(v))) {
		return {
			error: 'invalid_client_metadata',
			error_description: `invalid type in ${field} array`,
		};
	}

	// Check for any duplicate values.
	if (new Set(value).size !== value.length) {
		return {
			error: 'invalid_client_metadata',
			error_description: `duplicate entries in ${field} array`,
		};
	}

	return value as T[];
}

function validateField<T>(
	body: Record<string, unknown>,
	field: string,
	validator: (x: any) => boolean,
	defaultValue: T,
	// eslint-disable-next-line @typescript-eslint/ban-types
): T | null {
	if (!(field in body)) {
		return defaultValue;
	}

	const value = body[field];
	if (!validator(value)) {
		return null;
	}

	return value as T;
}

type RedirectUriValidator = (url: URL) => ClientError | undefined;

function validateWebRedirectUri(url: URL): ClientError | undefined {
	if (url.protocol !== 'https:') {
		return {
			error: 'invalid_redirect_uri',
			error_description: `"${url.toString()}" must use "https" as the scheme`,
		};
	}

	if (url.hostname === 'localhost') {
		return {
			error: 'invalid_redirect_uri',
			error_description: `"${url.toString()}" must not use "localhost" as a hostname`,
		};
	}

	return undefined;
}

function validateNativeRedirectUri(url: URL): ClientError | undefined {
	if (url.protocol === 'https:') {
		return {
			error: 'invalid_redirect_uri',
			error_description: `"${url.toString()}" must not use "https" as the scheme`,
		};
	}

	if (url.protocol === 'http:' && url.hostname !== 'localhost') {
		return {
			error: 'invalid_redirect_uri',
			error_description: `"${url.toString()}" may only use "localhost" as a hostname with the "http" scheme`,
		};
	}

	return undefined;
}

function validateRedirectUris(
	appType: AppType,
	body: Record<string, unknown>,
): ClientError | string[] {
	const _redirectUris = validateArray<string>(body, 'redirect_uris', isString);
	if (_redirectUris === undefined) {
		return {
			error: 'invalid_request',
			error_description: 'missing required parameter(s) redirect_uris',
		};
	}

	if ('error' in _redirectUris) {
		return _redirectUris;
	}

	const _redirectUrls: URL[] = [];
	for (const redirectUri of _redirectUris) {
		const uri = validateUri(redirectUri);
		if (uri === undefined) {
			return {
				error: 'invalid_redirect_uri',
				error_description: `"${redirectUri}" is not a valid redirect uri`,
			};
		}

		_redirectUrls.push(uri);
	}

	let validator: RedirectUriValidator;
	switch (appType) {
		case 'native':
			validator = validateNativeRedirectUri;
			break;
		case 'web':
			validator = validateWebRedirectUri;
			break;
		default:
			return {
				error: 'invalid_client_metadata',
				error_description: 'unknown application_type',
			};
	}

	for (const redirectUrl of _redirectUrls) {
		const error = validator(redirectUrl);
		if (error !== undefined) {
			return error;
		}
	}

	return _redirectUrls.map(url => url.toString());
}

export function getClientRegistrationBody(
	body: Record<string, unknown>,
): ClientMetadata | ClientError {
	let appType: AppType = 'web';
	if (body.application_type !== undefined && body.application_type === 'native') {
		appType = 'native';
	}

	const redirectUris = validateRedirectUris(appType, body);
	if ('error' in redirectUris) {
		return redirectUris;
	}

	const responseTypes = validateArray<ResponseType>(body, 'response_types', isResponseType) ?? [
		'code',
	];
	if ('error' in responseTypes) {
		return responseTypes;
	}

	const grantTypes = validateArray<GrantType>(body, 'grant_types', isGrantType);
	if (grantTypes !== undefined && 'error' in grantTypes) {
		return grantTypes;
	}

	// TODO: find a way to normalize all emails before validating the array
	// so the duplicate value check is properly followed.
	const contacts = validateArray<string>(body, 'contacts', isString);
	if (contacts !== undefined && 'error' in contacts) {
		return contacts;
	}

	const clientName = validateField<string | undefined>(body, 'client_name', isString, undefined);
	if (clientName === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'client_name must be a string',
		};
	}

	const logoUri = validateField<string | undefined>(body, 'logo_uri', isUri, undefined);
	if (logoUri === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'logo_uri must be a uri',
		};
	}

	const clientUri = validateField<string | undefined>(body, 'client_uri', isUri, undefined);
	if (clientUri === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'client_uri must be a uri',
		};
	}

	const policyUri = validateField<string | undefined>(body, 'policy_uri', isUri, undefined);
	if (policyUri === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'policy_uri must be a uri',
		};
	}

	const tosUri = validateField<string | undefined>(body, 'tos_uri', isUri, undefined);
	if (tosUri === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'tos_uri must be a uri',
		};
	}

	const jwksUri = validateField<string | undefined>(body, 'jwks_uri', isUri, undefined);
	if (jwksUri === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'jwks_uri must be a uri',
		};
	}

	const sectorIdentifierUri = validateField<string | undefined>(
		body,
		'sector_identifier_uri',
		isUri,
		undefined,
	);
	if (sectorIdentifierUri === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'sector_identifier_uri must be a uri',
		};
	}

	const subjectType = validateField<SubjectType | undefined>(
		body,
		'subject_type',
		isSubjectType,
		undefined,
	);
	if (subjectType === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid subject_type',
		};
	}

	const idTokenSignedResponseAlg = validateField<SigningAlgorithm>(
		body,
		'id_token_signed_response_alg',
		isSigningAlgorithm,
		'RS256',
	);
	if (idTokenSignedResponseAlg === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid id_token_signed_response_alg',
		};
	}

	const idTokenEncryptedResponseAlg = validateField<JWEAlgorithm | undefined>(
		body,
		'id_token_encrypted_response_alg',
		isJWEAlgorithm,
		undefined,
	);
	if (idTokenEncryptedResponseAlg === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid id_token_encrypted_response_alg',
		};
	}

	const idTokenEncryptedResponseEnc = validateField<JWEEncryption | undefined>(
		body,
		'id_token_encrypted_response_enc',
		isJWEEncryption,
		undefined,
	);
	if (idTokenEncryptedResponseEnc === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid id_token_encrypted_response_enc',
		};
	}

	const userinfoSignedResponseAlg = validateField<SigningAlgorithm | undefined>(
		body,
		'userinfo_signed_response_alg',
		isSigningAlgorithm,
		undefined,
	);
	if (userinfoSignedResponseAlg === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid userinfo_signed_response_alg',
		};
	}

	const userinfoEncryptedResponseAlg = validateField<JWEAlgorithm | undefined>(
		body,
		'userinfo_encrypted_response_alg',
		isJWEAlgorithm,
		undefined,
	);
	if (userinfoEncryptedResponseAlg === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid userinfo_encrypted_response_alg',
		};
	}

	const userinfoEncryptedResponseEnc = validateField<JWEEncryption | undefined>(
		body,
		'userinfo_encrypted_response_enc',
		isJWEEncryption,
		undefined,
	);
	if (userinfoEncryptedResponseEnc === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid userinfo_encrypted_response_enc',
		};
	}

	const requestObjectSigningAlg = validateField<SigningAlgorithm | undefined>(
		body,
		'request_object_signing_alg',
		isSigningAlgorithm,
		undefined,
	);
	if (requestObjectSigningAlg === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid request_object_signing_alg',
		};
	}

	const requestObjectEncryptionAlg = validateField<JWEAlgorithm | undefined>(
		body,
		'request_object_encryption_alg',
		isJWEAlgorithm,
		undefined,
	);
	if (requestObjectEncryptionAlg === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid request_object_encryption_alg',
		};
	}

	const requestObjectEncryptionEnc = validateField<JWEEncryption | undefined>(
		body,
		'request_object_encryption_enc',
		isJWEEncryption,
		undefined,
	);
	if (requestObjectEncryptionEnc === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid request_object_encryption_enc',
		};
	}

	const tokenEndpointAuthMethod = validateField<TokenAuthMethod>(
		body,
		'token_endpoint_auth_method',
		isTokenAuthMethod,
		'client_secret_basic',
	);
	if (tokenEndpointAuthMethod === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid token_endpoint_auth_method',
		};
	}

	const tokenEndpointAuthSigningAlg = validateField<SigningAlgorithm | undefined>(
		body,
		'token_endpoint_auth_signing_alg',
		isSigningAlgorithm,
		undefined,
	);
	if (tokenEndpointAuthSigningAlg === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'invalid token_endpoint_auth_signing_alg',
		};
	}

	const requireAuthTime = validateField<boolean>(body, 'require_auth_time', isBoolean, false);
	if (requireAuthTime === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'require_auth_time must be a boolean',
		};
	}

	const defaultMaxAge = validateField<number | undefined>(
		body,
		'default_max_age',
		isNumber,
		undefined,
	);
	if (defaultMaxAge === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'default_max_age must be an integer',
		};
	}

	// TODO: add a type and properly validate.
	const defaultAcrValues = validateArray<string>(body, 'default_acr_values', isString);
	if (defaultAcrValues !== undefined && 'error' in defaultAcrValues) {
		return defaultAcrValues;
	}

	const initiateLoginUri = validateField<string | undefined>(
		body,
		'initiate_login_uri',
		isUri,
		undefined,
	);
	if (initiateLoginUri === null) {
		return {
			error: 'invalid_client_metadata',
			error_description: 'initiate_login_uri must be a uri',
		};
	}

	const requestUris = validateArray<string>(body, 'request_uris', isUri);
	if (requestUris !== undefined && 'error' in requestUris) {
		return requestUris;
	}

	return {
		redirectUris,
		responseTypes,
		grantTypes,
		applicationType: appType,
		contacts,
		clientName,
		logoUri,
		clientUri,
		policyUri,
		tosUri,
		jwksUri,
		// TODO: jwks
		sectorIdentifierUri,
		subjectType,
		idTokenSignedResponseAlg,
		idTokenEncryptedResponseAlg,
		idTokenEncryptedResponseEnc,
		userinfoSignedResponseAlg,
		userinfoEncryptedResponseAlg,
		userinfoEncryptedResponseEnc,
		requestObjectSigningAlg,
		requestObjectEncryptionAlg,
		requestObjectEncryptionEnc,
		tokenEndpointAuthMethod,
		tokenEndpointAuthSigningAlg,
		defaultMaxAge,
		requireAuthTime,
		defaultAcrValues,
		initiateLoginUri,
		requestUris,
	};
}

export function getClientResponse(client: Client): Record<string, unknown> {
	return {
		redirect_uris: client.redirectUris,
		response_types: client.responseTypes,
		grant_types: client.grantTypes,
		application_type: client.applicationType,
		contacts: client.contacts,
		client_name: client.clientName,
		logo_uri: client.logoUri,
		client_uri: client.clientUri,
		policy_uri: client.policyUri,
		tos_uri: client.tosUri,
		jwks_uri: client.jwksUri,
		jwks: client.jwks,
		sector_identifier_uri: client.sectorIdentifierUri,
		subject_type: client.subjectType,
		id_token_signed_response_alg: client.idTokenSignedResponseAlg,
		id_token_encrypted_response_alg: client.idTokenEncryptedResponseAlg,
		id_token_encrypted_response_enc: client.idTokenEncryptedResponseEnc,
		userinfo_signed_response_alg: client.userinfoSignedResponseAlg,
		userinfo_encrypted_response_alg: client.userinfoEncryptedResponseAlg,
		userinfo_encrypted_response_enc: client.userinfoEncryptedResponseEnc,
		request_object_signing_alg: client.requestObjectSigningAlg,
		request_object_encryption_alg: client.requestObjectEncryptionAlg,
		request_object_encryption_enc: client.requestObjectEncryptionEnc,
		token_endpoint_auth_method: client.tokenEndpointAuthMethod,
		token_endpoint_auth_signing_alg: client.tokenEndpointAuthSigningAlg,
		default_max_age: client.defaultMaxAge,
		require_auth_time: client.requireAuthTime,
		default_acr_values: client.defaultAcrValues,
		initiate_login_uri: client.initiateLoginUri,
		request_uris: client.requestUris,

		client_id: client.clientId,
		client_id_issued_at: Math.ceil(client.clientIdIssuedAt.getTime() / 1000),
		client_secret: client.clientSecret,
		client_secret_expires_at:
			client.clientSecretExpiresAt === undefined
				? undefined
				: Math.ceil(client.clientSecretExpiresAt.getTime() / 1000),
	};
}
