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

export type { AuthorizationCode } from './authorization-code';
export type {
	ClaimType,
	DisplayValue,
	GrantType,
	JWEAlgorithm,
	JWEEncryption,
	ResponseMode,
	ResponseType,
	SigningAlgorithm,
	SubjectType,
	TokenAuthMethod,
} from './discovery';
export { getConfiguration } from './discovery';
export type { AuthorizationError, TokenError } from './error';
export type { ChallengeMethod } from './pkce';
export { verifyChallenge } from './pkce';
export type {
	AuthRequestQuery,
	Client,
	ClientError,
	ClientMetadata,
	TokenAuthorization,
	TokenRequestBody,
} from './request';
export {
	getAuthRequestQuery,
	getClientRegistrationBody,
	getClientResponse,
	getTokenRequestBody,
	parseTokenAuthorization,
} from './request';
export type { StorageProvider } from './storage';
export { durableObjectStorageProvider } from './storage';
