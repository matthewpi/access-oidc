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

type KeyLike = { type: string };

interface JWK {
	[propName: string]: unknown;

	alg?: string;
	crv?: string;
	d?: string;
	dp?: string;
	dq?: string;
	e?: string;
	ext?: boolean;
	k?: string;
	key_ops?: string[];
	kid?: string;
	kty?: string;
	n?: string;
	oth?: Array<{
		d?: string;
		r?: string;
		t?: string;
	}>;
	p?: string;
	q?: string;
	qi?: string;
	use?: string;
	x?: string;
	y?: string;
	x5c?: string[];
	x5t?: string;
	'x5t#S256'?: string;
	x5u?: string;
}

interface JWTPayload {
	[propName: string]: unknown;

	iss?: string;
	sub?: string;
	aud?: string | string[];
	jti?: string;
	nbf?: number;
	exp?: number;
	iat?: number;
}

interface JWTVerifyResult {
	payload: JWTPayload;
	protectedHeader: JWTHeaderParameters;
}

interface JoseHeaderParameters {
	kid?: string;
	x5t?: string;
	x5c?: string[];
	x5u?: string;
	jku?: string;
	jwk?: Pick<JWK, 'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'>;
	typ?: string;
	cty?: string;
}

interface JWSHeaderParameters extends JoseHeaderParameters {
	[propName: string]: unknown;

	alg?: string;
	b64?: boolean;
	crit?: string[];
}

interface CompactJWSHeaderParameters extends JWSHeaderParameters {
	alg: string;
}

interface JWTHeaderParameters extends CompactJWSHeaderParameters {
	b64?: true;
}

interface FlattenedJWSInput {
	header?: JWSHeaderParameters;
	payload: string | Uint8Array;
	protected?: string;
	signature: string;
}

type GetKeyFunction<T, T2> = (protectedHeader: T, token: T2) => Promise<KeyLike | Uint8Array>;

interface CritOption {
	crit?: Record<string, boolean>;
}

interface VerifyOptions extends CritOption {
	algorithms?: string[];
}

interface JWTClaimVerificationOptions {
	audience?: string | string[];
	clockTolerance?: string | number;
	issuer?: string | string[];
	maxTokenAge?: string | number;
	subject?: string;
	typ?: string;
	currentDate?: Date;
}

interface CompactVerifyResult {
	payload: Uint8Array;
	protectedHeader: CompactJWSHeaderParameters;
}

interface ResolvedKey {
	key: KeyLike | Uint8Array;
}

interface FlattenedVerifyResult {
	payload: Uint8Array;
	protectedHeader?: JWSHeaderParameters;
	unprotectedHeader?: JWSHeaderParameters;
}

interface JWEHeaderParameters extends JoseHeaderParameters {
	[propName: string]: unknown;

	alg?: string;
	enc?: string;
	crit?: string[];
	zip?: string;
}

interface SignOptions extends CritOption {}

interface FlattenedJWS extends Partial<FlattenedJWSInput> {
	payload: string;
	signature: string;
}

export type {
	JWK,
	JWTVerifyResult,
	CompactJWSHeaderParameters,
	JoseHeaderParameters,
	JWSHeaderParameters,
	JWTHeaderParameters,
	JWTPayload,
	KeyLike,
	FlattenedJWSInput,
	GetKeyFunction,
	VerifyOptions,
	CritOption,
	JWTClaimVerificationOptions,
	CompactVerifyResult,
	ResolvedKey,
	FlattenedVerifyResult,
	JWEHeaderParameters,
	SignOptions,
	FlattenedJWS,
};
