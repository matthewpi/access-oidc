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

import { base64url } from 'jose';

import type { SigningAlgorithm } from '../oidc-provider';

type Algorithm = 'SHA-256' | 'SHA-384' | 'SHA-512'; // | 'SHAKE-256';

type Curve = 'Ed25519' | 'Ed448';

function getAlgorithm(alg: SigningAlgorithm, crv?: Curve): Algorithm {
	switch (alg) {
		case 'ES256':
		case 'PS256':
		case 'RS256':
			return 'SHA-256';

		case 'ES384':
		case 'PS384':
		case 'RS384':
			return 'SHA-384';

		case 'ES512':
		case 'PS512':
		case 'RS512':
			return 'SHA-512';

		case 'EdDSA':
			switch (crv) {
				case 'Ed25519':
					return 'SHA-512';
				// case 'Ed448':
				// return 'SHAKE-256';
				default:
					throw new TypeError('invalid or unrecognized EdDSA curve');
			}

		default:
			throw new TypeError('invalid or unrecognized JWS algorithm');
	}
}

async function generate(token: string, alg: SigningAlgorithm, crv?: Curve): Promise<string> {
	const algorithm = getAlgorithm(alg, crv);
	const text = new TextEncoder().encode(token);
	const digest = await crypto.subtle.digest(
		{
			name: algorithm,
		},
		text,
	);
	const array = new Uint8Array(digest);
	return base64url.encode(array.slice(0, array.length / 2));
}

export { generate };
export type { Curve };
