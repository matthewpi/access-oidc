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

import { JOSENotSupported } from '../errors';
import type { GenerateKeyPairOptions } from '../key';

function getModulusLengthOption(options?: GenerateKeyPairOptions) {
	const modulusLength = options?.modulusLength ?? 2048;
	if (modulusLength < 2048) {
		throw new JOSENotSupported(
			'Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used',
		);
	}

	return modulusLength;
}

async function generateKeyPair(alg: string, options?: GenerateKeyPairOptions) {
	let algorithm: RsaHashedKeyGenParams | EcKeyGenParams;
	let keyUsages: KeyUsage[];

	switch (alg) {
		case 'PS256':
		case 'PS384':
		case 'PS512':
			algorithm = {
				name: 'RSA-PSS',
				hash: `SHA-${alg.slice(-3)}`,
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
				modulusLength: getModulusLengthOption(options),
			};
			keyUsages = ['sign', 'verify'];
			break;
		case 'RS256':
		case 'RS384':
		case 'RS512':
			algorithm = {
				name: 'RSASSA-PKCS1-v1_5',
				hash: `SHA-${alg.slice(-3)}`,
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
				modulusLength: getModulusLengthOption(options),
			};
			keyUsages = ['sign', 'verify'];
			break;
		case 'RSA-OAEP':
		case 'RSA-OAEP-256':
		case 'RSA-OAEP-384':
		case 'RSA-OAEP-512':
			algorithm = {
				name: 'RSA-OAEP',
				hash: `SHA-${Number.parseInt(alg.slice(-3), 10) || 1}`,
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
				modulusLength: getModulusLengthOption(options),
			};
			keyUsages = ['decrypt', 'unwrapKey', 'encrypt', 'wrapKey'];
			break;
		case 'ES256':
			algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
			keyUsages = ['sign', 'verify'];
			break;
		case 'ES384':
			algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
			keyUsages = ['sign', 'verify'];
			break;
		case 'ES512':
			algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
			keyUsages = ['sign', 'verify'];
			break;
		case 'EdDSA':
			switch (options?.crv) {
				case undefined:
				case 'Ed25519':
					algorithm = { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' };
					keyUsages = ['sign', 'verify'];
					break;
				default:
					throw new JOSENotSupported(
						'Invalid or unsupported crv option provided, supported values are Ed25519 and Ed448',
					);
			}

			break;
		case 'ECDH-ES':
		case 'ECDH-ES+A128KW':
		case 'ECDH-ES+A192KW':
		case 'ECDH-ES+A256KW':
			algorithm = { name: 'ECDH', namedCurve: options?.crv ?? 'P-256' };
			keyUsages = ['deriveKey', 'deriveBits'];
			break;
		default:
			throw new JOSENotSupported(
				'Invalid or unsupported JWK "alg" (Algorithm) Parameter value',
			);
	}

	return crypto.subtle.generateKey(
		algorithm,
		options?.extractable ?? false,
		keyUsages,
	) as Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }>;
}

export { generateKeyPair };
