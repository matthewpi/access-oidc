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

import { decode as decodeBase64URL } from '../../base64url';
import type { JWK } from '../types';

function subtleMapping(jwk: JWK): {
	algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
	keyUsages: KeyUsage[];
} {
	let algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
	let keyUsages: KeyUsage[];

	switch (jwk.kty) {
		case 'oct': {
			switch (jwk.alg) {
				case 'HS256':
				case 'HS384':
				case 'HS512':
					algorithm = { name: 'HMAC', hash: `SHA-${jwk.alg.slice(-3)}` };
					keyUsages = ['sign', 'verify'];
					break;
				case 'A128CBC-HS256':
				case 'A192CBC-HS384':
				case 'A256CBC-HS512':
					throw new Error(`${jwk.alg} keys cannot be imported as CryptoKey instances`);
				case 'A128GCM':
				case 'A192GCM':
				case 'A256GCM':
				case 'A128GCMKW':
				case 'A192GCMKW':
				case 'A256GCMKW':
					algorithm = { name: 'AES-GCM' };
					keyUsages = ['encrypt', 'decrypt'];
					break;
				case 'A128KW':
				case 'A192KW':
				case 'A256KW':
					algorithm = { name: 'AES-KW' };
					keyUsages = ['wrapKey', 'unwrapKey'];
					break;
				case 'PBES2-HS256+A128KW':
				case 'PBES2-HS384+A192KW':
				case 'PBES2-HS512+A256KW':
					algorithm = { name: 'PBKDF2' };
					keyUsages = ['deriveBits'];
					break;
				default:
					throw new Error('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
			}
			break;
		}
		case 'RSA': {
			switch (jwk.alg) {
				case 'PS256':
				case 'PS384':
				case 'PS512':
					algorithm = { name: 'RSA-PSS', hash: `SHA-${jwk.alg.slice(-3)}` };
					keyUsages = jwk.d ? ['sign'] : ['verify'];
					break;
				case 'RS256':
				case 'RS384':
				case 'RS512':
					algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${jwk.alg.slice(-3)}` };
					keyUsages = jwk.d ? ['sign'] : ['verify'];
					break;
				case 'RSA-OAEP':
				case 'RSA-OAEP-256':
				case 'RSA-OAEP-384':
				case 'RSA-OAEP-512':
					algorithm = {
						name: 'RSA-OAEP',
						hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`,
					};
					keyUsages = jwk.d ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey'];
					break;
				default:
					throw new Error('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
			}
			break;
		}
		case 'EC': {
			switch (jwk.alg) {
				case 'ES256':
					algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
					keyUsages = jwk.d ? ['sign'] : ['verify'];
					break;
				case 'ES384':
					algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
					keyUsages = jwk.d ? ['sign'] : ['verify'];
					break;
				case 'ES512':
					algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
					keyUsages = jwk.d ? ['sign'] : ['verify'];
					break;
				case 'ECDH-ES':
				case 'ECDH-ES+A128KW':
				case 'ECDH-ES+A192KW':
				case 'ECDH-ES+A256KW':
					algorithm = { name: 'ECDH', namedCurve: jwk.crv! };
					keyUsages = jwk.d ? ['deriveBits'] : [];
					break;
				default:
					throw new Error('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
			}
			break;
		}
		case 'OKP':
			if (jwk.alg !== 'EdDSA') {
				throw new Error('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
			}
			switch (jwk.crv) {
				case 'Ed25519':
					algorithm = { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' };
					keyUsages = jwk.d ? ['sign'] : ['verify'];
					break;
				default:
					throw new Error(
						'Invalid or unsupported JWK "crv" (Subtype of Key Pair) Parameter value',
					);
			}
			break;
		default:
			throw new Error('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
	}

	return { algorithm, keyUsages };
}

const parse = async (jwk: JWK): Promise<CryptoKey> => {
	const { algorithm, keyUsages } = subtleMapping(jwk);
	const rest: [RsaHashedImportParams | EcKeyAlgorithm | Algorithm, boolean, KeyUsage[]] = [
		algorithm,
		jwk.ext ?? false,
		<KeyUsage[]>jwk.key_ops ?? keyUsages,
	];

	if (algorithm.name === 'PBKDF2') {
		return crypto.subtle.importKey('raw', decodeBase64URL(jwk.k!), ...rest);
	}

	const keyData: JWK = { ...jwk };
	delete keyData.alg;
	return crypto.subtle.importKey('jwk', keyData, ...rest);
};
export default parse;
