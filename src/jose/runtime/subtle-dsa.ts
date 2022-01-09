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

function subtleDsa(alg: string, algorithm: KeyAlgorithm | EcKeyAlgorithm) {
	const hash = `SHA-${alg.slice(-3)}`;
	switch (alg) {
		case 'HS256':
		case 'HS384':
		case 'HS512':
			return { hash, name: 'HMAC' };
		case 'PS256':
		case 'PS384':
		case 'PS512':
			// @ts-expect-error
			return { hash, name: 'RSA-PSS', saltLength: alg.slice(-3) >> 3 };
		case 'RS256':
		case 'RS384':
		case 'RS512':
			return { hash, name: 'RSASSA-PKCS1-v1_5' };
		case 'ES256':
		case 'ES384':
		case 'ES512':
			return { hash, name: 'ECDSA', namedCurve: (<EcKeyAlgorithm>algorithm).namedCurve };
		case 'EdDSA':
			const { namedCurve } = <EcKeyAlgorithm>algorithm;
			return <EcKeyAlgorithm>{ name: namedCurve, namedCurve };
		default:
			throw new JOSENotSupported(
				`alg ${alg} is not supported either by JOSE or your javascript runtime`,
			);
	}
}

export { subtleDsa };
