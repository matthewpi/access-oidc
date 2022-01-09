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

import type {
	CompactJWSHeaderParameters,
	CompactVerifyResult,
	FlattenedJWSInput,
	GetKeyFunction,
	KeyLike,
	ResolvedKey,
	VerifyOptions,
} from '../../types';
import { decoder } from '../../lib';
import { flattenedVerify } from '../flattened/verify';

/**
 * Interface for Compact JWS Verification dynamic key resolution.
 * No token components have been verified at the time of this function call.
 *
 * See [createRemoteJWKSet](../functions/jwks_remote.createRemoteJWKSet.md#function-createremotejwkset)
 * to verify using a remote JSON Web Key Set.
 */
interface CompactVerifyGetKey
	extends GetKeyFunction<CompactJWSHeaderParameters, FlattenedJWSInput> {}

/**
 * Verifies the signature and format of and afterwards decodes the Compact JWS.
 *
 * @param jws Compact JWS.
 * @param key Key to verify the JWS with.
 * @param options JWS Verify options.
 *
 * @example Usage
 * ```js
 * const jws = 'eyJhbGciOiJFUzI1NiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.kkAs_gPPxWMI3rHuVlxHaTPfDWDoqdI8jSvuSmqV-8IHIWXg9mcAeC9ggV-45ZHRbiRJ3obUIFo1rHphPA5URg'
 *
 * const { payload, protectedHeader } = await jose.compactVerify(jws, publicKey)
 *
 * console.log(protectedHeader)
 * console.log(new TextDecoder().decode(payload))
 * ```
 */
async function compactVerify(
	jws: Uint8Array | string,
	key: KeyLike | Uint8Array | CompactVerifyGetKey,
	options?: VerifyOptions,
): Promise<CompactVerifyResult & ResolvedKey> {
	if (jws instanceof Uint8Array) {
		jws = decoder.decode(jws);
	}

	const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split('.');

	if (length !== 3) {
		throw new Error('Invalid Compact JWS');
	}

	const verified = await flattenedVerify(
		{ payload, protected: protectedHeader, signature },
		<Parameters<typeof flattenedVerify>[1]>key,
		options,
	);

	const result = { payload: verified.payload, protectedHeader: verified.protectedHeader! };

	if (typeof key === 'function') {
		return { ...result, key: verified.key };
	}

	return result;
}

export type { CompactVerifyGetKey };
export { compactVerify };
