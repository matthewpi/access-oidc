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

import { decode as decodeBase64URL } from '../../../base64url';
import { JOSEAlgNotAllowed, JWSInvalid, JWSSignatureVerificationFailed } from '../../errors';
import { encoder, decoder, concat, isDisjoint, isObject } from '../../lib';
import { checkKeyType } from '../../lib/check-key-type';
import { validateAlgorithms } from '../../lib/validate-algorithms';
import { validateCrit } from '../../lib/validate-crit';
import { verify } from '../../runtime/verify';
import type {
	FlattenedJWSInput,
	FlattenedVerifyResult,
	GetKeyFunction,
	JWSHeaderParameters,
	KeyLike,
	ResolvedKey,
	VerifyOptions,
} from '../../types';

/**
 * Interface for Flattened JWS Verification dynamic key resolution.
 * No token components have been verified at the time of this function call.
 *
 * See [createRemoteJWKSet](../functions/jwks_remote.createRemoteJWKSet.md#function-createremotejwkset)
 * to verify using a remote JSON Web Key Set.
 */
interface FlattenedVerifyGetKey
	extends GetKeyFunction<JWSHeaderParameters | undefined, FlattenedJWSInput> {}

/**
 * Verifies the signature and format of and afterwards decodes the Flattened JWS.
 *
 * @param jws Flattened JWS.
 * @param key Key to verify the JWS with.
 * @param options JWS Verify options.
 *
 * @example Usage
 * ```js
 * const decoder = new TextDecoder()
 * const jws = {
 *   signature: 'FVVOXwj6kD3DqdfD9yYqfT2W9jv-Nop4kOehp_DeDGNB5dQNSPRvntBY6xH3uxlCxE8na9d_kyhYOcanpDJ0EA',
 *   payload: 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4',
 *   protected: 'eyJhbGciOiJFUzI1NiJ9'
 * }
 *
 * const { payload, protectedHeader } = await jose.flattenedVerify(jws, publicKey)
 *
 * console.log(protectedHeader)
 * console.log(decoder.decode(payload))
 * ```
 */
function flattenedVerify(
	jws: FlattenedJWSInput,
	key: KeyLike | Uint8Array,
	options?: VerifyOptions,
): Promise<FlattenedVerifyResult>;

/**
 * @param jws Flattened JWS.
 * @param getKey Function resolving a key to verify the JWS with.
 * @param options JWS Verify options.
 */
function flattenedVerify(
	jws: FlattenedJWSInput,
	getKey: FlattenedVerifyGetKey,
	options?: VerifyOptions,
): Promise<FlattenedVerifyResult & ResolvedKey>;

async function flattenedVerify(
	jws: FlattenedJWSInput,
	key: KeyLike | Uint8Array | FlattenedVerifyGetKey,
	options?: VerifyOptions,
) {
	if (!isObject(jws)) {
		throw new JWSInvalid('Flattened JWS must be an object');
	}

	if (jws.protected === undefined && jws.header === undefined) {
		throw new JWSInvalid(
			'Flattened JWS must have either of the "protected" or "header" members',
		);
	}

	if (jws.protected !== undefined && typeof jws.protected !== 'string') {
		throw new JWSInvalid('JWS Protected Header incorrect type');
	}

	if (jws.payload === undefined) {
		throw new JWSInvalid('JWS Payload missing');
	}

	if (typeof jws.signature !== 'string') {
		throw new JWSInvalid('JWS Signature missing or incorrect type');
	}

	if (jws.header !== undefined && !isObject(jws.header)) {
		throw new JWSInvalid('JWS Unprotected Header incorrect type');
	}

	let parsedProt: JWSHeaderParameters = {};
	if (jws.protected) {
		const protectedHeader = decodeBase64URL(jws.protected);
		try {
			parsedProt = JSON.parse(decoder.decode(protectedHeader)) as JWSHeaderParameters;
		} catch {
			throw new JWSInvalid('JWS Protected Header is invalid');
		}
	}

	if (!isDisjoint(parsedProt, jws.header)) {
		throw new JWSInvalid(
			'JWS Protected and JWS Unprotected Header Parameter names must be disjoint',
		);
	}

	const joseHeader: JWSHeaderParameters = {
		...parsedProt,
		...jws.header,
	};

	const extensions = validateCrit(
		JWSInvalid,
		new Map([['b64', true]]),
		options?.crit,
		parsedProt,
		joseHeader,
	);

	let b64 = true;
	if (extensions.has('b64')) {
		b64 = parsedProt.b64!;
		if (typeof b64 !== 'boolean') {
			throw new JWSInvalid(
				'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
			);
		}
	}

	const { alg } = joseHeader;

	if (typeof alg !== 'string' || !alg) {
		throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
	}

	const algorithms = options && validateAlgorithms('algorithms', options.algorithms);

	if (algorithms && !algorithms.has(alg)) {
		throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter not allowed');
	}

	if (b64) {
		if (typeof jws.payload !== 'string') {
			throw new JWSInvalid('JWS Payload must be a string');
		}
	} else if (typeof jws.payload !== 'string' && !(jws.payload instanceof Uint8Array)) {
		throw new JWSInvalid('JWS Payload must be a string or an Uint8Array instance');
	}

	let resolvedKey = false;
	if (typeof key === 'function') {
		key = await key(parsedProt, jws);
		resolvedKey = true;
	}

	checkKeyType(alg, key, 'verify');

	const data = concat(
		encoder.encode(jws.protected ?? ''),
		encoder.encode('.'),
		typeof jws.payload === 'string' ? encoder.encode(jws.payload) : jws.payload,
	);
	const signature = decodeBase64URL(jws.signature);
	const verified = await verify(alg, key, signature, data);

	if (!verified) {
		throw new JWSSignatureVerificationFailed();
	}

	let payload: Uint8Array;
	if (b64) {
		payload = decodeBase64URL(jws.payload);
	} else if (typeof jws.payload === 'string') {
		payload = encoder.encode(jws.payload);
	} else {
		payload = jws.payload;
	}

	const result: FlattenedVerifyResult = { payload };

	if (jws.protected !== undefined) {
		result.protectedHeader = parsedProt;
	}

	if (jws.header !== undefined) {
		result.unprotectedHeader = jws.header;
	}

	if (resolvedKey) {
		return { ...result, key };
	}

	return result;
}

export type { FlattenedVerifyGetKey };
export { flattenedVerify };
