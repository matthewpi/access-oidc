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
	JWEHeaderParameters,
	JWSHeaderParameters,
	JWTClaimVerificationOptions,
	JWTPayload,
} from '../types';
import { decoder, isObject } from './index';

function normalizeTyp(value: string): string {
	return value.toLowerCase().replace(/^application\//, '');
}

function checkAudiencePresence(audPayload: unknown, audOption: unknown[]): boolean {
	if (typeof audPayload === 'string') {
		return audOption.includes(audPayload);
	}

	if (Array.isArray(audPayload)) {
		// Each principal intended to process the JWT MUST
		// identify itself with a value in the audience claim
		return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
	}

	return false;
}

export default (
	protectedHeader: JWEHeaderParameters | JWSHeaderParameters,
	encodedPayload: Uint8Array,
	options: JWTClaimVerificationOptions = {},
) => {
	const { typ } = options;
	if (
		typ &&
		(typeof protectedHeader!.typ !== 'string' ||
			normalizeTyp(protectedHeader!.typ) !== normalizeTyp(typ))
	) {
		throw new Error('unexpected "typ" JWT header value', 'typ', 'check_failed');
	}

	let payload!: { [propName: string]: unknown };
	try {
		payload = JSON.parse(decoder.decode(encodedPayload));
	} catch {
		//
	}

	if (!isObject(payload)) {
		throw new Error('JWT Claims Set must be a top-level JSON object');
	}

	const { issuer } = options;
	if (
		issuer &&
		!(<unknown[]>(Array.isArray(issuer) ? issuer : [issuer])).includes(payload.iss!)
	) {
		throw new Error('unexpected "iss" claim value', 'iss', 'check_failed');
	}

	const { subject } = options;
	if (subject && payload.sub !== subject) {
		throw new Error('unexpected "sub" claim value', 'sub', 'check_failed');
	}

	const { audience } = options;
	if (
		audience &&
		!checkAudiencePresence(payload.aud, typeof audience === 'string' ? [audience] : audience)
	) {
		throw new Error('unexpected "aud" claim value', 'aud', 'check_failed');
	}

	let tolerance: number;
	switch (typeof options.clockTolerance) {
		case 'string':
			tolerance = secs(options.clockTolerance);
			break;
		case 'number':
			tolerance = options.clockTolerance;
			break;
		case 'undefined':
			tolerance = 0;
			break;
		default:
			throw new TypeError('Invalid clockTolerance option type');
	}

	const { currentDate } = options;
	const now = epoch(currentDate || new Date());

	if (payload.iat !== undefined || options.maxTokenAge) {
		if (typeof payload.iat !== 'number') {
			throw new Error('"iat" claim must be a number', 'iat', 'invalid');
		}
		if (payload.exp === undefined && payload.iat > now + tolerance) {
			throw new Error(
				'"iat" claim timestamp check failed (it should be in the past)',
				'iat',
				'check_failed',
			);
		}
	}

	if (payload.nbf !== undefined) {
		if (typeof payload.nbf !== 'number') {
			throw new Error('"nbf" claim must be a number', 'nbf', 'invalid');
		}
		if (payload.nbf > now + tolerance) {
			throw new Error('"nbf" claim timestamp check failed', 'nbf', 'check_failed');
		}
	}

	if (payload.exp !== undefined) {
		if (typeof payload.exp !== 'number') {
			throw new Error('"exp" claim must be a number', 'exp', 'invalid');
		}
		if (payload.exp <= now - tolerance) {
			throw new Error('"exp" claim timestamp check failed', 'exp', 'check_failed');
		}
	}

	if (options.maxTokenAge) {
		const age = now - payload.iat!;
		const max =
			typeof options.maxTokenAge === 'number'
				? options.maxTokenAge
				: secs(options.maxTokenAge);

		if (age - tolerance > max) {
			throw new Error(
				'"iat" claim timestamp check failed (too far in the past)',
				'iat',
				'check_failed',
			);
		}

		if (age < 0 - tolerance) {
			throw new Error(
				'"iat" claim timestamp check failed (it should be in the past)',
				'iat',
				'check_failed',
			);
		}
	}

	return payload as JWTPayload;
};
