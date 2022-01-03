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

export const CHALLENGE_METHODS = ['plain', 'S256'] as const;
export type ChallengeMethod = typeof CHALLENGE_METHODS[number];
export const isChallengeMethod = (x: any): x is ChallengeMethod => CHALLENGE_METHODS.includes(x);

export async function verifyPlainChallenge(challenge: string, verifier: string): Promise<boolean> {
	return challenge === verifier;
}

export async function verifyS256Challenge(challenge: string, verifier: string): Promise<boolean> {
	const encoded = new TextEncoder().encode(verifier);
	const digest = await crypto.subtle.digest({ name: 'SHA-256' }, encoded);
	const codeVerifier = base64url.encode(new Uint8Array(digest));

	return challenge === codeVerifier;
}

export async function verifyChallenge(
	method: ChallengeMethod,
	challenge: string,
	verifier: string,
): Promise<boolean> {
	switch (method) {
		case 'plain':
			return verifyPlainChallenge(challenge, verifier);
		case 'S256':
			return verifyS256Challenge(challenge, verifier);
		default:
			return false;
	}
}
