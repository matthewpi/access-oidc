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

export const JsonResponse = (
	bodyInit?: any | undefined,
	maybeInit?: ResponseInit | Response,
): Response => {
	const response = new Response(
		typeof bodyInit === 'string' ? bodyInit : JSON.stringify(bodyInit),
		{
			...maybeInit,
		},
	);

	response.headers.set('Content-Type', 'application/json; charset=utf-8');

	response.headers.set('Cache-Control', 'no-cache, no-store, no-transform, must-revalidate');
	response.headers.set('Pragma', 'no-cache');

	response.headers.set(
		'Content-Security-Policy',
		[
			"default-src 'none'",
			"base-uri 'none'",
			"form-action 'none'",
			"frame-ancestors 'none'",
			"navigate-to 'none'",
		].join('; ') + ';',
	);
	response.headers.set('X-Content-Type-Options', 'nosniff');
	response.headers.set('X-Frame-Options', 'DENY');
	response.headers.set('X-XSS-Protection', '1; mode=block');
	response.headers.set('Referrer-Policy', 'no-referrer');
	response.headers.set('Permissions-Policy', 'document-domain=()');
	return response;
};
