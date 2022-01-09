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

const fetchJwks = async (url: URL, timeout: number) => {
	let controller!: AbortController;
	let id!: ReturnType<typeof setTimeout>;
	let timedOut = false;
	if (typeof AbortController === 'function') {
		controller = new AbortController();
		id = setTimeout(() => {
			timedOut = true;
			controller.abort();
		}, timeout);
	}

	const response = await fetch(url.href, {
		signal: controller ? controller.signal : undefined,
		redirect: 'manual',
		method: 'GET',
	}).catch(err => {
		if (timedOut) throw new Error();
		throw err;
	});

	if (id !== undefined) clearTimeout(id);

	if (response.status !== 200) {
		throw new Error('Expected 200 OK from the JSON Web Key Set HTTP response');
	}

	try {
		return await response.json();
	} catch {
		throw new Error('Failed to parse the JSON Web Key Set HTTP response as JSON');
	}
};

export { fetchJwks };
