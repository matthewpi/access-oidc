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

import { Route, RouteHandler, RouterRequest } from './types';

class Router {
	private readonly base: string;
	private readonly routes: Route[];

	constructor(base = '', routes: Route[] = []) {
		this.base = base;
		this.routes = routes;
	}

	async handle(request: Request, ...args: any): Promise<Response> {
		const url = new URL(request.url);
		// @ts-expect-error Request is a class and cannot be typed differently.
		request.query = Object.fromEntries(url.searchParams);

		for (const { method, pattern, handlers } of this.routes) {
			if (method !== request.method && method !== 'ALL') {
				continue;
			}

			const match = url.pathname.match(pattern);
			if (match !== null) {
				// @ts-expect-error Request is a class and cannot be typed differently.
				request.params = match?.groups;

				for (const handler of handlers) {
					// eslint-disable-next-line no-await-in-loop
					const response = await handler(request as RouterRequest, ...args);
					if (response === undefined) {
						continue;
					}

					return response;
				}
			}
		}

		return new Response(null, { status: 500 });
	}

	all(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('ALL', pattern, ...handlers);
	}

	connect(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('CONNECT', pattern, ...handlers);
	}

	delete(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('DELETE', pattern, ...handlers);
	}

	get(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('GET', pattern, ...handlers);
	}

	head(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('HEAD', pattern, ...handlers);
	}

	options(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('OPTIONS', pattern, ...handlers);
	}

	patch(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('PATCH', pattern, ...handlers);
	}

	post(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('POST', pattern, ...handlers);
	}

	put(pattern: string, ...handlers: RouteHandler[]): void {
		this.method('PUT', pattern, ...handlers);
	}

	method(method: string, pattern: string, ...handlers: RouteHandler[]): void {
		this.routes.push({
			method: method.toUpperCase(),
			pattern: new RegExp(
				`^${(this.base + pattern)
					.replace(/(\/?)\*/g, '($1.*)?')
					.replace(/\/$/, '')
					.replace(/:(\w+)(\?)?(\.)?/g, '$2(?<$1>[^/]+)$2$3')
					.replace(/\.(?=[\w(])/, '\\.')}/*$`,
			),
			handlers,
		});
	}
}

export { JsonResponse } from './response';
export type { Params, RouterRequest } from './types';
export { Router };
