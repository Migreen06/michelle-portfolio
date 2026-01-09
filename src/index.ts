export default {
	async fetch(request): Promise<Response> {
		const DEFAULT_SECURITY_HEADERS = {
			"X-XSS-Protection": "0",
			"X-Frame-Options": "DENY",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "strict-origin-when-cross-origin",
			"Cross-Origin-Embedder-Policy": 'require-corp; report-to="default";',
			"Cross-Origin-Opener-Policy": 'same-site; report-to="default";',
			"Cross-Origin-Resource-Policy": "same-site",
		};
		const BLOCKED_HEADERS = [
			"Public-Key-Pins",
			"X-Powered-By",
			"X-AspNet-Version",
		];

		let response = await fetch(request);
		let newHeaders = new Headers(response.headers);

		const tlsVersion = request.cf.tlsVersion;
		console.log(tlsVersion);
		// This sets the headers for HTML responses:
		if (
			newHeaders.has("Content-Type") &&
			!newHeaders.get("Content-Type").includes("text/html")
		) {
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders,
			});
		}

		Object.keys(DEFAULT_SECURITY_HEADERS).map((name) => {
			newHeaders.set(name, DEFAULT_SECURITY_HEADERS[name]);
		});

		BLOCKED_HEADERS.forEach((name) => {
			newHeaders.delete(name);
		});

		if (tlsVersion !== "TLSv1.2" && tlsVersion !== "TLSv1.3") {
			return new Response("You need to use TLS version 1.2 or higher.", {
				status: 400,
			});
		} else {
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders,
			});
		}
	},
} satisfies ExportedHandler;

export default {
	async fetch(request, env, ctx) {
		// write a key-value pair
		await env.KV.put('KEY', 'VALUE');

		// read a key-value pair
		const value = await env.KV.get('KEY');

		// list all key-value pairs
		const allKeys = await env.KV.list();

		// delete a key-value pair
		await env.KV.delete('KEY');

		// return a Workers response
		return new Response(
			JSON.stringify({
				value: value,
				allKeys: allKeys,
			}),
		);
	}
}