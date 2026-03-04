const open = require("open");
const http = require("http");
const crypto = require("crypto");

function generatePKCE() {
	const verifier = crypto.randomBytes(32).toString("base64url");
	const challenge = crypto
		.createHash("sha256")
		.update(verifier)
		.digest("base64url");
	return { verifier, challenge };
}

function parseUrl(urlStr) {
	try {
		return new URL(urlStr);
	} catch {
		return null;
	}
}

function startCallbackServer(port) {
	return new Promise((resolve) => {
		const server = http.createServer((req, res) => {
			const parsedUrl = parseUrl(`http://localhost${req.url}`);

			if (parsedUrl) {
				const params = {};
				parsedUrl.searchParams.forEach((value, key) => {
					params[key] = value;
				});

				res.writeHead(200, { "Content-Type": "text/html" });
				res.end(
					"<html><body><h1>Autenticado com sucesso!</h1><p>Você pode fechar esta aba e retornar ao Insomnia.</p><script>window.close()</script></body></html>",
				);

				server.close();
				resolve(params);
			} else {
				res.writeHead(400);
				res.end("Invalid request");
			}
		});

		server.listen(port, () => {
			console.log(`[EntraId] Servidor de callback iniciado na porta ${port}`);
		});

		server.on("error", (err) => {
			if (err.code === "EADDRINUSE") {
				resolve(startCallbackServer(port + 1));
			} else {
				resolve(null);
			}
		});
	});
}

async function authenticateEntraId(
	clientId,
	authority,
	redirectUri,
	scopes,
	state,
) {
	const { verifier, challenge } = generatePKCE();

	const scopeStr = Array.isArray(scopes) ? scopes.join(" ") : scopes;
	const authUrl =
		`${authority}/oauth2/v2.0/authorize?` +
		`client_id=${encodeURIComponent(clientId)}` +
		`&response_type=code` +
		`&redirect_uri=${encodeURIComponent(redirectUri)}` +
		`&response_mode=query` +
		`&scope=${encodeURIComponent(scopeStr)}` +
		`&code_challenge=${challenge}` +
		`&code_challenge_method=S256` +
		`&state=${state}`;

	console.log("[EntraId] Abrindo navegador para autenticacao...");

	const redirectParsed = parseUrl(redirectUri);
	const port = redirectParsed ? parseInt(redirectParsed.port) : 8090;

	const callbackPromise = startCallbackServer(port);
	await open(authUrl);

	console.log("[EntraId] Aguardando callback...");
	const params = await callbackPromise;

	if (!params || !params.code) {
		throw new Error("Codigo de autorizacao nao recebido");
	}

	return {
		code: params.code,
		code_verifier: verifier,
		state: params.state,
	};
}

module.exports = {
	name: "EntraId Auth",
	version: "1.0.0",
	description: "Autenticação OAuth2 PKCE com EntraId",
	icon: "fa-lock",
	templateTags: [
		{
			name: "ENTRAID_AUTH",
			label: "EntraId Auth",
			icon: "fa-lock",
			description: "Autentica com EntraId e retorna code e code_verifier",
			args: [
				{
					name: "clientId",
					label: "Client ID",
					type: "string",
					placeholder: "Seu clientId do Azure AD",
				},
				{
					name: "authority",
					label: "Authority",
					type: "string",
					placeholder: "https://login.microsoftonline.com/your-tenant-id",
				},
				{
					name: "redirectUri",
					label: "Redirect URI",
					type: "string",
					placeholder: "http://localhost:3847/callback",
				},
				{
					name: "scopes",
					label: "Scopes",
					type: "string",
					placeholder: "User.Read",
				},
			],
			liveDisplayName: (args) => {
				const [clientId, authority, redirectUri, scopes] = args;
				return `=>${redirectUri.value} scopes: ${scopes.value}, clientId: ${clientId.value}, authority: ${authority.value}`;
			},
			async run(context, ...args) {
				// console.log("args:", args);
				const [clientId, authority, redirectUri, scopes] = args;
				if (context.renderPurpose === "send") {
					console.log("context:", context);
					// const scopeArray = scopes
					//   ? scopes.split(" ").filter((s) => s)
					//   : ["User.Read"];
					// const result = await authenticateEntraId(
					//   clientId,
					//   authority || "https://login.microsoftonline.com/common",
					//   redirectUri || "http://localhost:3847/callback",
					//   scopeArray,
					//   "test",
					// );
					// return JSON.stringify(result, null, 2);
				} else {
					return `=>${redirectUri} scopes: ${scopes}, clientId: ${clientId}, authority: ${authority}`;
				}
			},
		},
	],

	reqquestHooks: [
		async (context) => {
			console.log("send:", context);

			// const url = request.getUrl();
			//
			// // Interceptar URLs com scheme especial
			// if (url.startsWith("entraid://") || url.startsWith("entraid-auth://")) {
			// 	try {
			// 		let bodyParams = {};
			// 		const requestBody = request.getBody();
			//
			// 		if (requestBody) {
			// 			if (typeof requestBody === "string") {
			// 				bodyParams = JSON.parse(requestBody);
			// 			} else {
			// 				bodyParams = requestBody;
			// 			}
			// 		}
			//
			// 		const cleanUrl = url.replace(/^entraid-auth?:\/\//, "");
			// 		const parsedUrl = parseUrl(cleanUrl);
			// 		if (parsedUrl) {
			// 			parsedUrl.searchParams.forEach((value, key) => {
			// 				bodyParams[key] = value;
			// 			});
			// 		}
			//
			// 		const {
			// 			clientId,
			// 			authority = "https://login.microsoftonline.com/common",
			// 			redirectUri = "http://localhost:3847/callback",
			// 			scopes = ["User.Read"],
			// 			state = "test",
			// 		} = bodyParams;
			//
			// 		if (!clientId) {
			// 			throw new Error("clientId e obrigatorio no body");
			// 		}
			//
			// 		const result = await authenticateEntraId(
			// 			clientId,
			// 			authority,
			// 			redirectUri,
			// 			scopes,
			// 			state,
			// 		);
			//
			// 		const responseBody = JSON.stringify(
			// 			{
			// 				success: true,
			// 				...result,
			// 				expires_in: 600,
			// 				message: "Use code e code_verifier para obter o token de acesso",
			// 			},
			// 			null,
			// 			2,
			// 		);
			//
			// 		await send({
			// 			status: 200,
			// 			statusText: "OK",
			// 			headers: { "content-type": "application/json" },
			// 			data: responseBody,
			// 		});
			//
			// 		return true;
			// 	} catch (error) {
			// 		const errorBody = JSON.stringify({ error: error.message }, null, 2);
			// 		await send({
			// 			status: 500,
			// 			statusText: "Error",
			// 			headers: { "content-type": "application/json" },
			// 			data: errorBody,
			// 		});
			// 		return true;
			// 	}
			// }

			return;
		},
	],
};
