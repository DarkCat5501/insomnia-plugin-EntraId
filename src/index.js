const os = require("os");
const { exec } = require("child_process");
const http = require("http");
const crypto = require("crypto");

const STORE_PREFIX = "entraid_";

function open(url) {
	let command;
	if (os.platform() === "win32") command = `start "" "${url}"`;
	else if (os.platform() === "darwin") command = `open "${url}"`;
	else command = `xdg-open "${url}"`;

	return exec(command, (err) => {
		if (err) {
			console.error(`Failed to open URL: ${err}`);
		}
	});
}

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

var server = null;

function startCallbackServer(port) {
	return new Promise((resolve, reject) => {
		let timer;


		const killServer = () => {
			server.close();
			if (timer) clearTimeout(timer);
			server = null;
			reject(new Error("Got killed"))
		};

		if (server) killServer();

		server = http.createServer((req, res) => {
			const parsedUrl = parseUrl(`http://localhost${req.url}`);

			if (parsedUrl) {
				const params = {};
				parsedUrl.searchParams.forEach((value, key) => {
					params[key] = value;
				});

				res.writeHead(200, { "Content-Type": "text/html" });
				res.end(
					"<html><body><h1>Autenticado com sucesso!</h1><p>Voce pode fechar esta aba e retornar ao Insomnia.</p><script>window.close()</script></body></html>",
				);

				resolve(params);
				killServer();
			} else {
				res.writeHead(400, { "Content-Type": "text/html" });
				res.end("<html><body><h1>Dados inválidos.</p></body></html>");

				reject(new Error("Invalid request received"));
				killServer();
			}
		});

		server.listen(port, () => {
			console.log(`[EntraId] Servidor de callback iniciado na porta ${port}`);

			timer = setTimeout(() => {
				reject(new Error("Timeout was reached"));
				killServer();
			}, 60 * 1000);
		});

		server.on("error", (_err) => {
			reject(new Error("Can't start response server"));
			killServer();
		});
	});
}

async function authenticateEntraId(
	clientId,
	authority,
	redirectUri,
	scopes,
	selectAccount,
	getAccess = false,
	clientSecret = "",
) {
	const { verifier, challenge } = generatePKCE();

	const scopeStr = Array.isArray(scopes) ? scopes.join(" ") : scopes;
	const promptParam = selectAccount ? "&prompt=select_account" : "";
	const authUrl =
		`${authority}/oauth2/v2.0/authorize?` +
		`client_id=${encodeURIComponent(clientId)}` +
		`&response_type=code` +
		`&redirect_uri=${encodeURIComponent(redirectUri)}` +
		`&response_mode=query` +
		`&scope=${encodeURIComponent(scopeStr)}` +
		`&code_challenge=${challenge}` +
		`&code_challenge_method=S256` +
		promptParam +
		`&state=${"teste123"}`;
	//TODO: acrescentar o state

	console.log("[EntraId] Abrindo navegador para autenticacao...");

	const redirectParsed = parseUrl(redirectUri);
	const port = redirectParsed ? parseInt(redirectParsed.port) : 8090;

	const callbackPromise = startCallbackServer(port);
	open(authUrl);
	console.log("Verifier:", verifier);

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

function getStoreKey(variable) {
	return STORE_PREFIX + (variable || "default");
}

module.exports = {
	name: "EntraId Auth",
	version: "1.0.0",
	description: "Autenticacao OAuth2 PKCE com EntraId",
	icon: "fa-lock",
	templateTags: [
		{
			name: "ENTRAID_AUTH",
			label: "EntraId Auth",
			icon: "fa-lock",
			description:
				"Autentica com EntraId e salva code e code_verifier no store",
			args: [
				{
					name: "clientId",
					displayName: "Client ID",
					type: "string",
					description: "Seu clientId do Azure AD",
				},
				{
					name: "authority",
					displayName: "Authority",
					type: "string",
					description: "https://login.microsoftonline.com/your-tenant-id",
				},
				{
					name: "redirectUri",
					displayName: "Redirect URI",
					type: "string",
					description: "http://localhost:3847/callback",
				},
				{
					name: "scopes",
					displayName: "Scopes",
					type: "string",
					description: "User.Read",
				},
				{
					name: "variable",
					displayName: "Variable",
					type: "string",
					description: "Nome da variavel para salvar no store",
				},
				{
					name: "selectAccount",
					displayName: "Select Account",
					type: "boolean",
					description: "Mostrar tela de seleção de conta",
					value: false,
				},
			],
			liveDisplayName: (args) => {
				const [
					clientId,
					authority,
					redirectUri,
					scopes,
					variable,
					selectAccount,
				] = args;
				const varName = variable?.value || "default";
				const accountStr = selectAccount?.value ? " [selectAccount]" : "";
				return `EntraId: ${varName}${accountStr} [>${redirectUri.value}] clientId:${clientId.value}, scopes:${scopes.value}, authority: ${authority.value}`;
			},
			async run(context, ...args) {
				const [
					clientId,
					authority,
					redirectUri,
					scopes,
					variable,
					selectAccount,
				] = args;
				const varName = variable || "default";

				if (context.renderPurpose === "send") {
					const scopeArray = scopes
						? scopes.split(" ").filter((s) => s)
						: ["User.Read"];
					const result = await authenticateEntraId(
						clientId,
						authority,
						redirectUri,
						scopeArray,
						selectAccount,
					);
					const key = getStoreKey(varName);
					await context.store.setItem(key, JSON.stringify(result));
					return `http://response?type=code&code=${result.code}&verifier=${result.code_verifier}`;
				} else {
					const accountStr = selectAccount ? " [selectAccount]" : "";
					return `EntraId: ${varName}${accountStr} [>${redirectUri}] clientId:${clientId}, scopes:${scopes}, authority: ${authority}`;
				}
			},
		},
		{
			name: "ENTRAID_AUTH_OIDC",
			label: "EntraId Auth",
			icon: "fa-lock",
			description: "Autentica com EntraId e puxa o accessToken e refreshToken",
			args: [
				{
					name: "clientId",
					displayName: "Client ID",
					type: "string",
					description: "Seu clientId do Azure AD",
				},
				{
					name: "clientSecret",
					displayName: "Client Secret",
					type: "string",
					description: "Seu clientSecret do Azure AD",
				},
				{
					name: "authority",
					displayName: "Authority",
					type: "string",
					description: "https://login.microsoftonline.com/your-tenant-id",
				},
				{
					name: "redirectUri",
					displayName: "Redirect URI",
					type: "string",
					description: "http://localhost:3847/callback",
				},
				{
					name: "scopes",
					displayName: "Scopes",
					type: "string",
					description: "User.Read",
				},
				{
					name: "variable",
					displayName: "Variable",
					type: "string",
					description: "Nome da variavel para salvar no store",
				},
				{
					name: "selectAccount",
					displayName: "Select Account",
					type: "boolean",
					description: "Mostrar tela de seleção de conta",
					value: false,
				},
				{
					name: "grantType",
					displayName: "Select Account",
					description: "Tipo de credencial gerada",
					type: "enum",
					options: [
						{
							displayName: "Authorization Code",
							value: "authorization_code",
						},
						{
							displayName: "Client Code",
							value: "client_credentials",
						},
					],
				},
			],
			liveDisplayName: (args) => {
				const [
					clientId,
					_clientSecret,
					authority,
					redirectUri,
					scopes,
					variable,
					selectAccount,
					_grantType,
				] = args;

				const varName = variable?.value || "default";
				const accountStr = selectAccount?.value ? " [selectAccount]" : "";
				return `EntraId: ${varName}${accountStr} [>${redirectUri.value}] clientId:${clientId.value}, scopes:${scopes.value}, authority: ${authority.value}`;
			},
			async run(context, ...args) {
				const [
					clientId,
					clientSecret,
					authority,
					redirectUri,
					scopes,
					variable,
					selectAccount,
					grantType,
				] = args;
				const varName = variable || "default";

				if (context.renderPurpose === "send") {
					const scopeArray = scopes
						? scopes.split(" ").filter((s) => s)
						: ["User.Read"];
					const result = await authenticateEntraId(
						clientId,
						authority,
						redirectUri,
						scopeArray,
						selectAccount,
					);

					const key = getStoreKey(varName);
					await context.store.setItem(key, JSON.stringify(result));
					return `http://response?type=auth&grantType=${grantType}&code=${result.code}&verifier=${result.code_verifier}&authority=${authority}&clientId=${clientId}&clientSecret=${clientSecret}&redirectUri=${redirectUri}&scope=${scopes}`;
				} else {
					const accountStr = selectAccount ? " [selectAccount]" : "";
					return `EntraId OIDC: ${varName}${accountStr} [>${redirectUri}] clientId:${clientId}, scopes:${scopes}, authority: ${authority}`;
				}
			},
		},
		{
			name: "ENTRAID_CODE",
			label: "EntraId Code",
			icon: "fa-key",
			description: "Retorna o code salvo no store",
			args: [
				{
					name: "variable",
					label: "Variable",
					type: "string",
					placeholder: "Nome da variavel",
				},
			],
			liveDisplayName: (args) => {
				const [variable] = args;
				return `Code: ${variable?.value || "default"}`;
			},
			async run(context, ...args) {
				const [variable] = args;
				const varName = variable || "default";

				const key = getStoreKey(varName);
				const stored = await context.store.getItem(key);

				if (!stored) {
					throw new Error(
						`Nenhum token encontrado para variavel: ${varName}. Execute ENTRAID_AUTH primeiro.`,
					);
				}

				const data = JSON.parse(stored);
				return data.code;
			},
		},
		{
			name: "ENTRAID_CODE_VERIFIER",
			label: "EntraId Code Verifier",
			icon: "fa-key",
			description: "Retorna o code_verifier salvo no store",
			args: [
				{
					name: "variable",
					label: "Variable",
					type: "string",
					placeholder: "Nome da variavel",
				},
			],
			liveDisplayName: (args) => {
				const [variable] = args;
				return `Verifier: ${variable?.value || "default"}`;
			},
			async run(context, ...args) {
				const [variable] = args;
				const varName = variable || "default";

				const key = getStoreKey(varName);
				const stored = await context.store.getItem(key);

				if (!stored) {
					throw new Error(
						`Nenhum token encontrado para variavel: ${varName}. Execute ENTRAID_AUTH primeiro.`,
					);
				}

				const data = JSON.parse(stored);
				return data.code_verifier;
			},
		},
	],
	requestHooks: [
		async ({ request: req }) => {
			const method = req.getMethod();
			if (method === "ENTRAID") {
				const url = new URL(req.getUrl());
				const type = url.searchParams.get("type");
				const code = url.searchParams.get("code");
				const verifier = url.searchParams.get("verifier");
				console.log("EntraId code:", code);
				console.log("EntraId verifier:", verifier);
				if (type == "code") {
					req.setUrl("https://postman-echo.com/get");
					req.setMethod("GET");
					req.setHeader("$$EntraId", "true");
					req.setHeader("$$PXXGP", code);
					req.setHeader("$$YAU", verifier);
				} else if (type == "auth") {
					const authority = url.searchParams.get("authority");
					const clientId = url.searchParams.get("clientId");
					const clientSecret = url.searchParams.get("clientSecret");
					const redirectUri = url.searchParams.get("redirectUri");
					const grantType = url.searchParams.get("grantType");
					const scope = url.searchParams.get("scope");
					req.setMethod("POST");
					req.setUrl(`${authority}/oauth2/v2.0/token`);
					req.setHeader("Content-Type", "application/x-www-form-urlencoded");
					req.setBody({
						mimeType: "application/x-www-form-urlencoded",
						params: [
							{ name: "grant_type", value: grantType },
							{ name: "client_id", value: clientId },
							{ name: "code", value: code },
							{ name: "code_verifier", value: verifier },
							{ name: "redirect_uri", value: redirectUri },
							{ name: "scope", value: scope },
							...(clientSecret
								? [{ name: "client_secret", value: clientSecret }]
								: []),
						],
					});
				}
			}
		},
	],
	responseHooks: [
		async ({ response: res, request: req }) => {
			const isEntraId = req.getHeader("$$EntraId") === "true";
			if (isEntraId) {
				const code = req.getHeader("$$PXXGP");
				const verifier = req.getHeader("$$YAU");
				res.setBody(
					JSON.stringify({
						code,
						verifier,
					}),
				);
			}
		},
	],
};
