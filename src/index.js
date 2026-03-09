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

function startCallbackServer(port) {
	return new Promise((resolve, reject) => {
		let timer;

		const server = http.createServer((req, res) => {
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

				server.close();
				if (timer) clearTimeout(timer);
				resolve(params);
			} else {
				res.writeHead(400);
				res.end("Invalid request");
			}
		});

		server.listen(port, () => {
			console.log(`[EntraId] Servidor de callback iniciado na porta ${port}`);

			timer = setTimeout(() => {
				server.close();
				reject(new Error("Timeout was reached"));
			}, 60 * 1000);
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
	selectAccount,
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
		promptParam;
	//TODO: acrescentar o state
	// +`&state=${state}`;

	console.log("[EntraId] Abrindo navegador para autenticacao...");

	const redirectParsed = parseUrl(redirectUri);
	const port = redirectParsed ? parseInt(redirectParsed.port) : 8090;

	const callbackPromise = startCallbackServer(port);
	open(authUrl);

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

					return JSON.stringify(result, null, 2);
				} else {
					const accountStr = selectAccount ? " [selectAccount]" : "";
					return `EntraId: ${varName}${accountStr} [>${redirectUri}] clientId:${clientId}, scopes:${scopes}, authority: ${authority}`;
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
};
