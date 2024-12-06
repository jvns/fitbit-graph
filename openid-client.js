// node_modules/oauth4webapi/build/index.js
var USER_AGENT;
if (typeof navigator === "undefined" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) {
  const NAME = "oauth4webapi";
  const VERSION = "v3.1.4";
  USER_AGENT = `${NAME}/${VERSION}`;
}
function looseInstanceOf(input, expected) {
  if (input == null) {
    return false;
  }
  try {
    return input instanceof expected || Object.getPrototypeOf(input)[Symbol.toStringTag] === expected.prototype[Symbol.toStringTag];
  } catch {
    return false;
  }
}
var ERR_INVALID_ARG_VALUE = "ERR_INVALID_ARG_VALUE";
var ERR_INVALID_ARG_TYPE = "ERR_INVALID_ARG_TYPE";
function CodedTypeError(message2, code, cause) {
  const err = new TypeError(message2, { cause });
  Object.assign(err, { code });
  return err;
}
var allowInsecureRequests = Symbol();
var clockSkew = Symbol();
var clockTolerance = Symbol();
var customFetch = Symbol();
var modifyAssertion = Symbol();
var jweDecrypt = Symbol();
var jwksCache = Symbol();
var encoder = new TextEncoder();
var decoder = new TextDecoder();
function buf(input) {
  if (typeof input === "string") {
    return encoder.encode(input);
  }
  return decoder.decode(input);
}
var CHUNK_SIZE = 32768;
function encodeBase64Url(input) {
  if (input instanceof ArrayBuffer) {
    input = new Uint8Array(input);
  }
  const arr = [];
  for (let i = 0; i < input.byteLength; i += CHUNK_SIZE) {
    arr.push(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK_SIZE)));
  }
  return btoa(arr.join("")).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function decodeBase64Url(input) {
  try {
    const binary = atob(input.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch (cause) {
    throw CodedTypeError("The input to be decoded is not correctly encoded.", ERR_INVALID_ARG_VALUE, cause);
  }
}
function b64u(input) {
  if (typeof input === "string") {
    return decodeBase64Url(input);
  }
  return encodeBase64Url(input);
}
var UnsupportedOperationError = class extends Error {
  code;
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    this.code = UNSUPPORTED_OPERATION;
    Error.captureStackTrace?.(this, this.constructor);
  }
};
var OperationProcessingError = class extends Error {
  code;
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    if (options?.code) {
      this.code = options?.code;
    }
    Error.captureStackTrace?.(this, this.constructor);
  }
};
function OPE(message2, code, cause) {
  return new OperationProcessingError(message2, { code, cause });
}
function assertCryptoKey(key, it) {
  if (!(key instanceof CryptoKey)) {
    throw CodedTypeError(`${it} must be a CryptoKey`, ERR_INVALID_ARG_TYPE);
  }
}
function assertPrivateKey(key, it) {
  assertCryptoKey(key, it);
  if (key.type !== "private") {
    throw CodedTypeError(`${it} must be a private CryptoKey`, ERR_INVALID_ARG_VALUE);
  }
}
function assertPublicKey(key, it) {
  assertCryptoKey(key, it);
  if (key.type !== "public") {
    throw CodedTypeError(`${it} must be a public CryptoKey`, ERR_INVALID_ARG_VALUE);
  }
}
function normalizeTyp(value) {
  return value.toLowerCase().replace(/^application\//, "");
}
function isJsonObject(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }
  return true;
}
function prepareHeaders(input) {
  if (looseInstanceOf(input, Headers)) {
    input = Object.fromEntries(input.entries());
  }
  const headers2 = new Headers(input);
  if (USER_AGENT && !headers2.has("user-agent")) {
    headers2.set("user-agent", USER_AGENT);
  }
  if (headers2.has("authorization")) {
    throw CodedTypeError('"options.headers" must not include the "authorization" header name', ERR_INVALID_ARG_VALUE);
  }
  if (headers2.has("dpop")) {
    throw CodedTypeError('"options.headers" must not include the "dpop" header name', ERR_INVALID_ARG_VALUE);
  }
  return headers2;
}
function signal(value) {
  if (typeof value === "function") {
    value = value();
  }
  if (!(value instanceof AbortSignal)) {
    throw CodedTypeError('"options.signal" must return or be an instance of AbortSignal', ERR_INVALID_ARG_TYPE);
  }
  return value;
}
async function discoveryRequest(issuerIdentifier, options) {
  if (!(issuerIdentifier instanceof URL)) {
    throw CodedTypeError('"issuerIdentifier" must be an instance of URL', ERR_INVALID_ARG_TYPE);
  }
  checkProtocol(issuerIdentifier, options?.[allowInsecureRequests] !== true);
  const url = new URL(issuerIdentifier.href);
  switch (options?.algorithm) {
    case void 0:
    case "oidc":
      url.pathname = `${url.pathname}/.well-known/openid-configuration`.replace("//", "/");
      break;
    case "oauth2":
      if (url.pathname === "/") {
        url.pathname = ".well-known/oauth-authorization-server";
      } else {
        url.pathname = `.well-known/oauth-authorization-server/${url.pathname}`.replace("//", "/");
      }
      break;
    default:
      throw CodedTypeError('"options.algorithm" must be "oidc" (default), or "oauth2"', ERR_INVALID_ARG_VALUE);
  }
  const headers2 = prepareHeaders(options?.headers);
  headers2.set("accept", "application/json");
  return (options?.[customFetch] || fetch)(url.href, {
    body: void 0,
    headers: Object.fromEntries(headers2.entries()),
    method: "GET",
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : void 0
  });
}
function assertNumber(input, allow0, it, code, cause) {
  try {
    if (typeof input !== "number" || !Number.isFinite(input)) {
      throw CodedTypeError(`${it} must be a number`, ERR_INVALID_ARG_TYPE, cause);
    }
    if (input > 0)
      return;
    if (allow0 && input !== 0) {
      throw CodedTypeError(`${it} must be a non-negative number`, ERR_INVALID_ARG_VALUE, cause);
    }
    throw CodedTypeError(`${it} must be a positive number`, ERR_INVALID_ARG_VALUE, cause);
  } catch (err) {
    if (code) {
      throw OPE(err.message, code, cause);
    }
    throw err;
  }
}
function assertString(input, it, code, cause) {
  try {
    if (typeof input !== "string") {
      throw CodedTypeError(`${it} must be a string`, ERR_INVALID_ARG_TYPE, cause);
    }
    if (input.length === 0) {
      throw CodedTypeError(`${it} must not be empty`, ERR_INVALID_ARG_VALUE, cause);
    }
  } catch (err) {
    if (code) {
      throw OPE(err.message, code, cause);
    }
    throw err;
  }
}
async function processDiscoveryResponse(expectedIssuerIdentifier, response) {
  if (!(expectedIssuerIdentifier instanceof URL) && expectedIssuerIdentifier !== _nodiscoverycheck) {
    throw CodedTypeError('"expectedIssuer" must be an instance of URL', ERR_INVALID_ARG_TYPE);
  }
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  if (response.status !== 200) {
    throw OPE('"response" is not a conform Authorization Server Metadata response (unexpected HTTP status code)', RESPONSE_IS_NOT_CONFORM, response);
  }
  assertReadableResponse(response);
  assertApplicationJson(response);
  let json;
  try {
    json = await response.json();
  } catch (cause) {
    throw OPE('failed to parse "response" body as JSON', PARSE_ERROR, cause);
  }
  if (!isJsonObject(json)) {
    throw OPE('"response" body must be a top level object', INVALID_RESPONSE, { body: json });
  }
  assertString(json.issuer, '"response" body "issuer" property', INVALID_RESPONSE, { body: json });
  if (new URL(json.issuer).href !== expectedIssuerIdentifier.href && expectedIssuerIdentifier !== _nodiscoverycheck) {
    throw OPE('"response" body "issuer" property does not match the expected value', JSON_ATTRIBUTE_COMPARISON, { expected: expectedIssuerIdentifier.href, body: json, attribute: "issuer" });
  }
  return json;
}
function assertApplicationJson(response) {
  assertContentType(response, "application/json");
}
function notJson(response, ...types2) {
  let msg = '"response" content-type must be ';
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `${types2.join(", ")}, or ${last}`;
  } else if (types2.length === 2) {
    msg += `${types2[0]} or ${types2[1]}`;
  } else {
    msg += types2[0];
  }
  return OPE(msg, RESPONSE_IS_NOT_JSON, response);
}
function assertContentTypes(response, ...types2) {
  if (!types2.includes(getContentType(response))) {
    throw notJson(response, ...types2);
  }
}
function assertContentType(response, contentType) {
  if (getContentType(response) !== contentType) {
    throw notJson(response, contentType);
  }
}
function randomBytes() {
  return b64u(crypto.getRandomValues(new Uint8Array(32)));
}
function generateRandomCodeVerifier() {
  return randomBytes();
}
function generateRandomState() {
  return randomBytes();
}
function generateRandomNonce() {
  return randomBytes();
}
async function calculatePKCECodeChallenge(codeVerifier) {
  assertString(codeVerifier, "codeVerifier");
  return b64u(await crypto.subtle.digest("SHA-256", buf(codeVerifier)));
}
function getKeyAndKid(input) {
  if (input instanceof CryptoKey) {
    return { key: input };
  }
  if (!(input?.key instanceof CryptoKey)) {
    return {};
  }
  if (input.kid !== void 0) {
    assertString(input.kid, '"kid"');
  }
  return {
    key: input.key,
    kid: input.kid
  };
}
function psAlg(key) {
  switch (key.algorithm.hash.name) {
    case "SHA-256":
      return "PS256";
    case "SHA-384":
      return "PS384";
    case "SHA-512":
      return "PS512";
    default:
      throw new UnsupportedOperationError("unsupported RsaHashedKeyAlgorithm hash name", {
        cause: key
      });
  }
}
function rsAlg(key) {
  switch (key.algorithm.hash.name) {
    case "SHA-256":
      return "RS256";
    case "SHA-384":
      return "RS384";
    case "SHA-512":
      return "RS512";
    default:
      throw new UnsupportedOperationError("unsupported RsaHashedKeyAlgorithm hash name", {
        cause: key
      });
  }
}
function esAlg(key) {
  switch (key.algorithm.namedCurve) {
    case "P-256":
      return "ES256";
    case "P-384":
      return "ES384";
    case "P-521":
      return "ES512";
    default:
      throw new UnsupportedOperationError("unsupported EcKeyAlgorithm namedCurve", { cause: key });
  }
}
function keyToJws(key) {
  switch (key.algorithm.name) {
    case "RSA-PSS":
      return psAlg(key);
    case "RSASSA-PKCS1-v1_5":
      return rsAlg(key);
    case "ECDSA":
      return esAlg(key);
    case "Ed25519":
    case "EdDSA":
      return "Ed25519";
    default:
      throw new UnsupportedOperationError("unsupported CryptoKey algorithm name", { cause: key });
  }
}
function getClockSkew(client) {
  const skew = client?.[clockSkew];
  return typeof skew === "number" && Number.isFinite(skew) ? skew : 0;
}
function getClockTolerance(client) {
  const tolerance = client?.[clockTolerance];
  return typeof tolerance === "number" && Number.isFinite(tolerance) && Math.sign(tolerance) !== -1 ? tolerance : 30;
}
function epochTime() {
  return Math.floor(Date.now() / 1e3);
}
function assertAs(as) {
  if (typeof as !== "object" || as === null) {
    throw CodedTypeError('"as" must be an object', ERR_INVALID_ARG_TYPE);
  }
  assertString(as.issuer, '"as.issuer"');
}
function assertClient(client) {
  if (typeof client !== "object" || client === null) {
    throw CodedTypeError('"client" must be an object', ERR_INVALID_ARG_TYPE);
  }
  assertString(client.client_id, '"client.client_id"');
}
function formUrlEncode(token) {
  return encodeURIComponent(token).replace(/(?:[-_.!~*'()]|%20)/g, (substring) => {
    switch (substring) {
      case "-":
      case "_":
      case ".":
      case "!":
      case "~":
      case "*":
      case "'":
      case "(":
      case ")":
        return `%${substring.charCodeAt(0).toString(16).toUpperCase()}`;
      case "%20":
        return "+";
      default:
        throw new Error();
    }
  });
}
function ClientSecretPost(clientSecret) {
  assertString(clientSecret, '"clientSecret"');
  return (_as, client, body, _headers) => {
    body.set("client_id", client.client_id);
    body.set("client_secret", clientSecret);
  };
}
function ClientSecretBasic(clientSecret) {
  assertString(clientSecret, '"clientSecret"');
  return (_as, client, _body, headers2) => {
    const username = formUrlEncode(client.client_id);
    const password = formUrlEncode(clientSecret);
    const credentials = btoa(`${username}:${password}`);
    headers2.set("authorization", `Basic ${credentials}`);
  };
}
function clientAssertionPayload(as, client) {
  const now = epochTime() + getClockSkew(client);
  return {
    jti: randomBytes(),
    aud: as.issuer,
    exp: now + 60,
    iat: now,
    nbf: now,
    iss: client.client_id,
    sub: client.client_id
  };
}
function PrivateKeyJwt(clientPrivateKey, options) {
  const { key, kid } = getKeyAndKid(clientPrivateKey);
  assertPrivateKey(key, '"clientPrivateKey.key"');
  return async (as, client, body, _headers) => {
    const header = { alg: keyToJws(key), kid };
    const payload = clientAssertionPayload(as, client);
    options?.[modifyAssertion]?.(header, payload);
    body.set("client_id", client.client_id);
    body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    body.set("client_assertion", await signJwt(header, payload, key));
  };
}
function ClientSecretJwt(clientSecret, options) {
  assertString(clientSecret, '"clientSecret"');
  const modify = options?.[modifyAssertion];
  let key;
  return async (as, client, body, _headers) => {
    key ||= await crypto.subtle.importKey("raw", buf(clientSecret), { hash: "SHA-256", name: "HMAC" }, false, ["sign"]);
    const header = { alg: "HS256" };
    const payload = clientAssertionPayload(as, client);
    modify?.(header, payload);
    const data = `${b64u(buf(JSON.stringify(header)))}.${b64u(buf(JSON.stringify(payload)))}`;
    const hmac = await crypto.subtle.sign(key.algorithm, key, buf(data));
    body.set("client_id", client.client_id);
    body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    body.set("client_assertion", `${data}.${b64u(new Uint8Array(hmac))}`);
  };
}
function None() {
  return (_as, client, body, _headers) => {
    body.set("client_id", client.client_id);
  };
}
function TlsClientAuth() {
  return None();
}
async function signJwt(header, payload, key) {
  if (!key.usages.includes("sign")) {
    throw CodedTypeError('CryptoKey instances used for signing assertions must include "sign" in their "usages"', ERR_INVALID_ARG_VALUE);
  }
  const input = `${b64u(buf(JSON.stringify(header)))}.${b64u(buf(JSON.stringify(payload)))}`;
  const signature = b64u(await crypto.subtle.sign(keyToSubtle(key), key, buf(input)));
  return `${input}.${signature}`;
}
async function issueRequestObject(as, client, parameters, privateKey, options) {
  assertAs(as);
  assertClient(client);
  parameters = new URLSearchParams(parameters);
  const { key, kid } = getKeyAndKid(privateKey);
  assertPrivateKey(key, '"privateKey.key"');
  parameters.set("client_id", client.client_id);
  const now = epochTime() + getClockSkew(client);
  const claims = {
    ...Object.fromEntries(parameters.entries()),
    jti: randomBytes(),
    aud: as.issuer,
    exp: now + 60,
    iat: now,
    nbf: now,
    iss: client.client_id
  };
  let resource;
  if (parameters.has("resource") && (resource = parameters.getAll("resource")) && resource.length > 1) {
    claims.resource = resource;
  }
  {
    let value = parameters.get("max_age");
    if (value !== null) {
      claims.max_age = parseInt(value, 10);
      assertNumber(claims.max_age, true, '"max_age" parameter');
    }
  }
  {
    let value = parameters.get("claims");
    if (value !== null) {
      try {
        claims.claims = JSON.parse(value);
      } catch (cause) {
        throw OPE('failed to parse the "claims" parameter as JSON', PARSE_ERROR, cause);
      }
      if (!isJsonObject(claims.claims)) {
        throw CodedTypeError('"claims" parameter must be a JSON with a top level object', ERR_INVALID_ARG_VALUE);
      }
    }
  }
  {
    let value = parameters.get("authorization_details");
    if (value !== null) {
      try {
        claims.authorization_details = JSON.parse(value);
      } catch (cause) {
        throw OPE('failed to parse the "authorization_details" parameter as JSON', PARSE_ERROR, cause);
      }
      if (!Array.isArray(claims.authorization_details)) {
        throw CodedTypeError('"authorization_details" parameter must be a JSON with a top level array', ERR_INVALID_ARG_VALUE);
      }
    }
  }
  const header = {
    alg: keyToJws(key),
    typ: "oauth-authz-req+jwt",
    kid
  };
  options?.[modifyAssertion]?.(header, claims);
  return signJwt(header, claims, key);
}
var jwkCache;
async function getSetPublicJwkCache(key) {
  const { kty, e: e2, n, x, y, crv } = await crypto.subtle.exportKey("jwk", key);
  const jwk = { kty, e: e2, n, x, y, crv };
  jwkCache.set(key, jwk);
  return jwk;
}
async function publicJwk(key) {
  jwkCache ||= /* @__PURE__ */ new WeakMap();
  return jwkCache.get(key) || getSetPublicJwkCache(key);
}
var URLParse = URL.parse ? (url, base) => URL.parse(url, base) : (url, base) => {
  try {
    return new URL(url, base);
  } catch {
    return null;
  }
};
function checkProtocol(url, enforceHttps) {
  if (enforceHttps && url.protocol !== "https:") {
    throw OPE("only requests to HTTPS are allowed", HTTP_REQUEST_FORBIDDEN, url);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw OPE("only HTTP and HTTPS requests are allowed", REQUEST_PROTOCOL_FORBIDDEN, url);
  }
}
function validateEndpoint(value, endpoint, useMtlsAlias, enforceHttps) {
  let url;
  if (typeof value !== "string" || !(url = URLParse(value))) {
    throw OPE(`authorization server metadata does not contain a valid ${useMtlsAlias ? `"as.mtls_endpoint_aliases.${endpoint}"` : `"as.${endpoint}"`}`, value === void 0 ? MISSING_SERVER_METADATA : INVALID_SERVER_METADATA, { attribute: useMtlsAlias ? `mtls_endpoint_aliases.${endpoint}` : endpoint });
  }
  checkProtocol(url, enforceHttps);
  return url;
}
function resolveEndpoint(as, endpoint, useMtlsAlias, enforceHttps) {
  if (useMtlsAlias && as.mtls_endpoint_aliases && endpoint in as.mtls_endpoint_aliases) {
    return validateEndpoint(as.mtls_endpoint_aliases[endpoint], endpoint, useMtlsAlias, enforceHttps);
  }
  return validateEndpoint(as[endpoint], endpoint, useMtlsAlias, enforceHttps);
}
async function pushedAuthorizationRequest(as, client, clientAuthentication, parameters, options) {
  assertAs(as);
  assertClient(client);
  const url = resolveEndpoint(as, "pushed_authorization_request_endpoint", client.use_mtls_endpoint_aliases, options?.[allowInsecureRequests] !== true);
  const body = new URLSearchParams(parameters);
  body.set("client_id", client.client_id);
  const headers2 = prepareHeaders(options?.headers);
  headers2.set("accept", "application/json");
  if (options?.DPoP !== void 0) {
    assertDPoP(options.DPoP);
    await options.DPoP.addProof(url, headers2, "POST");
  }
  const response = await authenticatedRequest(as, client, clientAuthentication, url, body, headers2, options);
  options?.DPoP?.cacheNonce(response);
  return response;
}
var DPoPHandler = class {
  #header;
  #privateKey;
  #publicKey;
  #clockSkew;
  #modifyAssertion;
  #map;
  constructor(client, keyPair, options) {
    assertPrivateKey(keyPair?.privateKey, '"DPoP.privateKey"');
    assertPublicKey(keyPair?.publicKey, '"DPoP.publicKey"');
    if (!keyPair.publicKey.extractable) {
      throw CodedTypeError('"DPoP.publicKey.extractable" must be true', ERR_INVALID_ARG_VALUE);
    }
    this.#modifyAssertion = options?.[modifyAssertion];
    this.#clockSkew = getClockSkew(client);
    this.#privateKey = keyPair.privateKey;
    this.#publicKey = keyPair.publicKey;
    branded.add(this);
  }
  #get(key) {
    this.#map ||= /* @__PURE__ */ new Map();
    let item = this.#map.get(key);
    if (item) {
      this.#map.delete(key);
      this.#map.set(key, item);
    }
    return item;
  }
  #set(key, val) {
    this.#map ||= /* @__PURE__ */ new Map();
    this.#map.delete(key);
    if (this.#map.size === 100) {
      this.#map.delete(this.#map.keys().next().value);
    }
    this.#map.set(key, val);
  }
  async addProof(url, headers2, htm, accessToken) {
    this.#header ||= {
      alg: keyToJws(this.#privateKey),
      typ: "dpop+jwt",
      jwk: await publicJwk(this.#publicKey)
    };
    const nonce = this.#get(url.origin);
    const now = epochTime() + this.#clockSkew;
    const payload = {
      iat: now,
      jti: randomBytes(),
      htm,
      nonce,
      htu: `${url.origin}${url.pathname}`,
      ath: accessToken ? b64u(await crypto.subtle.digest("SHA-256", buf(accessToken))) : void 0
    };
    this.#modifyAssertion?.(this.#header, payload);
    headers2.set("dpop", await signJwt(this.#header, payload, this.#privateKey));
  }
  cacheNonce(response) {
    try {
      const nonce = response.headers.get("dpop-nonce");
      if (nonce) {
        this.#set(new URL(response.url).origin, nonce);
      }
    } catch {
    }
  }
};
function isDPoPNonceError(err) {
  if (err instanceof WWWAuthenticateChallengeError) {
    const { 0: challenge, length } = err.cause;
    return length === 1 && challenge.scheme === "dpop" && challenge.parameters.error === "use_dpop_nonce";
  }
  if (err instanceof ResponseBodyError) {
    return err.error === "use_dpop_nonce";
  }
  return false;
}
function DPoP(client, keyPair, options) {
  return new DPoPHandler(client, keyPair, options);
}
var ResponseBodyError = class extends Error {
  cause;
  code;
  error;
  status;
  error_description;
  response;
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    this.code = RESPONSE_BODY_ERROR;
    this.cause = options.cause;
    this.error = options.cause.error;
    this.status = options.response.status;
    this.error_description = options.cause.error_description;
    Object.defineProperty(this, "response", { enumerable: false, value: options.response });
    Error.captureStackTrace?.(this, this.constructor);
  }
};
var AuthorizationResponseError = class extends Error {
  cause;
  code;
  error;
  error_description;
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    this.code = AUTHORIZATION_RESPONSE_ERROR;
    this.cause = options.cause;
    this.error = options.cause.get("error");
    this.error_description = options.cause.get("error_description") ?? void 0;
    Error.captureStackTrace?.(this, this.constructor);
  }
};
var WWWAuthenticateChallengeError = class extends Error {
  cause;
  code;
  response;
  status;
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    this.code = WWW_AUTHENTICATE_CHALLENGE;
    this.cause = options.cause;
    this.status = options.response.status;
    this.response = options.response;
    Object.defineProperty(this, "response", { enumerable: false });
    Error.captureStackTrace?.(this, this.constructor);
  }
};
function unquote(value) {
  if (value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"') {
    return value.slice(1, -1);
  }
  return value;
}
var SPLIT_REGEXP = /((?:,|, )?[0-9a-zA-Z!#$%&'*+-.^_`|~]+=)/;
var SCHEMES_REGEXP = /(?:^|, ?)([0-9a-zA-Z!#$%&'*+\-.^_`|~]+)(?=$|[ ,])/g;
function wwwAuth(scheme, params) {
  const arr = params.split(SPLIT_REGEXP).slice(1);
  if (!arr.length) {
    return { scheme: scheme.toLowerCase(), parameters: {} };
  }
  arr[arr.length - 1] = arr[arr.length - 1].replace(/,$/, "");
  const parameters = {};
  for (let i = 1; i < arr.length; i += 2) {
    const idx = i;
    if (arr[idx][0] === '"') {
      while (arr[idx].slice(-1) !== '"' && ++i < arr.length) {
        arr[idx] += arr[i];
      }
    }
    const key = arr[idx - 1].replace(/^(?:, ?)|=$/g, "").toLowerCase();
    parameters[key] = unquote(arr[idx]);
  }
  return {
    scheme: scheme.toLowerCase(),
    parameters
  };
}
function parseWwwAuthenticateChallenges(response) {
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  const header = response.headers.get("www-authenticate");
  if (header === null) {
    return void 0;
  }
  const result = [];
  for (const { 1: scheme, index } of header.matchAll(SCHEMES_REGEXP)) {
    result.push([scheme, index]);
  }
  if (!result.length) {
    return void 0;
  }
  const challenges = result.map(([scheme, indexOf], i, others) => {
    const next = others[i + 1];
    let parameters;
    if (next) {
      parameters = header.slice(indexOf, next[1]);
    } else {
      parameters = header.slice(indexOf);
    }
    return wwwAuth(scheme, parameters);
  });
  return challenges;
}
async function processPushedAuthorizationResponse(as, client, response) {
  assertAs(as);
  assertClient(client);
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(response)) {
    throw new WWWAuthenticateChallengeError("server responded with a challenge in the WWW-Authenticate HTTP Header", { cause: challenges, response });
  }
  if (response.status !== 201) {
    let err;
    if (err = await handleOAuthBodyError(response)) {
      await response.body?.cancel();
      throw new ResponseBodyError("server responded with an error in the response body", {
        cause: err,
        response
      });
    }
    throw OPE('"response" is not a conform Pushed Authorization Request Endpoint response (unexpected HTTP status code)', RESPONSE_IS_NOT_CONFORM, response);
  }
  assertReadableResponse(response);
  assertApplicationJson(response);
  let json;
  try {
    json = await response.json();
  } catch (cause) {
    throw OPE('failed to parse "response" body as JSON', PARSE_ERROR, cause);
  }
  if (!isJsonObject(json)) {
    throw OPE('"response" body must be a top level object', INVALID_RESPONSE, { body: json });
  }
  assertString(json.request_uri, '"response" body "request_uri" property', INVALID_RESPONSE, {
    body: json
  });
  let expiresIn = typeof json.expires_in !== "number" ? parseFloat(json.expires_in) : json.expires_in;
  assertNumber(expiresIn, false, '"response" body "expires_in" property', INVALID_RESPONSE, {
    body: json
  });
  json.expires_in = expiresIn;
  return json;
}
function assertDPoP(option) {
  if (!branded.has(option)) {
    throw CodedTypeError('"options.DPoP" is not a valid DPoPHandle', ERR_INVALID_ARG_VALUE);
  }
}
async function resourceRequest(accessToken, method, url, headers2, body, options) {
  assertString(accessToken, '"accessToken"');
  if (!(url instanceof URL)) {
    throw CodedTypeError('"url" must be an instance of URL', ERR_INVALID_ARG_TYPE);
  }
  checkProtocol(url, options?.[allowInsecureRequests] !== true);
  headers2 = prepareHeaders(headers2);
  if (options?.DPoP) {
    assertDPoP(options.DPoP);
    await options.DPoP.addProof(url, headers2, method.toUpperCase(), accessToken);
    headers2.set("authorization", `DPoP ${accessToken}`);
  } else {
    headers2.set("authorization", `Bearer ${accessToken}`);
  }
  const response = await (options?.[customFetch] || fetch)(url.href, {
    body,
    headers: Object.fromEntries(headers2.entries()),
    method,
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : void 0
  });
  options?.DPoP?.cacheNonce(response);
  return response;
}
async function protectedResourceRequest(accessToken, method, url, headers2, body, options) {
  return resourceRequest(accessToken, method, url, headers2, body, options).then((response) => {
    let challenges;
    if (challenges = parseWwwAuthenticateChallenges(response)) {
      throw new WWWAuthenticateChallengeError("server responded with a challenge in the WWW-Authenticate HTTP Header", { cause: challenges, response });
    }
    return response;
  });
}
async function userInfoRequest(as, client, accessToken, options) {
  assertAs(as);
  assertClient(client);
  const url = resolveEndpoint(as, "userinfo_endpoint", client.use_mtls_endpoint_aliases, options?.[allowInsecureRequests] !== true);
  const headers2 = prepareHeaders(options?.headers);
  if (client.userinfo_signed_response_alg) {
    headers2.set("accept", "application/jwt");
  } else {
    headers2.set("accept", "application/json");
    headers2.append("accept", "application/jwt");
  }
  return resourceRequest(accessToken, "GET", url, headers2, null, {
    ...options,
    [clockSkew]: getClockSkew(client)
  });
}
var jwksMap;
function setJwksCache(as, jwks, uat, cache) {
  jwksMap ||= /* @__PURE__ */ new WeakMap();
  jwksMap.set(as, {
    jwks,
    uat,
    get age() {
      return epochTime() - this.uat;
    }
  });
  if (cache) {
    Object.assign(cache, { jwks: structuredClone(jwks), uat });
  }
}
function isFreshJwksCache(input) {
  if (typeof input !== "object" || input === null) {
    return false;
  }
  if (!("uat" in input) || typeof input.uat !== "number" || epochTime() - input.uat >= 300) {
    return false;
  }
  if (!("jwks" in input) || !isJsonObject(input.jwks) || !Array.isArray(input.jwks.keys) || !Array.prototype.every.call(input.jwks.keys, isJsonObject)) {
    return false;
  }
  return true;
}
function clearJwksCache(as, cache) {
  jwksMap?.delete(as);
  delete cache?.jwks;
  delete cache?.uat;
}
async function getPublicSigKeyFromIssuerJwksUri(as, options, header) {
  const { alg, kid } = header;
  checkSupportedJwsAlg(header);
  if (!jwksMap?.has(as) && isFreshJwksCache(options?.[jwksCache])) {
    setJwksCache(as, options?.[jwksCache].jwks, options?.[jwksCache].uat);
  }
  let jwks;
  let age;
  if (jwksMap?.has(as)) {
    ;
    ({ jwks, age } = jwksMap.get(as));
    if (age >= 300) {
      clearJwksCache(as, options?.[jwksCache]);
      return getPublicSigKeyFromIssuerJwksUri(as, options, header);
    }
  } else {
    jwks = await jwksRequest(as, options).then(processJwksResponse);
    age = 0;
    setJwksCache(as, jwks, epochTime(), options?.[jwksCache]);
  }
  let kty;
  switch (alg.slice(0, 2)) {
    case "RS":
    case "PS":
      kty = "RSA";
      break;
    case "ES":
      kty = "EC";
      break;
    case "Ed":
      kty = "OKP";
      break;
    default:
      throw new UnsupportedOperationError("unsupported JWS algorithm", { cause: { alg } });
  }
  const candidates = jwks.keys.filter((jwk2) => {
    if (jwk2.kty !== kty) {
      return false;
    }
    if (kid !== void 0 && kid !== jwk2.kid) {
      return false;
    }
    if (jwk2.alg !== void 0 && alg !== jwk2.alg) {
      return false;
    }
    if (jwk2.use !== void 0 && jwk2.use !== "sig") {
      return false;
    }
    if (jwk2.key_ops?.includes("verify") === false) {
      return false;
    }
    switch (true) {
      case (alg === "ES256" && jwk2.crv !== "P-256"):
      case (alg === "ES384" && jwk2.crv !== "P-384"):
      case (alg === "ES512" && jwk2.crv !== "P-521"):
      case (alg === "Ed25519" && jwk2.crv !== "Ed25519"):
      case (alg === "EdDSA" && jwk2.crv !== "Ed25519"):
        return false;
    }
    return true;
  });
  const { 0: jwk, length } = candidates;
  if (!length) {
    if (age >= 60) {
      clearJwksCache(as, options?.[jwksCache]);
      return getPublicSigKeyFromIssuerJwksUri(as, options, header);
    }
    throw OPE("error when selecting a JWT verification key, no applicable keys found", KEY_SELECTION, { header, candidates, jwks_uri: new URL(as.jwks_uri) });
  }
  if (length !== 1) {
    throw OPE('error when selecting a JWT verification key, multiple applicable keys found, a "kid" JWT Header Parameter is required', KEY_SELECTION, { header, candidates, jwks_uri: new URL(as.jwks_uri) });
  }
  return importJwk(alg, jwk);
}
var skipSubjectCheck = Symbol();
function getContentType(input) {
  return input.headers.get("content-type")?.split(";")[0];
}
async function processUserInfoResponse(as, client, expectedSubject, response, options) {
  assertAs(as);
  assertClient(client);
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(response)) {
    throw new WWWAuthenticateChallengeError("server responded with a challenge in the WWW-Authenticate HTTP Header", { cause: challenges, response });
  }
  if (response.status !== 200) {
    throw OPE('"response" is not a conform UserInfo Endpoint response (unexpected HTTP status code)', RESPONSE_IS_NOT_CONFORM, response);
  }
  assertReadableResponse(response);
  let json;
  if (getContentType(response) === "application/jwt") {
    const { claims, jwt } = await validateJwt(await response.text(), checkSigningAlgorithm.bind(void 0, client.userinfo_signed_response_alg, as.userinfo_signing_alg_values_supported, void 0), getClockSkew(client), getClockTolerance(client), options?.[jweDecrypt]).then(validateOptionalAudience.bind(void 0, client.client_id)).then(validateOptionalIssuer.bind(void 0, as));
    jwtRefs.set(response, jwt);
    json = claims;
  } else {
    if (client.userinfo_signed_response_alg) {
      throw OPE("JWT UserInfo Response expected", JWT_USERINFO_EXPECTED, response);
    }
    assertApplicationJson(response);
    try {
      json = await response.json();
    } catch (cause) {
      throw OPE('failed to parse "response" body as JSON', PARSE_ERROR, cause);
    }
  }
  if (!isJsonObject(json)) {
    throw OPE('"response" body must be a top level object', INVALID_RESPONSE, { body: json });
  }
  assertString(json.sub, '"response" body "sub" property', INVALID_RESPONSE, { body: json });
  switch (expectedSubject) {
    case skipSubjectCheck:
      break;
    default:
      assertString(expectedSubject, '"expectedSubject"');
      if (json.sub !== expectedSubject) {
        throw OPE('unexpected "response" body "sub" property value', JSON_ATTRIBUTE_COMPARISON, {
          expected: expectedSubject,
          body: json,
          attribute: "sub"
        });
      }
  }
  return json;
}
async function authenticatedRequest(as, client, clientAuthentication, url, body, headers2, options) {
  await clientAuthentication(as, client, body, headers2);
  headers2.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
  return (options?.[customFetch] || fetch)(url.href, {
    body,
    headers: Object.fromEntries(headers2.entries()),
    method: "POST",
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : void 0
  });
}
async function tokenEndpointRequest(as, client, clientAuthentication, grantType, parameters, options) {
  const url = resolveEndpoint(as, "token_endpoint", client.use_mtls_endpoint_aliases, options?.[allowInsecureRequests] !== true);
  parameters.set("grant_type", grantType);
  const headers2 = prepareHeaders(options?.headers);
  headers2.set("accept", "application/json");
  if (options?.DPoP !== void 0) {
    assertDPoP(options.DPoP);
    await options.DPoP.addProof(url, headers2, "POST");
  }
  const response = await authenticatedRequest(as, client, clientAuthentication, url, parameters, headers2, options);
  options?.DPoP?.cacheNonce(response);
  return response;
}
async function refreshTokenGrantRequest(as, client, clientAuthentication, refreshToken, options) {
  assertAs(as);
  assertClient(client);
  assertString(refreshToken, '"refreshToken"');
  const parameters = new URLSearchParams(options?.additionalParameters);
  parameters.set("refresh_token", refreshToken);
  return tokenEndpointRequest(as, client, clientAuthentication, "refresh_token", parameters, options);
}
var idTokenClaims = /* @__PURE__ */ new WeakMap();
var jwtRefs = /* @__PURE__ */ new WeakMap();
function getValidatedIdTokenClaims(ref) {
  if (!ref.id_token) {
    return void 0;
  }
  const claims = idTokenClaims.get(ref);
  if (!claims) {
    throw CodedTypeError('"ref" was already garbage collected or did not resolve from the proper sources', ERR_INVALID_ARG_VALUE);
  }
  return claims;
}
async function validateApplicationLevelSignature(as, ref, options) {
  assertAs(as);
  if (!jwtRefs.has(ref)) {
    throw CodedTypeError('"ref" does not contain a processed JWT Response to verify the signature of', ERR_INVALID_ARG_VALUE);
  }
  const { 0: protectedHeader, 1: payload, 2: encodedSignature } = jwtRefs.get(ref).split(".");
  const header = JSON.parse(buf(b64u(protectedHeader)));
  if (header.alg.startsWith("HS")) {
    throw new UnsupportedOperationError("unsupported JWS algorithm", { cause: { alg: header.alg } });
  }
  let key;
  key = await getPublicSigKeyFromIssuerJwksUri(as, options, header);
  await validateJwsSignature(protectedHeader, payload, key, b64u(encodedSignature));
}
async function processGenericAccessTokenResponse(as, client, response, additionalRequiredIdTokenClaims, options) {
  assertAs(as);
  assertClient(client);
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(response)) {
    throw new WWWAuthenticateChallengeError("server responded with a challenge in the WWW-Authenticate HTTP Header", { cause: challenges, response });
  }
  if (response.status !== 200) {
    let err;
    if (err = await handleOAuthBodyError(response)) {
      await response.body?.cancel();
      throw new ResponseBodyError("server responded with an error in the response body", {
        cause: err,
        response
      });
    }
    throw OPE('"response" is not a conform Token Endpoint response (unexpected HTTP status code)', RESPONSE_IS_NOT_CONFORM, response);
  }
  assertReadableResponse(response);
  assertApplicationJson(response);
  let json;
  try {
    json = await response.json();
  } catch (cause) {
    throw OPE('failed to parse "response" body as JSON', PARSE_ERROR, cause);
  }
  if (!isJsonObject(json)) {
    throw OPE('"response" body must be a top level object', INVALID_RESPONSE, { body: json });
  }
  assertString(json.access_token, '"response" body "access_token" property', INVALID_RESPONSE, {
    body: json
  });
  assertString(json.token_type, '"response" body "token_type" property', INVALID_RESPONSE, {
    body: json
  });
  json.token_type = json.token_type.toLowerCase();
  if (json.token_type !== "dpop" && json.token_type !== "bearer") {
    throw new UnsupportedOperationError("unsupported `token_type` value", { cause: { body: json } });
  }
  if (json.expires_in !== void 0) {
    let expiresIn = typeof json.expires_in !== "number" ? parseFloat(json.expires_in) : json.expires_in;
    assertNumber(expiresIn, false, '"response" body "expires_in" property', INVALID_RESPONSE, {
      body: json
    });
    json.expires_in = expiresIn;
  }
  if (json.refresh_token !== void 0) {
    assertString(json.refresh_token, '"response" body "refresh_token" property', INVALID_RESPONSE, {
      body: json
    });
  }
  if (json.scope !== void 0 && typeof json.scope !== "string") {
    throw OPE('"response" body "scope" property must be a string', INVALID_RESPONSE, { body: json });
  }
  if (json.id_token !== void 0) {
    assertString(json.id_token, '"response" body "id_token" property', INVALID_RESPONSE, {
      body: json
    });
    const requiredClaims = ["aud", "exp", "iat", "iss", "sub"];
    if (client.require_auth_time === true) {
      requiredClaims.push("auth_time");
    }
    if (client.default_max_age !== void 0) {
      assertNumber(client.default_max_age, false, '"client.default_max_age"');
      requiredClaims.push("auth_time");
    }
    if (additionalRequiredIdTokenClaims?.length) {
      requiredClaims.push(...additionalRequiredIdTokenClaims);
    }
    const { claims, jwt } = await validateJwt(json.id_token, checkSigningAlgorithm.bind(void 0, client.id_token_signed_response_alg, as.id_token_signing_alg_values_supported, "RS256"), getClockSkew(client), getClockTolerance(client), options?.[jweDecrypt]).then(validatePresence.bind(void 0, requiredClaims)).then(validateIssuer.bind(void 0, as)).then(validateAudience.bind(void 0, client.client_id));
    if (Array.isArray(claims.aud) && claims.aud.length !== 1) {
      if (claims.azp === void 0) {
        throw OPE('ID Token "aud" (audience) claim includes additional untrusted audiences', JWT_CLAIM_COMPARISON, { claims, claim: "aud" });
      }
      if (claims.azp !== client.client_id) {
        throw OPE('unexpected ID Token "azp" (authorized party) claim value', JWT_CLAIM_COMPARISON, { expected: client.client_id, claims, claim: "azp" });
      }
    }
    if (claims.auth_time !== void 0) {
      assertNumber(claims.auth_time, false, 'ID Token "auth_time" (authentication time)', INVALID_RESPONSE, { claims });
    }
    jwtRefs.set(response, jwt);
    idTokenClaims.set(json, claims);
  }
  return json;
}
async function processRefreshTokenResponse(as, client, response, options) {
  return processGenericAccessTokenResponse(as, client, response, void 0, options);
}
function validateOptionalAudience(expected, result) {
  if (result.claims.aud !== void 0) {
    return validateAudience(expected, result);
  }
  return result;
}
function validateAudience(expected, result) {
  if (Array.isArray(result.claims.aud)) {
    if (!result.claims.aud.includes(expected)) {
      throw OPE('unexpected JWT "aud" (audience) claim value', JWT_CLAIM_COMPARISON, {
        expected,
        claims: result.claims,
        claim: "aud"
      });
    }
  } else if (result.claims.aud !== expected) {
    throw OPE('unexpected JWT "aud" (audience) claim value', JWT_CLAIM_COMPARISON, {
      expected,
      claims: result.claims,
      claim: "aud"
    });
  }
  return result;
}
function validateOptionalIssuer(as, result) {
  if (result.claims.iss !== void 0) {
    return validateIssuer(as, result);
  }
  return result;
}
function validateIssuer(as, result) {
  const expected = as[_expectedIssuer]?.(result) ?? as.issuer;
  if (result.claims.iss !== expected) {
    throw OPE('unexpected JWT "iss" (issuer) claim value', JWT_CLAIM_COMPARISON, {
      expected,
      claims: result.claims,
      claim: "iss"
    });
  }
  return result;
}
var branded = /* @__PURE__ */ new WeakSet();
function brand(searchParams) {
  branded.add(searchParams);
  return searchParams;
}
async function authorizationCodeGrantRequest(as, client, clientAuthentication, callbackParameters, redirectUri, codeVerifier, options) {
  assertAs(as);
  assertClient(client);
  if (!branded.has(callbackParameters)) {
    throw CodedTypeError('"callbackParameters" must be an instance of URLSearchParams obtained from "validateAuthResponse()", or "validateJwtAuthResponse()', ERR_INVALID_ARG_VALUE);
  }
  assertString(redirectUri, '"redirectUri"');
  const code = getURLSearchParameter(callbackParameters, "code");
  if (!code) {
    throw OPE('no authorization code in "callbackParameters"', INVALID_RESPONSE);
  }
  const parameters = new URLSearchParams(options?.additionalParameters);
  parameters.set("redirect_uri", redirectUri);
  parameters.set("code", code);
  if (codeVerifier !== _nopkce) {
    assertString(codeVerifier, '"codeVerifier"');
    parameters.set("code_verifier", codeVerifier);
  }
  return tokenEndpointRequest(as, client, clientAuthentication, "authorization_code", parameters, options);
}
var jwtClaimNames = {
  aud: "audience",
  c_hash: "code hash",
  client_id: "client id",
  exp: "expiration time",
  iat: "issued at",
  iss: "issuer",
  jti: "jwt id",
  nonce: "nonce",
  s_hash: "state hash",
  sub: "subject",
  ath: "access token hash",
  htm: "http method",
  htu: "http uri",
  cnf: "confirmation",
  auth_time: "authentication time"
};
function validatePresence(required, result) {
  for (const claim of required) {
    if (result.claims[claim] === void 0) {
      throw OPE(`JWT "${claim}" (${jwtClaimNames[claim]}) claim missing`, INVALID_RESPONSE, {
        claims: result.claims
      });
    }
  }
  return result;
}
var expectNoNonce = Symbol();
var skipAuthTimeCheck = Symbol();
async function processAuthorizationCodeResponse(as, client, response, options) {
  if (typeof options?.expectedNonce === "string" || typeof options?.maxAge === "number" || options?.requireIdToken) {
    return processAuthorizationCodeOpenIDResponse(as, client, response, options.expectedNonce, options.maxAge, {
      [jweDecrypt]: options[jweDecrypt]
    });
  }
  return processAuthorizationCodeOAuth2Response(as, client, response, options);
}
async function processAuthorizationCodeOpenIDResponse(as, client, response, expectedNonce, maxAge, options) {
  const additionalRequiredClaims = [];
  switch (expectedNonce) {
    case void 0:
      expectedNonce = expectNoNonce;
      break;
    case expectNoNonce:
      break;
    default:
      assertString(expectedNonce, '"expectedNonce" argument');
      additionalRequiredClaims.push("nonce");
  }
  maxAge ??= client.default_max_age;
  switch (maxAge) {
    case void 0:
      maxAge = skipAuthTimeCheck;
      break;
    case skipAuthTimeCheck:
      break;
    default:
      assertNumber(maxAge, false, '"maxAge" argument');
      additionalRequiredClaims.push("auth_time");
  }
  const result = await processGenericAccessTokenResponse(as, client, response, additionalRequiredClaims, options);
  assertString(result.id_token, '"response" body "id_token" property', INVALID_RESPONSE, {
    body: result
  });
  const claims = getValidatedIdTokenClaims(result);
  if (maxAge !== skipAuthTimeCheck) {
    const now = epochTime() + getClockSkew(client);
    const tolerance = getClockTolerance(client);
    if (claims.auth_time + maxAge < now - tolerance) {
      throw OPE("too much time has elapsed since the last End-User authentication", JWT_TIMESTAMP_CHECK, { claims, now, tolerance, claim: "auth_time" });
    }
  }
  if (expectedNonce === expectNoNonce) {
    if (claims.nonce !== void 0) {
      throw OPE('unexpected ID Token "nonce" claim value', JWT_CLAIM_COMPARISON, {
        expected: void 0,
        claims,
        claim: "nonce"
      });
    }
  } else if (claims.nonce !== expectedNonce) {
    throw OPE('unexpected ID Token "nonce" claim value', JWT_CLAIM_COMPARISON, {
      expected: expectedNonce,
      claims,
      claim: "nonce"
    });
  }
  return result;
}
async function processAuthorizationCodeOAuth2Response(as, client, response, options) {
  const result = await processGenericAccessTokenResponse(as, client, response, void 0, options);
  const claims = getValidatedIdTokenClaims(result);
  if (claims) {
    if (client.default_max_age !== void 0) {
      assertNumber(client.default_max_age, false, '"client.default_max_age"');
      const now = epochTime() + getClockSkew(client);
      const tolerance = getClockTolerance(client);
      if (claims.auth_time + client.default_max_age < now - tolerance) {
        throw OPE("too much time has elapsed since the last End-User authentication", JWT_TIMESTAMP_CHECK, { claims, now, tolerance, claim: "auth_time" });
      }
    }
    if (claims.nonce !== void 0) {
      throw OPE('unexpected ID Token "nonce" claim value', JWT_CLAIM_COMPARISON, {
        expected: void 0,
        claims,
        claim: "nonce"
      });
    }
  }
  return result;
}
var WWW_AUTHENTICATE_CHALLENGE = "OAUTH_WWW_AUTHENTICATE_CHALLENGE";
var RESPONSE_BODY_ERROR = "OAUTH_RESPONSE_BODY_ERROR";
var UNSUPPORTED_OPERATION = "OAUTH_UNSUPPORTED_OPERATION";
var AUTHORIZATION_RESPONSE_ERROR = "OAUTH_AUTHORIZATION_RESPONSE_ERROR";
var JWT_USERINFO_EXPECTED = "OAUTH_JWT_USERINFO_EXPECTED";
var PARSE_ERROR = "OAUTH_PARSE_ERROR";
var INVALID_RESPONSE = "OAUTH_INVALID_RESPONSE";
var RESPONSE_IS_NOT_JSON = "OAUTH_RESPONSE_IS_NOT_JSON";
var RESPONSE_IS_NOT_CONFORM = "OAUTH_RESPONSE_IS_NOT_CONFORM";
var HTTP_REQUEST_FORBIDDEN = "OAUTH_HTTP_REQUEST_FORBIDDEN";
var REQUEST_PROTOCOL_FORBIDDEN = "OAUTH_REQUEST_PROTOCOL_FORBIDDEN";
var JWT_TIMESTAMP_CHECK = "OAUTH_JWT_TIMESTAMP_CHECK_FAILED";
var JWT_CLAIM_COMPARISON = "OAUTH_JWT_CLAIM_COMPARISON_FAILED";
var JSON_ATTRIBUTE_COMPARISON = "OAUTH_JSON_ATTRIBUTE_COMPARISON_FAILED";
var KEY_SELECTION = "OAUTH_KEY_SELECTION_FAILED";
var MISSING_SERVER_METADATA = "OAUTH_MISSING_SERVER_METADATA";
var INVALID_SERVER_METADATA = "OAUTH_INVALID_SERVER_METADATA";
function checkJwtType(expected, result) {
  if (typeof result.header.typ !== "string" || normalizeTyp(result.header.typ) !== expected) {
    throw OPE('unexpected JWT "typ" header parameter value', INVALID_RESPONSE, {
      header: result.header
    });
  }
  return result;
}
async function clientCredentialsGrantRequest(as, client, clientAuthentication, parameters, options) {
  assertAs(as);
  assertClient(client);
  return tokenEndpointRequest(as, client, clientAuthentication, "client_credentials", new URLSearchParams(parameters), options);
}
async function genericTokenEndpointRequest(as, client, clientAuthentication, grantType, parameters, options) {
  assertAs(as);
  assertClient(client);
  assertString(grantType, '"grantType"');
  return tokenEndpointRequest(as, client, clientAuthentication, grantType, new URLSearchParams(parameters), options);
}
async function processGenericTokenEndpointResponse(as, client, response, options) {
  return processGenericAccessTokenResponse(as, client, response, void 0, options);
}
async function processClientCredentialsResponse(as, client, response, options) {
  return processGenericAccessTokenResponse(as, client, response, void 0, options);
}
async function revocationRequest(as, client, clientAuthentication, token, options) {
  assertAs(as);
  assertClient(client);
  assertString(token, '"token"');
  const url = resolveEndpoint(as, "revocation_endpoint", client.use_mtls_endpoint_aliases, options?.[allowInsecureRequests] !== true);
  const body = new URLSearchParams(options?.additionalParameters);
  body.set("token", token);
  const headers2 = prepareHeaders(options?.headers);
  headers2.delete("accept");
  return authenticatedRequest(as, client, clientAuthentication, url, body, headers2, options);
}
async function processRevocationResponse(response) {
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(response)) {
    throw new WWWAuthenticateChallengeError("server responded with a challenge in the WWW-Authenticate HTTP Header", { cause: challenges, response });
  }
  if (response.status !== 200) {
    let err;
    if (err = await handleOAuthBodyError(response)) {
      await response.body?.cancel();
      throw new ResponseBodyError("server responded with an error in the response body", {
        cause: err,
        response
      });
    }
    throw OPE('"response" is not a conform Revocation Endpoint response (unexpected HTTP status code)', RESPONSE_IS_NOT_CONFORM, response);
  }
  return void 0;
}
function assertReadableResponse(response) {
  if (response.bodyUsed) {
    throw CodedTypeError('"response" body has been used already', ERR_INVALID_ARG_VALUE);
  }
}
async function introspectionRequest(as, client, clientAuthentication, token, options) {
  assertAs(as);
  assertClient(client);
  assertString(token, '"token"');
  const url = resolveEndpoint(as, "introspection_endpoint", client.use_mtls_endpoint_aliases, options?.[allowInsecureRequests] !== true);
  const body = new URLSearchParams(options?.additionalParameters);
  body.set("token", token);
  const headers2 = prepareHeaders(options?.headers);
  if (options?.requestJwtResponse ?? client.introspection_signed_response_alg) {
    headers2.set("accept", "application/token-introspection+jwt");
  } else {
    headers2.set("accept", "application/json");
  }
  return authenticatedRequest(as, client, clientAuthentication, url, body, headers2, options);
}
async function processIntrospectionResponse(as, client, response, options) {
  assertAs(as);
  assertClient(client);
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(response)) {
    throw new WWWAuthenticateChallengeError("server responded with a challenge in the WWW-Authenticate HTTP Header", { cause: challenges, response });
  }
  if (response.status !== 200) {
    let err;
    if (err = await handleOAuthBodyError(response)) {
      await response.body?.cancel();
      throw new ResponseBodyError("server responded with an error in the response body", {
        cause: err,
        response
      });
    }
    throw OPE('"response" is not a conform Introspection Endpoint response (unexpected HTTP status code)', RESPONSE_IS_NOT_CONFORM, response);
  }
  let json;
  if (getContentType(response) === "application/token-introspection+jwt") {
    assertReadableResponse(response);
    const { claims, jwt } = await validateJwt(await response.text(), checkSigningAlgorithm.bind(void 0, client.introspection_signed_response_alg, as.introspection_signing_alg_values_supported, "RS256"), getClockSkew(client), getClockTolerance(client), options?.[jweDecrypt]).then(checkJwtType.bind(void 0, "token-introspection+jwt")).then(validatePresence.bind(void 0, ["aud", "iat", "iss"])).then(validateIssuer.bind(void 0, as)).then(validateAudience.bind(void 0, client.client_id));
    jwtRefs.set(response, jwt);
    json = claims.token_introspection;
    if (!isJsonObject(json)) {
      throw OPE('JWT "token_introspection" claim must be a JSON object', INVALID_RESPONSE, {
        claims
      });
    }
  } else {
    assertReadableResponse(response);
    assertApplicationJson(response);
    try {
      json = await response.json();
    } catch (cause) {
      throw OPE('failed to parse "response" body as JSON', PARSE_ERROR, cause);
    }
    if (!isJsonObject(json)) {
      throw OPE('"response" body must be a top level object', INVALID_RESPONSE, { body: json });
    }
  }
  if (typeof json.active !== "boolean") {
    throw OPE('"response" body "active" property must be a boolean', INVALID_RESPONSE, {
      body: json
    });
  }
  return json;
}
async function jwksRequest(as, options) {
  assertAs(as);
  const url = resolveEndpoint(as, "jwks_uri", false, options?.[allowInsecureRequests] !== true);
  const headers2 = prepareHeaders(options?.headers);
  headers2.set("accept", "application/json");
  headers2.append("accept", "application/jwk-set+json");
  return (options?.[customFetch] || fetch)(url.href, {
    body: void 0,
    headers: Object.fromEntries(headers2.entries()),
    method: "GET",
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : void 0
  });
}
async function processJwksResponse(response) {
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  if (response.status !== 200) {
    throw OPE('"response" is not a conform JSON Web Key Set response (unexpected HTTP status code)', RESPONSE_IS_NOT_CONFORM, response);
  }
  assertReadableResponse(response);
  assertContentTypes(response, "application/json", "application/jwk-set+json");
  let json;
  try {
    json = await response.json();
  } catch (cause) {
    throw OPE('failed to parse "response" body as JSON', PARSE_ERROR, cause);
  }
  if (!isJsonObject(json)) {
    throw OPE('"response" body must be a top level object', INVALID_RESPONSE, { body: json });
  }
  if (!Array.isArray(json.keys)) {
    throw OPE('"response" body "keys" property must be an array', INVALID_RESPONSE, { body: json });
  }
  if (!Array.prototype.every.call(json.keys, isJsonObject)) {
    throw OPE('"response" body "keys" property members must be JWK formatted objects', INVALID_RESPONSE, { body: json });
  }
  return json;
}
async function handleOAuthBodyError(response) {
  if (response.status > 399 && response.status < 500) {
    assertReadableResponse(response);
    assertApplicationJson(response);
    try {
      const json = await response.clone().json();
      if (isJsonObject(json) && typeof json.error === "string" && json.error.length) {
        return json;
      }
    } catch {
    }
  }
  return void 0;
}
function supported(alg) {
  switch (alg) {
    case "PS256":
    case "ES256":
    case "RS256":
    case "PS384":
    case "ES384":
    case "RS384":
    case "PS512":
    case "ES512":
    case "RS512":
    case "Ed25519":
    case "EdDSA":
      return true;
    default:
      return false;
  }
}
function checkSupportedJwsAlg(header) {
  if (!supported(header.alg)) {
    throw new UnsupportedOperationError('unsupported JWS "alg" identifier', {
      cause: { alg: header.alg }
    });
  }
}
function checkRsaKeyAlgorithm(key) {
  const { algorithm } = key;
  if (typeof algorithm.modulusLength !== "number" || algorithm.modulusLength < 2048) {
    throw new UnsupportedOperationError(`unsupported ${algorithm.name} modulusLength`, {
      cause: key
    });
  }
}
function ecdsaHashName(key) {
  const { algorithm } = key;
  switch (algorithm.namedCurve) {
    case "P-256":
      return "SHA-256";
    case "P-384":
      return "SHA-384";
    case "P-521":
      return "SHA-512";
    default:
      throw new UnsupportedOperationError("unsupported ECDSA namedCurve", { cause: key });
  }
}
function keyToSubtle(key) {
  switch (key.algorithm.name) {
    case "ECDSA":
      return {
        name: key.algorithm.name,
        hash: ecdsaHashName(key)
      };
    case "RSA-PSS": {
      checkRsaKeyAlgorithm(key);
      switch (key.algorithm.hash.name) {
        case "SHA-256":
        case "SHA-384":
        case "SHA-512":
          return {
            name: key.algorithm.name,
            saltLength: parseInt(key.algorithm.hash.name.slice(-3), 10) >> 3
          };
        default:
          throw new UnsupportedOperationError("unsupported RSA-PSS hash name", { cause: key });
      }
    }
    case "RSASSA-PKCS1-v1_5":
      checkRsaKeyAlgorithm(key);
      return key.algorithm.name;
    case "Ed25519":
    case "EdDSA":
      return key.algorithm.name;
  }
  throw new UnsupportedOperationError("unsupported CryptoKey algorithm name", { cause: key });
}
async function validateJwsSignature(protectedHeader, payload, key, signature) {
  const data = buf(`${protectedHeader}.${payload}`);
  const algorithm = keyToSubtle(key);
  const verified = await crypto.subtle.verify(algorithm, key, signature, data);
  if (!verified) {
    throw OPE("JWT signature verification failed", INVALID_RESPONSE, {
      key,
      data,
      signature,
      algorithm
    });
  }
}
async function validateJwt(jws, checkAlg, clockSkew3, clockTolerance3, decryptJwt) {
  let { 0: protectedHeader, 1: payload, length } = jws.split(".");
  if (length === 5) {
    if (decryptJwt !== void 0) {
      jws = await decryptJwt(jws);
      ({ 0: protectedHeader, 1: payload, length } = jws.split("."));
    } else {
      throw new UnsupportedOperationError("JWE decryption is not configured", { cause: jws });
    }
  }
  if (length !== 3) {
    throw OPE("Invalid JWT", INVALID_RESPONSE, jws);
  }
  let header;
  try {
    header = JSON.parse(buf(b64u(protectedHeader)));
  } catch (cause) {
    throw OPE("failed to parse JWT Header body as base64url encoded JSON", PARSE_ERROR, cause);
  }
  if (!isJsonObject(header)) {
    throw OPE("JWT Header must be a top level object", INVALID_RESPONSE, jws);
  }
  checkAlg(header);
  if (header.crit !== void 0) {
    throw new UnsupportedOperationError('no JWT "crit" header parameter extensions are supported', {
      cause: { header }
    });
  }
  let claims;
  try {
    claims = JSON.parse(buf(b64u(payload)));
  } catch (cause) {
    throw OPE("failed to parse JWT Payload body as base64url encoded JSON", PARSE_ERROR, cause);
  }
  if (!isJsonObject(claims)) {
    throw OPE("JWT Payload must be a top level object", INVALID_RESPONSE, jws);
  }
  const now = epochTime() + clockSkew3;
  if (claims.exp !== void 0) {
    if (typeof claims.exp !== "number") {
      throw OPE('unexpected JWT "exp" (expiration time) claim type', INVALID_RESPONSE, { claims });
    }
    if (claims.exp <= now - clockTolerance3) {
      throw OPE('unexpected JWT "exp" (expiration time) claim value, expiration is past current timestamp', JWT_TIMESTAMP_CHECK, { claims, now, tolerance: clockTolerance3, claim: "exp" });
    }
  }
  if (claims.iat !== void 0) {
    if (typeof claims.iat !== "number") {
      throw OPE('unexpected JWT "iat" (issued at) claim type', INVALID_RESPONSE, { claims });
    }
  }
  if (claims.iss !== void 0) {
    if (typeof claims.iss !== "string") {
      throw OPE('unexpected JWT "iss" (issuer) claim type', INVALID_RESPONSE, { claims });
    }
  }
  if (claims.nbf !== void 0) {
    if (typeof claims.nbf !== "number") {
      throw OPE('unexpected JWT "nbf" (not before) claim type', INVALID_RESPONSE, { claims });
    }
    if (claims.nbf > now + clockTolerance3) {
      throw OPE('unexpected JWT "nbf" (not before) claim value', JWT_TIMESTAMP_CHECK, {
        claims,
        now,
        tolerance: clockTolerance3,
        claim: "nbf"
      });
    }
  }
  if (claims.aud !== void 0) {
    if (typeof claims.aud !== "string" && !Array.isArray(claims.aud)) {
      throw OPE('unexpected JWT "aud" (audience) claim type', INVALID_RESPONSE, { claims });
    }
  }
  return { header, claims, jwt: jws };
}
async function validateJwtAuthResponse(as, client, parameters, expectedState, options) {
  assertAs(as);
  assertClient(client);
  if (parameters instanceof URL) {
    parameters = parameters.searchParams;
  }
  if (!(parameters instanceof URLSearchParams)) {
    throw CodedTypeError('"parameters" must be an instance of URLSearchParams, or URL', ERR_INVALID_ARG_TYPE);
  }
  const response = getURLSearchParameter(parameters, "response");
  if (!response) {
    throw OPE('"parameters" does not contain a JARM response', INVALID_RESPONSE);
  }
  const { claims, header, jwt } = await validateJwt(response, checkSigningAlgorithm.bind(void 0, client.authorization_signed_response_alg, as.authorization_signing_alg_values_supported, "RS256"), getClockSkew(client), getClockTolerance(client), options?.[jweDecrypt]).then(validatePresence.bind(void 0, ["aud", "exp", "iss"])).then(validateIssuer.bind(void 0, as)).then(validateAudience.bind(void 0, client.client_id));
  const { 0: protectedHeader, 1: payload, 2: encodedSignature } = jwt.split(".");
  const signature = b64u(encodedSignature);
  const key = await getPublicSigKeyFromIssuerJwksUri(as, options, header);
  await validateJwsSignature(protectedHeader, payload, key, signature);
  const result = new URLSearchParams();
  for (const [key2, value] of Object.entries(claims)) {
    if (typeof value === "string" && key2 !== "aud") {
      result.set(key2, value);
    }
  }
  return validateAuthResponse(as, client, result, expectedState);
}
async function idTokenHash(data, header, claimName) {
  let algorithm;
  switch (header.alg) {
    case "RS256":
    case "PS256":
    case "ES256":
      algorithm = "SHA-256";
      break;
    case "RS384":
    case "PS384":
    case "ES384":
      algorithm = "SHA-384";
      break;
    case "RS512":
    case "PS512":
    case "ES512":
    case "Ed25519":
    case "EdDSA":
      algorithm = "SHA-512";
      break;
    default:
      throw new UnsupportedOperationError(`unsupported JWS algorithm for ${claimName} calculation`, { cause: { alg: header.alg } });
  }
  const digest2 = await crypto.subtle.digest(algorithm, buf(data));
  return b64u(digest2.slice(0, digest2.byteLength / 2));
}
async function idTokenHashMatches(data, actual, header, claimName) {
  const expected = await idTokenHash(data, header, claimName);
  return actual === expected;
}
async function validateDetachedSignatureResponse(as, client, parameters, expectedNonce, expectedState, maxAge, options) {
  return validateHybridResponse(as, client, parameters, expectedNonce, expectedState, maxAge, options, true);
}
async function validateCodeIdTokenResponse(as, client, parameters, expectedNonce, expectedState, maxAge, options) {
  return validateHybridResponse(as, client, parameters, expectedNonce, expectedState, maxAge, options, false);
}
async function consumeStream(request) {
  if (request.bodyUsed) {
    throw CodedTypeError("form_post Request instances must contain a readable body", ERR_INVALID_ARG_VALUE, { cause: request });
  }
  return request.text();
}
async function formPostResponse(request) {
  if (request.method !== "POST") {
    throw CodedTypeError("form_post responses are expected to use the POST method", ERR_INVALID_ARG_VALUE, { cause: request });
  }
  if (getContentType(request) !== "application/x-www-form-urlencoded") {
    throw CodedTypeError("form_post responses are expected to use the application/x-www-form-urlencoded content-type", ERR_INVALID_ARG_VALUE, { cause: request });
  }
  return consumeStream(request);
}
async function validateHybridResponse(as, client, parameters, expectedNonce, expectedState, maxAge, options, fapi) {
  assertAs(as);
  assertClient(client);
  if (parameters instanceof URL) {
    if (!parameters.hash.length) {
      throw CodedTypeError('"parameters" as an instance of URL must contain a hash (fragment) with the Authorization Response parameters', ERR_INVALID_ARG_VALUE);
    }
    parameters = new URLSearchParams(parameters.hash.slice(1));
  } else if (looseInstanceOf(parameters, Request)) {
    parameters = new URLSearchParams(await formPostResponse(parameters));
  } else if (parameters instanceof URLSearchParams) {
    parameters = new URLSearchParams(parameters);
  } else {
    throw CodedTypeError('"parameters" must be an instance of URLSearchParams, URL, or Response', ERR_INVALID_ARG_TYPE);
  }
  const id_token = getURLSearchParameter(parameters, "id_token");
  parameters.delete("id_token");
  switch (expectedState) {
    case void 0:
    case expectNoState:
      break;
    default:
      assertString(expectedState, '"expectedState" argument');
  }
  const result = validateAuthResponse({
    ...as,
    authorization_response_iss_parameter_supported: false
  }, client, parameters, expectedState);
  if (!id_token) {
    throw OPE('"parameters" does not contain an ID Token', INVALID_RESPONSE);
  }
  const code = getURLSearchParameter(parameters, "code");
  if (!code) {
    throw OPE('"parameters" does not contain an Authorization Code', INVALID_RESPONSE);
  }
  const requiredClaims = [
    "aud",
    "exp",
    "iat",
    "iss",
    "sub",
    "nonce",
    "c_hash"
  ];
  const state = parameters.get("state");
  if (fapi && (typeof expectedState === "string" || state !== null)) {
    requiredClaims.push("s_hash");
  }
  if (maxAge !== void 0) {
    assertNumber(maxAge, false, '"maxAge" argument');
  } else if (client.default_max_age !== void 0) {
    assertNumber(client.default_max_age, false, '"client.default_max_age"');
  }
  maxAge ??= client.default_max_age ?? skipAuthTimeCheck;
  if (client.require_auth_time || maxAge !== skipAuthTimeCheck) {
    requiredClaims.push("auth_time");
  }
  const { claims, header, jwt } = await validateJwt(id_token, checkSigningAlgorithm.bind(void 0, client.id_token_signed_response_alg, as.id_token_signing_alg_values_supported, "RS256"), getClockSkew(client), getClockTolerance(client), options?.[jweDecrypt]).then(validatePresence.bind(void 0, requiredClaims)).then(validateIssuer.bind(void 0, as)).then(validateAudience.bind(void 0, client.client_id));
  const clockSkew3 = getClockSkew(client);
  const now = epochTime() + clockSkew3;
  if (claims.iat < now - 3600) {
    throw OPE('unexpected JWT "iat" (issued at) claim value, it is too far in the past', JWT_TIMESTAMP_CHECK, { now, claims, claim: "iat" });
  }
  assertString(claims.c_hash, 'ID Token "c_hash" (code hash) claim value', INVALID_RESPONSE, {
    claims
  });
  if (claims.auth_time !== void 0) {
    assertNumber(claims.auth_time, false, 'ID Token "auth_time" (authentication time)', INVALID_RESPONSE, { claims });
  }
  if (maxAge !== skipAuthTimeCheck) {
    const now2 = epochTime() + getClockSkew(client);
    const tolerance = getClockTolerance(client);
    if (claims.auth_time + maxAge < now2 - tolerance) {
      throw OPE("too much time has elapsed since the last End-User authentication", JWT_TIMESTAMP_CHECK, { claims, now: now2, tolerance, claim: "auth_time" });
    }
  }
  assertString(expectedNonce, '"expectedNonce" argument');
  if (claims.nonce !== expectedNonce) {
    throw OPE('unexpected ID Token "nonce" claim value', JWT_CLAIM_COMPARISON, {
      expected: expectedNonce,
      claims,
      claim: "nonce"
    });
  }
  if (Array.isArray(claims.aud) && claims.aud.length !== 1) {
    if (claims.azp === void 0) {
      throw OPE('ID Token "aud" (audience) claim includes additional untrusted audiences', JWT_CLAIM_COMPARISON, { claims, claim: "aud" });
    }
    if (claims.azp !== client.client_id) {
      throw OPE('unexpected ID Token "azp" (authorized party) claim value', JWT_CLAIM_COMPARISON, {
        expected: client.client_id,
        claims,
        claim: "azp"
      });
    }
  }
  const { 0: protectedHeader, 1: payload, 2: encodedSignature } = jwt.split(".");
  const signature = b64u(encodedSignature);
  const key = await getPublicSigKeyFromIssuerJwksUri(as, options, header);
  await validateJwsSignature(protectedHeader, payload, key, signature);
  if (await idTokenHashMatches(code, claims.c_hash, header, "c_hash") !== true) {
    throw OPE('invalid ID Token "c_hash" (code hash) claim value', JWT_CLAIM_COMPARISON, {
      code,
      alg: header.alg,
      claim: "c_hash",
      claims
    });
  }
  if (fapi && state !== null || claims.s_hash !== void 0) {
    assertString(claims.s_hash, 'ID Token "s_hash" (state hash) claim value', INVALID_RESPONSE, {
      claims
    });
    assertString(state, '"state" response parameter', INVALID_RESPONSE, { parameters });
    if (await idTokenHashMatches(state, claims.s_hash, header, "s_hash") !== true) {
      throw OPE('invalid ID Token "s_hash" (state hash) claim value', JWT_CLAIM_COMPARISON, {
        state,
        alg: header.alg,
        claim: "s_hash",
        claims
      });
    }
  }
  return result;
}
function checkSigningAlgorithm(client, issuer, fallback, header) {
  if (client !== void 0) {
    if (typeof client === "string" ? header.alg !== client : !client.includes(header.alg)) {
      throw OPE('unexpected JWT "alg" header parameter', INVALID_RESPONSE, {
        header,
        expected: client,
        reason: "client configuration"
      });
    }
    return;
  }
  if (Array.isArray(issuer)) {
    if (!issuer.includes(header.alg)) {
      throw OPE('unexpected JWT "alg" header parameter', INVALID_RESPONSE, {
        header,
        expected: issuer,
        reason: "authorization server metadata"
      });
    }
    return;
  }
  if (fallback !== void 0) {
    if (typeof fallback === "string" ? header.alg !== fallback : typeof fallback === "function" ? !fallback(header.alg) : !fallback.includes(header.alg)) {
      throw OPE('unexpected JWT "alg" header parameter', INVALID_RESPONSE, {
        header,
        expected: fallback,
        reason: "default value"
      });
    }
    return;
  }
  throw OPE('missing client or server configuration to verify used JWT "alg" header parameter', void 0, { client, issuer, fallback });
}
function getURLSearchParameter(parameters, name) {
  const { 0: value, length } = parameters.getAll(name);
  if (length > 1) {
    throw OPE(`"${name}" parameter must be provided only once`, INVALID_RESPONSE);
  }
  return value;
}
var skipStateCheck = Symbol();
var expectNoState = Symbol();
function validateAuthResponse(as, client, parameters, expectedState) {
  assertAs(as);
  assertClient(client);
  if (parameters instanceof URL) {
    parameters = parameters.searchParams;
  }
  if (!(parameters instanceof URLSearchParams)) {
    throw CodedTypeError('"parameters" must be an instance of URLSearchParams, or URL', ERR_INVALID_ARG_TYPE);
  }
  if (getURLSearchParameter(parameters, "response")) {
    throw OPE('"parameters" contains a JARM response, use validateJwtAuthResponse() instead of validateAuthResponse()', INVALID_RESPONSE, { parameters });
  }
  const iss = getURLSearchParameter(parameters, "iss");
  const state = getURLSearchParameter(parameters, "state");
  if (!iss && as.authorization_response_iss_parameter_supported) {
    throw OPE('response parameter "iss" (issuer) missing', INVALID_RESPONSE, { parameters });
  }
  if (iss && iss !== as.issuer) {
    throw OPE('unexpected "iss" (issuer) response parameter value', INVALID_RESPONSE, {
      expected: as.issuer,
      parameters
    });
  }
  switch (expectedState) {
    case void 0:
    case expectNoState:
      if (state !== void 0) {
        throw OPE('unexpected "state" response parameter encountered', INVALID_RESPONSE, {
          expected: void 0,
          parameters
        });
      }
      break;
    case skipStateCheck:
      break;
    default:
      assertString(expectedState, '"expectedState" argument');
      if (state !== expectedState) {
        throw OPE(state === void 0 ? 'response parameter "state" missing' : 'unexpected "state" response parameter value', INVALID_RESPONSE, { expected: expectedState, parameters });
      }
  }
  const error = getURLSearchParameter(parameters, "error");
  if (error) {
    throw new AuthorizationResponseError("authorization response from the server is an error", {
      cause: parameters
    });
  }
  const id_token = getURLSearchParameter(parameters, "id_token");
  const token = getURLSearchParameter(parameters, "token");
  if (id_token !== void 0 || token !== void 0) {
    throw new UnsupportedOperationError("implicit and hybrid flows are not supported");
  }
  return brand(new URLSearchParams(parameters));
}
function algToSubtle(alg) {
  switch (alg) {
    case "PS256":
    case "PS384":
    case "PS512":
      return { name: "RSA-PSS", hash: `SHA-${alg.slice(-3)}` };
    case "RS256":
    case "RS384":
    case "RS512":
      return { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${alg.slice(-3)}` };
    case "ES256":
    case "ES384":
      return { name: "ECDSA", namedCurve: `P-${alg.slice(-3)}` };
    case "ES512":
      return { name: "ECDSA", namedCurve: "P-521" };
    case "Ed25519":
    case "EdDSA":
      return "Ed25519";
    default:
      throw new UnsupportedOperationError("unsupported JWS algorithm", { cause: { alg } });
  }
}
async function importJwk(alg, jwk) {
  const { ext, key_ops, use, ...key } = jwk;
  return crypto.subtle.importKey("jwk", key, algToSubtle(alg), true, ["verify"]);
}
async function deviceAuthorizationRequest(as, client, clientAuthentication, parameters, options) {
  assertAs(as);
  assertClient(client);
  const url = resolveEndpoint(as, "device_authorization_endpoint", client.use_mtls_endpoint_aliases, options?.[allowInsecureRequests] !== true);
  const body = new URLSearchParams(parameters);
  body.set("client_id", client.client_id);
  const headers2 = prepareHeaders(options?.headers);
  headers2.set("accept", "application/json");
  return authenticatedRequest(as, client, clientAuthentication, url, body, headers2, options);
}
async function processDeviceAuthorizationResponse(as, client, response) {
  assertAs(as);
  assertClient(client);
  if (!looseInstanceOf(response, Response)) {
    throw CodedTypeError('"response" must be an instance of Response', ERR_INVALID_ARG_TYPE);
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(response)) {
    throw new WWWAuthenticateChallengeError("server responded with a challenge in the WWW-Authenticate HTTP Header", { cause: challenges, response });
  }
  if (response.status !== 200) {
    let err;
    if (err = await handleOAuthBodyError(response)) {
      await response.body?.cancel();
      throw new ResponseBodyError("server responded with an error in the response body", {
        cause: err,
        response
      });
    }
    throw OPE('"response" is not a conform Device Authorization Endpoint response (unexpected HTTP status code)', RESPONSE_IS_NOT_CONFORM, response);
  }
  assertReadableResponse(response);
  assertApplicationJson(response);
  let json;
  try {
    json = await response.json();
  } catch (cause) {
    throw OPE('failed to parse "response" body as JSON', PARSE_ERROR, cause);
  }
  if (!isJsonObject(json)) {
    throw OPE('"response" body must be a top level object', INVALID_RESPONSE, { body: json });
  }
  assertString(json.device_code, '"response" body "device_code" property', INVALID_RESPONSE, {
    body: json
  });
  assertString(json.user_code, '"response" body "user_code" property', INVALID_RESPONSE, {
    body: json
  });
  assertString(json.verification_uri, '"response" body "verification_uri" property', INVALID_RESPONSE, { body: json });
  let expiresIn = typeof json.expires_in !== "number" ? parseFloat(json.expires_in) : json.expires_in;
  assertNumber(expiresIn, false, '"response" body "expires_in" property', INVALID_RESPONSE, {
    body: json
  });
  json.expires_in = expiresIn;
  if (json.verification_uri_complete !== void 0) {
    assertString(json.verification_uri_complete, '"response" body "verification_uri_complete" property', INVALID_RESPONSE, { body: json });
  }
  if (json.interval !== void 0) {
    assertNumber(json.interval, false, '"response" body "interval" property', INVALID_RESPONSE, {
      body: json
    });
  }
  return json;
}
async function deviceCodeGrantRequest(as, client, clientAuthentication, deviceCode, options) {
  assertAs(as);
  assertClient(client);
  assertString(deviceCode, '"deviceCode"');
  const parameters = new URLSearchParams(options?.additionalParameters);
  parameters.set("device_code", deviceCode);
  return tokenEndpointRequest(as, client, clientAuthentication, "urn:ietf:params:oauth:grant-type:device_code", parameters, options);
}
async function processDeviceCodeResponse(as, client, response, options) {
  return processGenericAccessTokenResponse(as, client, response, void 0, options);
}
async function generateKeyPair(alg, options) {
  assertString(alg, '"alg"');
  const algorithm = algToSubtle(alg);
  if (alg.startsWith("PS") || alg.startsWith("RS")) {
    Object.assign(algorithm, {
      modulusLength: options?.modulusLength ?? 2048,
      publicExponent: new Uint8Array([1, 0, 1])
    });
  }
  return crypto.subtle.generateKey(algorithm, options?.extractable ?? false, [
    "sign",
    "verify"
  ]);
}
var _nopkce = Symbol();
var _nodiscoverycheck = Symbol();
var _expectedIssuer = Symbol();

// node_modules/jose/dist/browser/runtime/webcrypto.js
var webcrypto_default = crypto;
var isCryptoKey = (key) => key instanceof CryptoKey;

// node_modules/jose/dist/browser/runtime/digest.js
var digest = async (algorithm, data) => {
  const subtleDigest = `SHA-${algorithm.slice(-3)}`;
  return new Uint8Array(await webcrypto_default.subtle.digest(subtleDigest, data));
};
var digest_default = digest;

// node_modules/jose/dist/browser/lib/buffer_utils.js
var encoder2 = new TextEncoder();
var decoder2 = new TextDecoder();
var MAX_INT32 = 2 ** 32;
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf2 = new Uint8Array(size);
  let i = 0;
  for (const buffer of buffers) {
    buf2.set(buffer, i);
    i += buffer.length;
  }
  return buf2;
}
function p2s(alg, p2sInput) {
  return concat(encoder2.encode(alg), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf2, value, offset) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  }
  buf2.set([value >>> 24, value >>> 16, value >>> 8, value & 255], offset);
}
function uint64be(value) {
  const high = Math.floor(value / MAX_INT32);
  const low = value % MAX_INT32;
  const buf2 = new Uint8Array(8);
  writeUInt32BE(buf2, high, 0);
  writeUInt32BE(buf2, low, 4);
  return buf2;
}
function uint32be(value) {
  const buf2 = new Uint8Array(4);
  writeUInt32BE(buf2, value);
  return buf2;
}
function lengthAndInput(input) {
  return concat(uint32be(input.length), input);
}
async function concatKdf(secret, bits, value) {
  const iterations = Math.ceil((bits >> 3) / 32);
  const res = new Uint8Array(iterations * 32);
  for (let iter = 0; iter < iterations; iter++) {
    const buf2 = new Uint8Array(4 + secret.length + value.length);
    buf2.set(uint32be(iter + 1));
    buf2.set(secret, 4);
    buf2.set(value, 4 + secret.length);
    res.set(await digest_default("sha256", buf2), iter * 32);
  }
  return res.slice(0, bits >> 3);
}

// node_modules/jose/dist/browser/runtime/base64url.js
var decodeBase64 = (encoded) => {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};
var decode = (input) => {
  let encoded = input;
  if (encoded instanceof Uint8Array) {
    encoded = decoder2.decode(encoded);
  }
  encoded = encoded.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  try {
    return decodeBase64(encoded);
  } catch {
    throw new TypeError("The input to be decoded is not correctly encoded.");
  }
};

// node_modules/jose/dist/browser/util/errors.js
var JOSEError = class extends Error {
  constructor(message2, options) {
    super(message2, options);
    this.code = "ERR_JOSE_GENERIC";
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
};
JOSEError.code = "ERR_JOSE_GENERIC";
var JWTClaimValidationFailed = class extends JOSEError {
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2, { cause: { claim, reason, payload } });
    this.code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
    this.claim = claim;
    this.reason = reason;
    this.payload = payload;
  }
};
JWTClaimValidationFailed.code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
var JWTExpired = class extends JOSEError {
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2, { cause: { claim, reason, payload } });
    this.code = "ERR_JWT_EXPIRED";
    this.claim = claim;
    this.reason = reason;
    this.payload = payload;
  }
};
JWTExpired.code = "ERR_JWT_EXPIRED";
var JOSEAlgNotAllowed = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JOSE_ALG_NOT_ALLOWED";
  }
};
JOSEAlgNotAllowed.code = "ERR_JOSE_ALG_NOT_ALLOWED";
var JOSENotSupported = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JOSE_NOT_SUPPORTED";
  }
};
JOSENotSupported.code = "ERR_JOSE_NOT_SUPPORTED";
var JWEDecryptionFailed = class extends JOSEError {
  constructor(message2 = "decryption operation failed", options) {
    super(message2, options);
    this.code = "ERR_JWE_DECRYPTION_FAILED";
  }
};
JWEDecryptionFailed.code = "ERR_JWE_DECRYPTION_FAILED";
var JWEInvalid = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JWE_INVALID";
  }
};
JWEInvalid.code = "ERR_JWE_INVALID";
var JWSInvalid = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JWS_INVALID";
  }
};
JWSInvalid.code = "ERR_JWS_INVALID";
var JWTInvalid = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JWT_INVALID";
  }
};
JWTInvalid.code = "ERR_JWT_INVALID";
var JWKInvalid = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JWK_INVALID";
  }
};
JWKInvalid.code = "ERR_JWK_INVALID";
var JWKSInvalid = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JWKS_INVALID";
  }
};
JWKSInvalid.code = "ERR_JWKS_INVALID";
var JWKSNoMatchingKey = class extends JOSEError {
  constructor(message2 = "no applicable key found in the JSON Web Key Set", options) {
    super(message2, options);
    this.code = "ERR_JWKS_NO_MATCHING_KEY";
  }
};
JWKSNoMatchingKey.code = "ERR_JWKS_NO_MATCHING_KEY";
var JWKSMultipleMatchingKeys = class extends JOSEError {
  constructor(message2 = "multiple matching keys found in the JSON Web Key Set", options) {
    super(message2, options);
    this.code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
  }
};
JWKSMultipleMatchingKeys.code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
var JWKSTimeout = class extends JOSEError {
  constructor(message2 = "request timed out", options) {
    super(message2, options);
    this.code = "ERR_JWKS_TIMEOUT";
  }
};
JWKSTimeout.code = "ERR_JWKS_TIMEOUT";
var JWSSignatureVerificationFailed = class extends JOSEError {
  constructor(message2 = "signature verification failed", options) {
    super(message2, options);
    this.code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  }
};
JWSSignatureVerificationFailed.code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";

// node_modules/jose/dist/browser/runtime/random.js
var random_default = webcrypto_default.getRandomValues.bind(webcrypto_default);

// node_modules/jose/dist/browser/lib/iv.js
function bitLength(alg) {
  switch (alg) {
    case "A128GCM":
    case "A128GCMKW":
    case "A192GCM":
    case "A192GCMKW":
    case "A256GCM":
    case "A256GCMKW":
      return 96;
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return 128;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}

// node_modules/jose/dist/browser/lib/check_iv_length.js
var checkIvLength = (enc, iv) => {
  if (iv.length << 3 !== bitLength(enc)) {
    throw new JWEInvalid("Invalid Initialization Vector length");
  }
};
var check_iv_length_default = checkIvLength;

// node_modules/jose/dist/browser/runtime/check_cek_length.js
var checkCekLength = (cek, expected) => {
  const actual = cek.byteLength << 3;
  if (actual !== expected) {
    throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
  }
};
var check_cek_length_default = checkCekLength;

// node_modules/jose/dist/browser/runtime/timing_safe_equal.js
var timingSafeEqual = (a, b) => {
  if (!(a instanceof Uint8Array)) {
    throw new TypeError("First argument must be a buffer");
  }
  if (!(b instanceof Uint8Array)) {
    throw new TypeError("Second argument must be a buffer");
  }
  if (a.length !== b.length) {
    throw new TypeError("Input buffers must have the same length");
  }
  const len = a.length;
  let out = 0;
  let i = -1;
  while (++i < len) {
    out |= a[i] ^ b[i];
  }
  return out === 0;
};
var timing_safe_equal_default = timingSafeEqual;

// node_modules/jose/dist/browser/lib/crypto_key.js
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
function checkUsage(key, usages) {
  if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
    let msg = "CryptoKey does not support this operation, its usages must include ";
    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(", ")}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }
    throw new TypeError(msg);
  }
}
function checkEncCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (!isAlgorithm(key.algorithm, "AES-GCM"))
        throw unusable("AES-GCM");
      const expected = parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (!isAlgorithm(key.algorithm, "AES-KW"))
        throw unusable("AES-KW");
      const expected = parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "ECDH": {
      switch (key.algorithm.name) {
        case "ECDH":
        case "X25519":
        case "X448":
          break;
        default:
          throw unusable("ECDH, X25519, or X448");
      }
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW":
      if (!isAlgorithm(key.algorithm, "PBKDF2"))
        throw unusable("PBKDF2");
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (!isAlgorithm(key.algorithm, "RSA-OAEP"))
        throw unusable("RSA-OAEP");
      const expected = parseInt(alg.slice(9), 10) || 1;
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}

// node_modules/jose/dist/browser/lib/invalid_key_input.js
function message(msg, actual, ...types2) {
  types2 = types2.filter(Boolean);
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `one of type ${types2.join(", ")}, or ${last}.`;
  } else if (types2.length === 2) {
    msg += `one of type ${types2[0]} or ${types2[1]}.`;
  } else {
    msg += `of type ${types2[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor?.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
var invalid_key_input_default = (actual, ...types2) => {
  return message("Key must be ", actual, ...types2);
};
function withAlg(alg, actual, ...types2) {
  return message(`Key for the ${alg} algorithm must be `, actual, ...types2);
}

// node_modules/jose/dist/browser/runtime/is_key_like.js
var is_key_like_default = (key) => {
  if (isCryptoKey(key)) {
    return true;
  }
  return key?.[Symbol.toStringTag] === "KeyObject";
};
var types = ["CryptoKey"];

// node_modules/jose/dist/browser/runtime/decrypt.js
async function cbcDecrypt(enc, cek, ciphertext, iv, tag2, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(invalid_key_input_default(cek, "Uint8Array"));
  }
  const keySize = parseInt(enc.slice(1, 4), 10);
  const encKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, ["decrypt"]);
  const macKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const expectedTag = new Uint8Array((await webcrypto_default.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
  let macCheckPassed;
  try {
    macCheckPassed = timing_safe_equal_default(tag2, expectedTag);
  } catch {
  }
  if (!macCheckPassed) {
    throw new JWEDecryptionFailed();
  }
  let plaintext;
  try {
    plaintext = new Uint8Array(await webcrypto_default.subtle.decrypt({ iv, name: "AES-CBC" }, encKey, ciphertext));
  } catch {
  }
  if (!plaintext) {
    throw new JWEDecryptionFailed();
  }
  return plaintext;
}
async function gcmDecrypt(enc, cek, ciphertext, iv, tag2, aad) {
  let encKey;
  if (cek instanceof Uint8Array) {
    encKey = await webcrypto_default.subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  } else {
    checkEncCryptoKey(cek, enc, "decrypt");
    encKey = cek;
  }
  try {
    return new Uint8Array(await webcrypto_default.subtle.decrypt({
      additionalData: aad,
      iv,
      name: "AES-GCM",
      tagLength: 128
    }, encKey, concat(ciphertext, tag2)));
  } catch {
    throw new JWEDecryptionFailed();
  }
}
var decrypt = async (enc, cek, ciphertext, iv, tag2, aad) => {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
    throw new TypeError(invalid_key_input_default(cek, ...types, "Uint8Array"));
  }
  if (!iv) {
    throw new JWEInvalid("JWE Initialization Vector missing");
  }
  if (!tag2) {
    throw new JWEInvalid("JWE Authentication Tag missing");
  }
  check_iv_length_default(enc, iv);
  switch (enc) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      if (cek instanceof Uint8Array)
        check_cek_length_default(cek, parseInt(enc.slice(-3), 10));
      return cbcDecrypt(enc, cek, ciphertext, iv, tag2, aad);
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
      if (cek instanceof Uint8Array)
        check_cek_length_default(cek, parseInt(enc.slice(1, 4), 10));
      return gcmDecrypt(enc, cek, ciphertext, iv, tag2, aad);
    default:
      throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
  }
};
var decrypt_default = decrypt;

// node_modules/jose/dist/browser/lib/is_disjoint.js
var isDisjoint = (...headers2) => {
  const sources = headers2.filter(Boolean);
  if (sources.length === 0 || sources.length === 1) {
    return true;
  }
  let acc;
  for (const header of sources) {
    const parameters = Object.keys(header);
    if (!acc || acc.size === 0) {
      acc = new Set(parameters);
      continue;
    }
    for (const parameter of parameters) {
      if (acc.has(parameter)) {
        return false;
      }
      acc.add(parameter);
    }
  }
  return true;
};
var is_disjoint_default = isDisjoint;

// node_modules/jose/dist/browser/lib/is_object.js
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isObject(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}

// node_modules/jose/dist/browser/runtime/bogus.js
var bogusWebCrypto = [
  { hash: "SHA-256", name: "HMAC" },
  true,
  ["sign"]
];
var bogus_default = bogusWebCrypto;

// node_modules/jose/dist/browser/runtime/aeskw.js
function checkKeySize(key, alg) {
  if (key.algorithm.length !== parseInt(alg.slice(1, 4), 10)) {
    throw new TypeError(`Invalid key size for alg: ${alg}`);
  }
}
function getCryptoKey(key, alg, usage) {
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, usage);
    return key;
  }
  if (key instanceof Uint8Array) {
    return webcrypto_default.subtle.importKey("raw", key, "AES-KW", true, [usage]);
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
}
var unwrap = async (alg, key, encryptedKey) => {
  const cryptoKey = await getCryptoKey(key, alg, "unwrapKey");
  checkKeySize(cryptoKey, alg);
  const cryptoKeyCek = await webcrypto_default.subtle.unwrapKey("raw", encryptedKey, cryptoKey, "AES-KW", ...bogus_default);
  return new Uint8Array(await webcrypto_default.subtle.exportKey("raw", cryptoKeyCek));
};

// node_modules/jose/dist/browser/runtime/ecdhes.js
async function deriveKey(publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) {
  if (!isCryptoKey(publicKey)) {
    throw new TypeError(invalid_key_input_default(publicKey, ...types));
  }
  checkEncCryptoKey(publicKey, "ECDH");
  if (!isCryptoKey(privateKey)) {
    throw new TypeError(invalid_key_input_default(privateKey, ...types));
  }
  checkEncCryptoKey(privateKey, "ECDH", "deriveBits");
  const value = concat(lengthAndInput(encoder2.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
  let length;
  if (publicKey.algorithm.name === "X25519") {
    length = 256;
  } else if (publicKey.algorithm.name === "X448") {
    length = 448;
  } else {
    length = Math.ceil(parseInt(publicKey.algorithm.namedCurve.substr(-3), 10) / 8) << 3;
  }
  const sharedSecret = new Uint8Array(await webcrypto_default.subtle.deriveBits({
    name: publicKey.algorithm.name,
    public: publicKey
  }, privateKey, length));
  return concatKdf(sharedSecret, keyLength, value);
}
function ecdhAllowed(key) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalid_key_input_default(key, ...types));
  }
  return ["P-256", "P-384", "P-521"].includes(key.algorithm.namedCurve) || key.algorithm.name === "X25519" || key.algorithm.name === "X448";
}

// node_modules/jose/dist/browser/lib/check_p2s.js
function checkP2s(p2s2) {
  if (!(p2s2 instanceof Uint8Array) || p2s2.length < 8) {
    throw new JWEInvalid("PBES2 Salt Input must be 8 or more octets");
  }
}

// node_modules/jose/dist/browser/runtime/pbes2kw.js
function getCryptoKey2(key, alg) {
  if (key instanceof Uint8Array) {
    return webcrypto_default.subtle.importKey("raw", key, "PBKDF2", false, ["deriveBits"]);
  }
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, "deriveBits", "deriveKey");
    return key;
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
}
async function deriveKey2(p2s2, alg, p2c, key) {
  checkP2s(p2s2);
  const salt = p2s(alg, p2s2);
  const keylen = parseInt(alg.slice(13, 16), 10);
  const subtleAlg = {
    hash: `SHA-${alg.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt
  };
  const wrapAlg = {
    length: keylen,
    name: "AES-KW"
  };
  const cryptoKey = await getCryptoKey2(key, alg);
  if (cryptoKey.usages.includes("deriveBits")) {
    return new Uint8Array(await webcrypto_default.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
  }
  if (cryptoKey.usages.includes("deriveKey")) {
    return webcrypto_default.subtle.deriveKey(subtleAlg, cryptoKey, wrapAlg, false, ["wrapKey", "unwrapKey"]);
  }
  throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');
}
var decrypt2 = async (alg, key, encryptedKey, p2c, p2s2) => {
  const derived = await deriveKey2(p2s2, alg, p2c, key);
  return unwrap(alg.slice(-6), derived, encryptedKey);
};

// node_modules/jose/dist/browser/runtime/subtle_rsaes.js
function subtleRsaEs(alg) {
  switch (alg) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      return "RSA-OAEP";
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}

// node_modules/jose/dist/browser/runtime/check_key_length.js
var check_key_length_default = (alg, key) => {
  if (alg.startsWith("RS") || alg.startsWith("PS")) {
    const { modulusLength } = key.algorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
    }
  }
};

// node_modules/jose/dist/browser/runtime/rsaes.js
var decrypt3 = async (alg, key, encryptedKey) => {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalid_key_input_default(key, ...types));
  }
  checkEncCryptoKey(key, alg, "decrypt", "unwrapKey");
  check_key_length_default(alg, key);
  if (key.usages.includes("decrypt")) {
    return new Uint8Array(await webcrypto_default.subtle.decrypt(subtleRsaEs(alg), key, encryptedKey));
  }
  if (key.usages.includes("unwrapKey")) {
    const cryptoKeyCek = await webcrypto_default.subtle.unwrapKey("raw", encryptedKey, key, subtleRsaEs(alg), ...bogus_default);
    return new Uint8Array(await webcrypto_default.subtle.exportKey("raw", cryptoKeyCek));
  }
  throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation');
};

// node_modules/jose/dist/browser/lib/is_jwk.js
function isJWK(key) {
  return isObject(key) && typeof key.kty === "string";
}
function isPrivateJWK(key) {
  return key.kty !== "oct" && typeof key.d === "string";
}
function isPublicJWK(key) {
  return key.kty !== "oct" && typeof key.d === "undefined";
}
function isSecretJWK(key) {
  return isJWK(key) && key.kty === "oct" && typeof key.k === "string";
}

// node_modules/jose/dist/browser/runtime/jwk_to_key.js
function subtleMapping(jwk) {
  let algorithm;
  let keyUsages;
  switch (jwk.kty) {
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512":
          algorithm = { name: "RSA-PSS", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RS256":
        case "RS384":
        case "RS512":
          algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`
          };
          keyUsages = jwk.d ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256":
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES384":
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES512":
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: "ECDH", namedCurve: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "EdDSA":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
  }
  return { algorithm, keyUsages };
}
var parse = async (jwk) => {
  if (!jwk.alg) {
    throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
  }
  const { algorithm, keyUsages } = subtleMapping(jwk);
  const rest = [
    algorithm,
    jwk.ext ?? false,
    jwk.key_ops ?? keyUsages
  ];
  const keyData = { ...jwk };
  delete keyData.alg;
  delete keyData.use;
  return webcrypto_default.subtle.importKey("jwk", keyData, ...rest);
};
var jwk_to_key_default = parse;

// node_modules/jose/dist/browser/runtime/normalize_key.js
var exportKeyValue = (k) => decode(k);
var privCache;
var pubCache;
var isKeyObject = (key) => {
  return key?.[Symbol.toStringTag] === "KeyObject";
};
var importAndCache = async (cache, key, jwk, alg, freeze = false) => {
  let cached = cache.get(key);
  if (cached?.[alg]) {
    return cached[alg];
  }
  const cryptoKey = await jwk_to_key_default({ ...jwk, alg });
  if (freeze)
    Object.freeze(key);
  if (!cached) {
    cache.set(key, { [alg]: cryptoKey });
  } else {
    cached[alg] = cryptoKey;
  }
  return cryptoKey;
};
var normalizePublicKey = (key, alg) => {
  if (isKeyObject(key)) {
    let jwk = key.export({ format: "jwk" });
    delete jwk.d;
    delete jwk.dp;
    delete jwk.dq;
    delete jwk.p;
    delete jwk.q;
    delete jwk.qi;
    if (jwk.k) {
      return exportKeyValue(jwk.k);
    }
    pubCache || (pubCache = /* @__PURE__ */ new WeakMap());
    return importAndCache(pubCache, key, jwk, alg);
  }
  if (isJWK(key)) {
    if (key.k)
      return decode(key.k);
    pubCache || (pubCache = /* @__PURE__ */ new WeakMap());
    const cryptoKey = importAndCache(pubCache, key, key, alg, true);
    return cryptoKey;
  }
  return key;
};
var normalizePrivateKey = (key, alg) => {
  if (isKeyObject(key)) {
    let jwk = key.export({ format: "jwk" });
    if (jwk.k) {
      return exportKeyValue(jwk.k);
    }
    privCache || (privCache = /* @__PURE__ */ new WeakMap());
    return importAndCache(privCache, key, jwk, alg);
  }
  if (isJWK(key)) {
    if (key.k)
      return decode(key.k);
    privCache || (privCache = /* @__PURE__ */ new WeakMap());
    const cryptoKey = importAndCache(privCache, key, key, alg, true);
    return cryptoKey;
  }
  return key;
};
var normalize_key_default = { normalizePublicKey, normalizePrivateKey };

// node_modules/jose/dist/browser/lib/cek.js
function bitLength2(alg) {
  switch (alg) {
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
    case "A128CBC-HS256":
      return 256;
    case "A192CBC-HS384":
      return 384;
    case "A256CBC-HS512":
      return 512;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}
var cek_default = (alg) => random_default(new Uint8Array(bitLength2(alg) >> 3));

// node_modules/jose/dist/browser/key/import.js
async function importJWK(jwk, alg) {
  if (!isObject(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  alg || (alg = jwk.alg);
  switch (jwk.kty) {
    case "oct":
      if (typeof jwk.k !== "string" || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }
      return decode(jwk.k);
    case "RSA":
      if (jwk.oth !== void 0) {
        throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
      }
    case "EC":
    case "OKP":
      return jwk_to_key_default({ ...jwk, alg });
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}

// node_modules/jose/dist/browser/lib/check_key_type.js
var tag = (key) => key?.[Symbol.toStringTag];
var jwkMatchesOp = (alg, key, usage) => {
  if (key.use !== void 0 && key.use !== "sig") {
    throw new TypeError("Invalid key for this operation, when present its use must be sig");
  }
  if (key.key_ops !== void 0 && key.key_ops.includes?.(usage) !== true) {
    throw new TypeError(`Invalid key for this operation, when present its key_ops must include ${usage}`);
  }
  if (key.alg !== void 0 && key.alg !== alg) {
    throw new TypeError(`Invalid key for this operation, when present its alg must be ${alg}`);
  }
  return true;
};
var symmetricTypeCheck = (alg, key, usage, allowJwk) => {
  if (key instanceof Uint8Array)
    return;
  if (allowJwk && isJWK(key)) {
    if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage))
      return;
    throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
  }
  if (!is_key_like_default(key)) {
    throw new TypeError(withAlg(alg, key, ...types, "Uint8Array", allowJwk ? "JSON Web Key" : null));
  }
  if (key.type !== "secret") {
    throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
  }
};
var asymmetricTypeCheck = (alg, key, usage, allowJwk) => {
  if (allowJwk && isJWK(key)) {
    switch (usage) {
      case "sign":
        if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage))
          return;
        throw new TypeError(`JSON Web Key for this operation be a private JWK`);
      case "verify":
        if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage))
          return;
        throw new TypeError(`JSON Web Key for this operation be a public JWK`);
    }
  }
  if (!is_key_like_default(key)) {
    throw new TypeError(withAlg(alg, key, ...types, allowJwk ? "JSON Web Key" : null));
  }
  if (key.type === "secret") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
  }
  if (usage === "sign" && key.type === "public") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
  }
  if (usage === "decrypt" && key.type === "public") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
  }
  if (key.algorithm && usage === "verify" && key.type === "private") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
  }
  if (key.algorithm && usage === "encrypt" && key.type === "private") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
  }
};
function checkKeyType(allowJwk, alg, key, usage) {
  const symmetric = alg.startsWith("HS") || alg === "dir" || alg.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(alg);
  if (symmetric) {
    symmetricTypeCheck(alg, key, usage, allowJwk);
  } else {
    asymmetricTypeCheck(alg, key, usage, allowJwk);
  }
}
var check_key_type_default = checkKeyType.bind(void 0, false);
var checkKeyTypeWithJwk = checkKeyType.bind(void 0, true);

// node_modules/jose/dist/browser/lib/aesgcmkw.js
async function unwrap2(alg, key, encryptedKey, iv, tag2) {
  const jweAlgorithm = alg.slice(0, 7);
  return decrypt_default(jweAlgorithm, key, encryptedKey, iv, tag2, new Uint8Array(0));
}

// node_modules/jose/dist/browser/lib/decrypt_key_management.js
async function decryptKeyManagement(alg, key, encryptedKey, joseHeader, options) {
  check_key_type_default(alg, key, "decrypt");
  key = await normalize_key_default.normalizePrivateKey?.(key, alg) || key;
  switch (alg) {
    case "dir": {
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
      return key;
    }
    case "ECDH-ES":
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!isObject(joseHeader.epk))
        throw new JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
      if (!ecdhAllowed(key))
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      const epk = await importJWK(joseHeader.epk, alg);
      let partyUInfo;
      let partyVInfo;
      if (joseHeader.apu !== void 0) {
        if (typeof joseHeader.apu !== "string")
          throw new JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
        try {
          partyUInfo = decode(joseHeader.apu);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the apu");
        }
      }
      if (joseHeader.apv !== void 0) {
        if (typeof joseHeader.apv !== "string")
          throw new JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
        try {
          partyVInfo = decode(joseHeader.apv);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the apv");
        }
      }
      const sharedSecret = await deriveKey(epk, key, alg === "ECDH-ES" ? joseHeader.enc : alg, alg === "ECDH-ES" ? bitLength2(joseHeader.enc) : parseInt(alg.slice(-5, -2), 10), partyUInfo, partyVInfo);
      if (alg === "ECDH-ES")
        return sharedSecret;
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap(alg.slice(-6), sharedSecret, encryptedKey);
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return decrypt3(alg, key, encryptedKey);
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.p2c !== "number")
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
      const p2cLimit = options?.maxPBES2Count || 1e4;
      if (joseHeader.p2c > p2cLimit)
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds`);
      if (typeof joseHeader.p2s !== "string")
        throw new JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
      let p2s2;
      try {
        p2s2 = decode(joseHeader.p2s);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the p2s");
      }
      return decrypt2(alg, key, encryptedKey, joseHeader.p2c, p2s2);
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap(alg, key, encryptedKey);
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.iv !== "string")
        throw new JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
      if (typeof joseHeader.tag !== "string")
        throw new JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
      let iv;
      try {
        iv = decode(joseHeader.iv);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the iv");
      }
      let tag2;
      try {
        tag2 = decode(joseHeader.tag);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the tag");
      }
      return unwrap2(alg, key, encryptedKey, iv, tag2);
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
}
var decrypt_key_management_default = decryptKeyManagement;

// node_modules/jose/dist/browser/lib/validate_crit.js
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }
    if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}
var validate_crit_default = validateCrit;

// node_modules/jose/dist/browser/lib/validate_algorithms.js
var validateAlgorithms = (option, algorithms) => {
  if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== "string"))) {
    throw new TypeError(`"${option}" option must be an array of strings`);
  }
  if (!algorithms) {
    return void 0;
  }
  return new Set(algorithms);
};
var validate_algorithms_default = validateAlgorithms;

// node_modules/jose/dist/browser/jwe/flattened/decrypt.js
async function flattenedDecrypt(jwe, key, options) {
  if (!isObject(jwe)) {
    throw new JWEInvalid("Flattened JWE must be an object");
  }
  if (jwe.protected === void 0 && jwe.header === void 0 && jwe.unprotected === void 0) {
    throw new JWEInvalid("JOSE Header missing");
  }
  if (jwe.iv !== void 0 && typeof jwe.iv !== "string") {
    throw new JWEInvalid("JWE Initialization Vector incorrect type");
  }
  if (typeof jwe.ciphertext !== "string") {
    throw new JWEInvalid("JWE Ciphertext missing or incorrect type");
  }
  if (jwe.tag !== void 0 && typeof jwe.tag !== "string") {
    throw new JWEInvalid("JWE Authentication Tag incorrect type");
  }
  if (jwe.protected !== void 0 && typeof jwe.protected !== "string") {
    throw new JWEInvalid("JWE Protected Header incorrect type");
  }
  if (jwe.encrypted_key !== void 0 && typeof jwe.encrypted_key !== "string") {
    throw new JWEInvalid("JWE Encrypted Key incorrect type");
  }
  if (jwe.aad !== void 0 && typeof jwe.aad !== "string") {
    throw new JWEInvalid("JWE AAD incorrect type");
  }
  if (jwe.header !== void 0 && !isObject(jwe.header)) {
    throw new JWEInvalid("JWE Shared Unprotected Header incorrect type");
  }
  if (jwe.unprotected !== void 0 && !isObject(jwe.unprotected)) {
    throw new JWEInvalid("JWE Per-Recipient Unprotected Header incorrect type");
  }
  let parsedProt;
  if (jwe.protected) {
    try {
      const protectedHeader2 = decode(jwe.protected);
      parsedProt = JSON.parse(decoder2.decode(protectedHeader2));
    } catch {
      throw new JWEInvalid("JWE Protected Header is invalid");
    }
  }
  if (!is_disjoint_default(parsedProt, jwe.header, jwe.unprotected)) {
    throw new JWEInvalid("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jwe.header,
    ...jwe.unprotected
  };
  validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options?.crit, parsedProt, joseHeader);
  if (joseHeader.zip !== void 0) {
    throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
  }
  const { alg, enc } = joseHeader;
  if (typeof alg !== "string" || !alg) {
    throw new JWEInvalid("missing JWE Algorithm (alg) in JWE Header");
  }
  if (typeof enc !== "string" || !enc) {
    throw new JWEInvalid("missing JWE Encryption Algorithm (enc) in JWE Header");
  }
  const keyManagementAlgorithms = options && validate_algorithms_default("keyManagementAlgorithms", options.keyManagementAlgorithms);
  const contentEncryptionAlgorithms = options && validate_algorithms_default("contentEncryptionAlgorithms", options.contentEncryptionAlgorithms);
  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg) || !keyManagementAlgorithms && alg.startsWith("PBES2")) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  }
  if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc)) {
    throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter value not allowed');
  }
  let encryptedKey;
  if (jwe.encrypted_key !== void 0) {
    try {
      encryptedKey = decode(jwe.encrypted_key);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the encrypted_key");
    }
  }
  let resolvedKey = false;
  if (typeof key === "function") {
    key = await key(parsedProt, jwe);
    resolvedKey = true;
  }
  let cek;
  try {
    cek = await decrypt_key_management_default(alg, key, encryptedKey, joseHeader, options);
  } catch (err) {
    if (err instanceof TypeError || err instanceof JWEInvalid || err instanceof JOSENotSupported) {
      throw err;
    }
    cek = cek_default(enc);
  }
  let iv;
  let tag2;
  if (jwe.iv !== void 0) {
    try {
      iv = decode(jwe.iv);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the iv");
    }
  }
  if (jwe.tag !== void 0) {
    try {
      tag2 = decode(jwe.tag);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the tag");
    }
  }
  const protectedHeader = encoder2.encode(jwe.protected ?? "");
  let additionalData;
  if (jwe.aad !== void 0) {
    additionalData = concat(protectedHeader, encoder2.encode("."), encoder2.encode(jwe.aad));
  } else {
    additionalData = protectedHeader;
  }
  let ciphertext;
  try {
    ciphertext = decode(jwe.ciphertext);
  } catch {
    throw new JWEInvalid("Failed to base64url decode the ciphertext");
  }
  const plaintext = await decrypt_default(enc, cek, ciphertext, iv, tag2, additionalData);
  const result = { plaintext };
  if (jwe.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jwe.aad !== void 0) {
    try {
      result.additionalAuthenticatedData = decode(jwe.aad);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the aad");
    }
  }
  if (jwe.unprotected !== void 0) {
    result.sharedUnprotectedHeader = jwe.unprotected;
  }
  if (jwe.header !== void 0) {
    result.unprotectedHeader = jwe.header;
  }
  if (resolvedKey) {
    return { ...result, key };
  }
  return result;
}

// node_modules/jose/dist/browser/jwe/compact/decrypt.js
async function compactDecrypt(jwe, key, options) {
  if (jwe instanceof Uint8Array) {
    jwe = decoder2.decode(jwe);
  }
  if (typeof jwe !== "string") {
    throw new JWEInvalid("Compact JWE must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag2, length } = jwe.split(".");
  if (length !== 5) {
    throw new JWEInvalid("Invalid Compact JWE");
  }
  const decrypted = await flattenedDecrypt({
    ciphertext,
    iv: iv || void 0,
    protected: protectedHeader,
    tag: tag2 || void 0,
    encrypted_key: encryptedKey || void 0
  }, key, options);
  const result = { plaintext: decrypted.plaintext, protectedHeader: decrypted.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}

// node_modules/openid-client/build/index.js
var headers;
var USER_AGENT2;
if (typeof navigator === "undefined" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) {
  const NAME = "openid-client";
  const VERSION = "v6.1.7";
  USER_AGENT2 = `${NAME}/${VERSION}`;
  headers = { "user-agent": USER_AGENT2 };
}
var int = (config) => {
  return props.get(config);
};
var props;
function ClientSecretPost2(clientSecret) {
  return ClientSecretPost(clientSecret);
}
function ClientSecretBasic2(clientSecret) {
  return ClientSecretBasic(clientSecret);
}
function ClientSecretJwt2(clientSecret, options) {
  return ClientSecretJwt(clientSecret, options);
}
function None2() {
  return None();
}
function PrivateKeyJwt2(clientPrivateKey, options) {
  return PrivateKeyJwt(clientPrivateKey, options);
}
function TlsClientAuth2() {
  return TlsClientAuth();
}
var skipStateCheck2 = skipStateCheck;
var skipSubjectCheck2 = skipSubjectCheck;
var customFetch2 = customFetch;
var modifyAssertion2 = modifyAssertion;
var clockSkew2 = clockSkew;
var clockTolerance2 = clockTolerance;
var ERR_INVALID_ARG_VALUE2 = "ERR_INVALID_ARG_VALUE";
var ERR_INVALID_ARG_TYPE2 = "ERR_INVALID_ARG_TYPE";
function CodedTypeError2(message2, code, cause) {
  const err = new TypeError(message2, { cause });
  Object.assign(err, { code });
  return err;
}
function calculatePKCECodeChallenge2(codeVerifier) {
  return calculatePKCECodeChallenge(codeVerifier);
}
function randomPKCECodeVerifier() {
  return generateRandomCodeVerifier();
}
function randomNonce() {
  return generateRandomNonce();
}
function randomState() {
  return generateRandomState();
}
var ClientError = class extends Error {
  code;
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    this.code = options?.code;
    Error.captureStackTrace?.(this, this.constructor);
  }
};
var decoder3 = new TextDecoder();
function e(msg, cause, code) {
  return new ClientError(msg, { cause, code });
}
function errorHandler(err) {
  if (err instanceof TypeError || err instanceof ClientError || err instanceof ResponseBodyError || err instanceof AuthorizationResponseError || err instanceof WWWAuthenticateChallengeError) {
    throw err;
  }
  if (err instanceof OperationProcessingError) {
    switch (err.code) {
      case HTTP_REQUEST_FORBIDDEN:
        throw e("only requests to HTTPS are allowed", err, err.code);
      case REQUEST_PROTOCOL_FORBIDDEN:
        throw e("only requests to HTTP or HTTPS are allowed", err, err.code);
      case RESPONSE_IS_NOT_CONFORM:
        throw e("unexpected HTTP response status code", err.cause, err.code);
      case RESPONSE_IS_NOT_JSON:
        throw e("unexpected response content-type", err.cause, err.code);
      case PARSE_ERROR:
        throw e("parsing error occured", err, err.code);
      case INVALID_RESPONSE:
        throw e("invalid response encountered", err, err.code);
      case JWT_CLAIM_COMPARISON:
        throw e("unexpected JWT claim value encountered", err, err.code);
      case JSON_ATTRIBUTE_COMPARISON:
        throw e("unexpected JSON attribute value encountered", err, err.code);
      case JWT_TIMESTAMP_CHECK:
        throw e("JWT timestamp claim value failed validation", err, err.code);
      default:
        throw e(err.message, err, err.code);
    }
  }
  if (err instanceof UnsupportedOperationError) {
    throw e("unsupported operation", err, err.code);
  }
  if (err instanceof DOMException) {
    switch (err.name) {
      case "OperationError":
        throw e("runtime operation error", err, UNSUPPORTED_OPERATION);
      case "NotSupportedError":
        throw e("runtime unsupported operation", err, UNSUPPORTED_OPERATION);
      case "TimeoutError":
        throw e("operation timed out", err, "OAUTH_TIMEOUT");
      case "AbortError":
        throw e("operation aborted", err, "OAUTH_ABORT");
    }
  }
  throw new ClientError("something went wrong", { cause: err });
}
function randomDPoPKeyPair(alg, options) {
  return generateKeyPair(alg ?? "ES256", {
    extractable: options?.extractable
  }).catch(errorHandler);
}
function handleEntraId(server, as, options) {
  if (server.origin === "https://login.microsoftonline.com" && (!options?.algorithm || options.algorithm === "oidc")) {
    as[kEntraId] = true;
    return true;
  }
  return false;
}
function handleB2Clogin(server, options) {
  if (server.hostname.endsWith(".b2clogin.com") && (!options?.algorithm || options.algorithm === "oidc")) {
    return true;
  }
  return false;
}
async function discovery(server, clientId, metadata, clientAuthentication, options) {
  if (!(server instanceof URL)) {
    throw CodedTypeError2('"server" must be an instance of URL', ERR_INVALID_ARG_TYPE2);
  }
  const resolve = !server.href.includes("/.well-known/");
  const timeout = options?.timeout ?? 30;
  const signal3 = AbortSignal.timeout(timeout * 1e3);
  const as = await (resolve ? discoveryRequest(server, {
    algorithm: options?.algorithm,
    [customFetch]: options?.[customFetch2],
    [allowInsecureRequests]: options?.execute?.includes(allowInsecureRequests2),
    signal: signal3,
    headers: new Headers(headers)
  }) : (options?.[customFetch2] || fetch)((() => {
    checkProtocol(server, options?.execute?.includes(allowInsecureRequests2) ? false : true);
    return server.href;
  })(), {
    headers: Object.fromEntries(new Headers({ accept: "application/json", ...headers }).entries()),
    body: void 0,
    method: "GET",
    redirect: "manual",
    signal: signal3
  })).then((response) => processDiscoveryResponse(_nodiscoverycheck, response)).catch(errorHandler);
  if (resolve && new URL(as.issuer).href !== server.href) {
    handleEntraId(server, as, options) || handleB2Clogin(server, options) || (() => {
      throw new ClientError("discovered metadata issuer does not match the expected issuer", {
        code: JSON_ATTRIBUTE_COMPARISON,
        cause: {
          expected: server.href,
          body: as,
          attribute: "issuer"
        }
      });
    })();
  }
  const instance = new Configuration(as, clientId, metadata, clientAuthentication);
  let internals = int(instance);
  if (options?.[customFetch2]) {
    internals.fetch = options[customFetch2];
  }
  if (options?.timeout) {
    internals.timeout = options.timeout;
  }
  if (options?.execute) {
    for (const extension of options.execute) {
      extension(instance);
    }
  }
  return instance;
}
function isRsaOaep(input) {
  return input.name === "RSA-OAEP";
}
function isEcdh(input) {
  return input.name === "ECDH";
}
var ecdhEs = "ECDH-ES";
var ecdhEsA128Kw = "ECDH-ES+A128KW";
var ecdhEsA192Kw = "ECDH-ES+A192KW";
var ecdhEsA256Kw = "ECDH-ES+A256KW";
function checkEcdhAlg(algs, alg, pk) {
  switch (alg) {
    case void 0:
      algs.add(ecdhEs);
      algs.add(ecdhEsA128Kw);
      algs.add(ecdhEsA192Kw);
      algs.add(ecdhEsA256Kw);
      break;
    case ecdhEs:
    case ecdhEsA128Kw:
    case ecdhEsA192Kw:
    case ecdhEsA256Kw:
      algs.add(alg);
      break;
    default:
      throw CodedTypeError2("invalid key alg", ERR_INVALID_ARG_VALUE2, { pk });
  }
}
function enableDecryptingResponses(config, contentEncryptionAlgorithms = [
  "A128GCM",
  "A192GCM",
  "A256GCM",
  "A128CBC-HS256",
  "A192CBC-HS384",
  "A256CBC-HS512"
], ...keys) {
  if (int(config).decrypt !== void 0) {
    throw new TypeError("enableDecryptingResponses can only be called on a given Configuration instance once");
  }
  if (keys.length === 0) {
    throw CodedTypeError2("no keys were provided", ERR_INVALID_ARG_VALUE2);
  }
  const algs = /* @__PURE__ */ new Set();
  const normalized = [];
  for (const pk of keys) {
    let key;
    if ("key" in pk) {
      key = { key: pk.key };
      if (typeof pk.alg === "string")
        key.alg = pk.alg;
      if (typeof pk.kid === "string")
        key.kid = pk.kid;
    } else {
      key = { key: pk };
    }
    if (key.key.type !== "private") {
      throw CodedTypeError2("only private keys must be provided", ERR_INVALID_ARG_VALUE2);
    }
    if (isRsaOaep(key.key.algorithm)) {
      switch (key.key.algorithm.hash.name) {
        case "SHA-1":
        case "SHA-256":
        case "SHA-384":
        case "SHA-512": {
          let alg = "RSA-OAEP";
          let sha;
          if (sha = parseInt(key.key.algorithm.hash.name.slice(-3), 10)) {
            alg = `${alg}-${sha}`;
          }
          key.alg ||= alg;
          if (alg !== key.alg)
            throw CodedTypeError2("invalid key alg", ERR_INVALID_ARG_VALUE2, {
              pk
            });
          algs.add(key.alg);
          break;
        }
        default:
          throw CodedTypeError2("only SHA-512, SHA-384, SHA-256, and SHA-1 RSA-OAEP keys are supported", ERR_INVALID_ARG_VALUE2);
      }
    } else if (isEcdh(key.key.algorithm)) {
      if (key.key.algorithm.namedCurve !== "P-256") {
        throw CodedTypeError2("Only P-256 ECDH keys are supported", ERR_INVALID_ARG_VALUE2);
      }
      checkEcdhAlg(algs, key.alg, pk);
    } else if (key.key.algorithm.name === "X25519") {
      checkEcdhAlg(algs, key.alg, pk);
    } else {
      throw CodedTypeError2("only RSA-OAEP, ECDH, or X25519 keys are supported", ERR_INVALID_ARG_VALUE2);
    }
    normalized.push(key);
  }
  int(config).decrypt = async (jwe) => decrypt4(normalized, jwe, contentEncryptionAlgorithms, [...algs]).catch(errorHandler);
}
function checkCryptoKey(key, alg, epk) {
  if (alg.startsWith("RSA-OAEP")) {
    return true;
  }
  if (alg.startsWith("ECDH-ES")) {
    if (key.algorithm.name !== "ECDH" && key.algorithm.name !== "X25519") {
      return false;
    }
    if (key.algorithm.name === "ECDH") {
      return epk?.crv === key.algorithm.namedCurve;
    }
    if (key.algorithm.name === "X25519") {
      return epk?.crv === "X25519";
    }
  }
  return false;
}
function selectCryptoKeyForDecryption(keys, alg, kid, epk) {
  const { 0: key, length } = keys.filter((key2) => {
    if (kid !== key2.kid) {
      return false;
    }
    if (key2.alg && alg !== key2.alg) {
      return false;
    }
    return checkCryptoKey(key2.key, alg, epk);
  });
  if (!key) {
    throw e("no applicable decryption key selected", void 0, "OAUTH_DECRYPTION_FAILED");
  }
  if (length !== 1) {
    throw e("multiple applicable decryption keys selected", void 0, "OAUTH_DECRYPTION_FAILED");
  }
  return key.key;
}
async function decrypt4(keys, jwe, contentEncryptionAlgorithms, keyManagementAlgorithms) {
  return decoder3.decode((await compactDecrypt(jwe, async (header) => {
    const { kid, alg, epk } = header;
    return selectCryptoKeyForDecryption(keys, alg, kid, epk);
  }, { keyManagementAlgorithms, contentEncryptionAlgorithms }).catch((err) => {
    if (err instanceof JOSEError) {
      throw e("decryption failed", err, "OAUTH_DECRYPTION_FAILED");
    }
    errorHandler(err);
  })).plaintext);
}
function getServerHelpers(metadata) {
  return {
    supportsPKCE: {
      __proto__: null,
      value(method = "S256") {
        return metadata.code_challenge_methods_supported?.includes(method) === true;
      }
    }
  };
}
function addServerHelpers(metadata) {
  Object.defineProperties(metadata, getServerHelpers(metadata));
}
var kEntraId = Symbol();
var Configuration = class {
  constructor(server, clientId, metadata, clientAuthentication) {
    if (typeof clientId !== "string" || !clientId.length) {
      throw CodedTypeError2('"clientId" must be a non-empty string', ERR_INVALID_ARG_TYPE2);
    }
    if (typeof metadata === "string") {
      metadata = { client_secret: metadata };
    }
    if (metadata?.client_id !== void 0 && clientId !== metadata.client_id) {
      throw CodedTypeError2('"clientId" and "metadata.client_id" must be the same', ERR_INVALID_ARG_VALUE2);
    }
    const client = {
      ...structuredClone(metadata),
      client_id: clientId
    };
    client[clockSkew] = metadata?.[clockSkew] ?? 0;
    client[clockTolerance] = metadata?.[clockTolerance] ?? 30;
    let auth;
    if (clientAuthentication) {
      auth = clientAuthentication;
    } else {
      if (typeof client.client_secret === "string" && client.client_secret.length) {
        auth = ClientSecretPost2(client.client_secret);
      } else {
        auth = None2();
      }
    }
    let c = Object.freeze(client);
    const clone = structuredClone(server);
    if (kEntraId in server) {
      clone[_expectedIssuer] = ({ claims: { tid } }) => server.issuer.replace("{tenantid}", tid);
    }
    let as = Object.freeze(clone);
    props ||= /* @__PURE__ */ new WeakMap();
    props.set(this, {
      __proto__: null,
      as,
      c,
      auth,
      tlsOnly: true,
      jwksCache: {}
    });
  }
  serverMetadata() {
    const metadata = structuredClone(int(this).as);
    addServerHelpers(metadata);
    return metadata;
  }
  get timeout() {
    return int(this).timeout;
  }
  set timeout(value) {
    int(this).timeout = value;
  }
  get [customFetch2]() {
    return int(this).fetch;
  }
  set [customFetch2](value) {
    int(this).fetch = value;
  }
};
Object.freeze(Configuration.prototype);
function getHelpers(response) {
  let exp = void 0;
  if (response.expires_in !== void 0) {
    const now = /* @__PURE__ */ new Date();
    now.setSeconds(now.getSeconds() + response.expires_in);
    exp = now.getTime();
  }
  return {
    expiresIn: {
      __proto__: null,
      value() {
        if (exp) {
          const now = Date.now();
          if (exp > now) {
            return Math.floor((exp - now) / 1e3);
          }
          return 0;
        }
        return void 0;
      }
    },
    claims: {
      __proto__: null,
      value() {
        try {
          return getValidatedIdTokenClaims(this);
        } catch {
          return void 0;
        }
      }
    }
  };
}
function addHelpers(response) {
  Object.defineProperties(response, getHelpers(response));
}
function getDPoPHandle(config, keyPair, options) {
  checkConfig(config);
  return DPoP(int(config).c, keyPair, options);
}
function wait(interval) {
  return new Promise((resolve) => {
    setTimeout(resolve, interval * 1e3);
  });
}
async function pollDeviceAuthorizationGrant(config, deviceAuthorizationResponse, parameters, options) {
  checkConfig(config);
  parameters = new URLSearchParams(parameters);
  let interval = deviceAuthorizationResponse.interval ?? 5;
  const pollingSignal = options?.signal ?? AbortSignal.timeout(deviceAuthorizationResponse.expires_in * 1e3);
  try {
    pollingSignal.throwIfAborted();
  } catch (err) {
    errorHandler(err);
  }
  await wait(interval);
  const { as, c, auth, fetch: fetch2, tlsOnly, nonRepudiation, timeout, decrypt: decrypt5 } = int(config);
  const response = await deviceCodeGrantRequest(as, c, auth, deviceAuthorizationResponse.device_code, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    additionalParameters: parameters,
    DPoP: options?.DPoP,
    headers: new Headers(headers),
    signal: pollingSignal.aborted ? pollingSignal : signal2(timeout)
  }).catch(errorHandler);
  const p = processDeviceCodeResponse(as, c, response, {
    [jweDecrypt]: decrypt5
  });
  let result;
  try {
    result = await p;
  } catch (err) {
    if (retryable(err, options)) {
      return pollDeviceAuthorizationGrant(config, {
        ...deviceAuthorizationResponse,
        interval
      }, parameters, {
        ...options,
        signal: pollingSignal,
        flag: retry
      });
    }
    if (err instanceof ResponseBodyError) {
      switch (err.error) {
        case "slow_down":
          interval += 5;
        case "authorization_pending":
          return pollDeviceAuthorizationGrant(config, {
            ...deviceAuthorizationResponse,
            interval
          }, parameters, {
            ...options,
            signal: pollingSignal,
            flag: void 0
          });
      }
    }
    errorHandler(err);
  }
  result.id_token && await nonRepudiation?.(response);
  addHelpers(result);
  return result;
}
async function initiateDeviceAuthorization(config, parameters) {
  checkConfig(config);
  const { as, c, auth, fetch: fetch2, tlsOnly, timeout } = int(config);
  return deviceAuthorizationRequest(as, c, auth, parameters, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).then((response) => processDeviceAuthorizationResponse(as, c, response)).catch(errorHandler);
}
function allowInsecureRequests2(config) {
  int(config).tlsOnly = false;
}
function setJwksCache2(config, jwksCache2) {
  int(config).jwksCache = structuredClone(jwksCache2);
}
function getJwksCache(config) {
  const cache = int(config).jwksCache;
  if (cache.uat) {
    return cache;
  }
  return void 0;
}
function enableNonRepudiationChecks(config) {
  checkConfig(config);
  int(config).nonRepudiation = (response) => {
    const { as, fetch: fetch2, tlsOnly, timeout, jwksCache: jwksCache2 } = int(config);
    return validateApplicationLevelSignature(as, response, {
      [customFetch]: fetch2,
      [allowInsecureRequests]: !tlsOnly,
      headers: new Headers(headers),
      signal: signal2(timeout),
      [jwksCache]: jwksCache2
    }).catch(errorHandler);
  };
}
function useJwtResponseMode(config) {
  checkConfig(config);
  if (int(config).hybrid) {
    throw e("JARM cannot be combined with a hybrid response mode", void 0, UNSUPPORTED_OPERATION);
  }
  int(config).jarm = (authorizationResponse, expectedState) => validateJARMResponse(config, authorizationResponse, expectedState);
}
function enableDetachedSignatureResponseChecks(config) {
  if (!int(config).hybrid) {
    throw e('"code id_token" response type must be configured to be used first', void 0, UNSUPPORTED_OPERATION);
  }
  int(config).hybrid = (authorizationResponse, expectedNonce, expectedState, maxAge) => validateCodeIdTokenResponse2(config, authorizationResponse, expectedNonce, expectedState, maxAge, true);
}
function useCodeIdTokenResponseType(config) {
  checkConfig(config);
  if (int(config).jarm) {
    throw e('"code id_token" response type cannot be combined with JARM', void 0, UNSUPPORTED_OPERATION);
  }
  int(config).hybrid = (authorizationResponse, expectedNonce, expectedState, maxAge) => validateCodeIdTokenResponse2(config, authorizationResponse, expectedNonce, expectedState, maxAge, false);
}
function stripParams(url) {
  url = new URL(url);
  url.search = "";
  url.hash = "";
  return url.href;
}
function webInstanceOf(input, toStringTag) {
  try {
    return Object.getPrototypeOf(input)[Symbol.toStringTag] === toStringTag;
  } catch {
    return false;
  }
}
async function authorizationCodeGrant(config, currentUrl, checks, tokenEndpointParameters, options) {
  checkConfig(config);
  if (options?.flag !== retry && !(currentUrl instanceof URL) && !webInstanceOf(currentUrl, "Request")) {
    throw CodedTypeError2('"currentUrl" must be an instance of URL, or Request', ERR_INVALID_ARG_TYPE2);
  }
  let authResponse;
  let redirectUri;
  const { as, c, auth, fetch: fetch2, tlsOnly, jarm, hybrid, nonRepudiation, timeout, decrypt: decrypt5 } = int(config);
  if (options?.flag === retry) {
    authResponse = options.authResponse;
    redirectUri = options.redirectUri;
  } else {
    let request;
    if (!(currentUrl instanceof URL)) {
      if (currentUrl.method === "POST") {
        request = currentUrl;
      }
      currentUrl = new URL(currentUrl.url);
    }
    redirectUri = stripParams(currentUrl);
    switch (true) {
      case !!jarm:
        authResponse = await jarm(currentUrl, checks?.expectedState);
        break;
      case !!hybrid:
        authResponse = await hybrid(request || currentUrl, checks?.expectedNonce, checks?.expectedState, checks?.maxAge);
        break;
      default:
        try {
          authResponse = validateAuthResponse(as, c, currentUrl.searchParams, checks?.expectedState);
        } catch (err) {
          return errorHandler(err);
        }
    }
  }
  const response = await authorizationCodeGrantRequest(as, c, auth, authResponse, redirectUri, checks?.pkceCodeVerifier || _nopkce, {
    additionalParameters: tokenEndpointParameters,
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    DPoP: options?.DPoP,
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).catch(errorHandler);
  if (typeof checks?.expectedNonce === "string" || typeof checks?.maxAge === "number") {
    checks.idTokenExpected = true;
  }
  const p = processAuthorizationCodeResponse(as, c, response, {
    expectedNonce: checks?.expectedNonce,
    maxAge: checks?.maxAge,
    requireIdToken: checks?.idTokenExpected,
    [jweDecrypt]: decrypt5
  });
  let result;
  try {
    result = await p;
  } catch (err) {
    if (retryable(err, options)) {
      return authorizationCodeGrant(config, void 0, checks, tokenEndpointParameters, {
        ...options,
        flag: retry,
        authResponse,
        redirectUri
      });
    }
    errorHandler(err);
  }
  result.id_token && await nonRepudiation?.(response);
  addHelpers(result);
  return result;
}
async function validateJARMResponse(config, authorizationResponse, expectedState) {
  const { as, c, fetch: fetch2, tlsOnly, timeout, decrypt: decrypt5, jwksCache: jwksCache2 } = int(config);
  return validateJwtAuthResponse(as, c, authorizationResponse, expectedState, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    headers: new Headers(headers),
    signal: signal2(timeout),
    [jweDecrypt]: decrypt5,
    [jwksCache]: jwksCache2
  }).catch(errorHandler);
}
async function validateCodeIdTokenResponse2(config, authorizationResponse, expectedNonce, expectedState, maxAge, fapi) {
  if (typeof expectedNonce !== "string") {
    throw CodedTypeError2('"expectedNonce" must be a string', ERR_INVALID_ARG_TYPE2);
  }
  if (expectedState !== void 0 && typeof expectedState !== "string") {
    throw CodedTypeError2('"expectedState" must be a string', ERR_INVALID_ARG_TYPE2);
  }
  const { as, c, fetch: fetch2, tlsOnly, timeout, decrypt: decrypt5, jwksCache: jwksCache2 } = int(config);
  return (fapi ? validateDetachedSignatureResponse : validateCodeIdTokenResponse)(as, c, authorizationResponse, expectedNonce, expectedState, maxAge, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    headers: new Headers(headers),
    signal: signal2(timeout),
    [jweDecrypt]: decrypt5,
    [jwksCache]: jwksCache2
  }).catch(errorHandler);
}
async function refreshTokenGrant(config, refreshToken, parameters, options) {
  checkConfig(config);
  parameters = new URLSearchParams(parameters);
  const { as, c, auth, fetch: fetch2, tlsOnly, nonRepudiation, timeout, decrypt: decrypt5 } = int(config);
  const response = await refreshTokenGrantRequest(as, c, auth, refreshToken, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    additionalParameters: parameters,
    DPoP: options?.DPoP,
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).catch(errorHandler);
  const p = processRefreshTokenResponse(as, c, response, {
    [jweDecrypt]: decrypt5
  });
  let result;
  try {
    result = await p;
  } catch (err) {
    if (retryable(err, options)) {
      return refreshTokenGrant(config, refreshToken, parameters, {
        ...options,
        flag: retry
      });
    }
    errorHandler(err);
  }
  result.id_token && await nonRepudiation?.(response);
  addHelpers(result);
  return result;
}
async function clientCredentialsGrant(config, parameters, options) {
  checkConfig(config);
  parameters = new URLSearchParams(parameters);
  const { as, c, auth, fetch: fetch2, tlsOnly, timeout } = int(config);
  const response = await clientCredentialsGrantRequest(as, c, auth, parameters, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    DPoP: options?.DPoP,
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).catch(errorHandler);
  const p = processClientCredentialsResponse(as, c, response);
  let result;
  try {
    result = await p;
  } catch (err) {
    if (retryable(err, options)) {
      return clientCredentialsGrant(config, parameters, {
        ...options,
        flag: retry
      });
    }
    errorHandler(err);
  }
  addHelpers(result);
  return result;
}
function buildAuthorizationUrl(config, parameters) {
  checkConfig(config);
  const { as, c, tlsOnly, hybrid, jarm } = int(config);
  const authorizationEndpoint = resolveEndpoint(as, "authorization_endpoint", false, tlsOnly);
  parameters = new URLSearchParams(parameters);
  if (!parameters.has("client_id")) {
    parameters.set("client_id", c.client_id);
  }
  if (!parameters.has("request_uri") && !parameters.has("request")) {
    if (!parameters.has("response_type")) {
      parameters.set("response_type", hybrid ? "code id_token" : "code");
    }
    if (jarm) {
      parameters.set("response_mode", "jwt");
    }
  }
  for (const [k, v] of parameters.entries()) {
    authorizationEndpoint.searchParams.append(k, v);
  }
  return authorizationEndpoint;
}
async function buildAuthorizationUrlWithJAR(config, parameters, signingKey, options) {
  checkConfig(config);
  const authorizationEndpoint = buildAuthorizationUrl(config, parameters);
  parameters = authorizationEndpoint.searchParams;
  if (!signingKey) {
    throw CodedTypeError2('"signingKey" must be provided', ERR_INVALID_ARG_VALUE2);
  }
  const { as, c } = int(config);
  const request = await issueRequestObject(as, c, parameters, signingKey, options).catch(errorHandler);
  return buildAuthorizationUrl(config, { request });
}
async function buildAuthorizationUrlWithPAR(config, parameters, options) {
  checkConfig(config);
  const authorizationEndpoint = buildAuthorizationUrl(config, parameters);
  const { as, c, auth, fetch: fetch2, tlsOnly, timeout } = int(config);
  const response = await pushedAuthorizationRequest(as, c, auth, authorizationEndpoint.searchParams, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    DPoP: options?.DPoP,
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).catch(errorHandler);
  const p = processPushedAuthorizationResponse(as, c, response);
  let result;
  try {
    result = await p;
  } catch (err) {
    if (retryable(err, options)) {
      return buildAuthorizationUrlWithPAR(config, parameters, {
        ...options,
        flag: retry
      });
    }
    errorHandler(err);
  }
  return buildAuthorizationUrl(config, { request_uri: result.request_uri });
}
function buildEndSessionUrl(config, parameters) {
  checkConfig(config);
  const { as, c, tlsOnly } = int(config);
  const endSessionEndpoint = resolveEndpoint(as, "end_session_endpoint", false, tlsOnly);
  parameters = new URLSearchParams(parameters);
  if (!parameters.has("client_id")) {
    parameters.set("client_id", c.client_id);
  }
  for (const [k, v] of parameters.entries()) {
    endSessionEndpoint.searchParams.append(k, v);
  }
  return endSessionEndpoint;
}
function checkConfig(input) {
  if (!(input instanceof Configuration)) {
    throw CodedTypeError2('"config" must be an instance of Configuration', ERR_INVALID_ARG_TYPE2);
  }
  if (Object.getPrototypeOf(input) !== Configuration.prototype) {
    throw CodedTypeError2("subclassing Configuration is not allowed", ERR_INVALID_ARG_VALUE2);
  }
}
function signal2(timeout) {
  return timeout ? AbortSignal.timeout(timeout * 1e3) : void 0;
}
async function fetchUserInfo(config, accessToken, expectedSubject, options) {
  checkConfig(config);
  const { as, c, fetch: fetch2, tlsOnly, nonRepudiation, timeout, decrypt: decrypt5 } = int(config);
  const response = await userInfoRequest(as, c, accessToken, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    DPoP: options?.DPoP,
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).catch(errorHandler);
  let exec = processUserInfoResponse(as, c, expectedSubject, response, {
    [jweDecrypt]: decrypt5
  });
  let result;
  try {
    result = await exec;
  } catch (err) {
    if (retryable(err, options)) {
      return fetchUserInfo(config, accessToken, expectedSubject, {
        ...options,
        flag: retry
      });
    }
    errorHandler(err);
  }
  getContentType2(response) === "application/jwt" && await nonRepudiation?.(response);
  return result;
}
function retryable(err, options) {
  if (options?.DPoP && options.flag !== retry) {
    return isDPoPNonceError(err);
  }
  return false;
}
async function tokenIntrospection(config, token, parameters) {
  checkConfig(config);
  const { as, c, auth, fetch: fetch2, tlsOnly, nonRepudiation, timeout, decrypt: decrypt5 } = int(config);
  const response = await introspectionRequest(as, c, auth, token, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    additionalParameters: new URLSearchParams(parameters),
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).catch(errorHandler);
  const result = await processIntrospectionResponse(as, c, response, {
    [jweDecrypt]: decrypt5
  }).catch(errorHandler);
  getContentType2(response) === "application/token-introspection+jwt" && await nonRepudiation?.(response);
  return result;
}
var retry = Symbol();
async function genericGrantRequest(config, grantType, parameters, options) {
  checkConfig(config);
  const { as, c, auth, fetch: fetch2, tlsOnly, timeout, decrypt: decrypt5 } = int(config);
  const result = await genericTokenEndpointRequest(as, c, auth, grantType, new URLSearchParams(parameters), {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    DPoP: options?.DPoP,
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).then((response) => processGenericTokenEndpointResponse(as, c, response, {
    [jweDecrypt]: decrypt5
  })).catch(errorHandler);
  addHelpers(result);
  return result;
}
async function tokenRevocation(config, token, parameters) {
  checkConfig(config);
  const { as, c, auth, fetch: fetch2, tlsOnly, timeout } = int(config);
  return revocationRequest(as, c, auth, token, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    additionalParameters: new URLSearchParams(parameters),
    headers: new Headers(headers),
    signal: signal2(timeout)
  }).then(processRevocationResponse).catch(errorHandler);
}
async function fetchProtectedResource(config, accessToken, url, method, body, headers2, options) {
  checkConfig(config);
  headers2 ||= new Headers();
  if (!headers2.has("user-agent")) {
    headers2.set("user-agent", USER_AGENT2);
  }
  const { fetch: fetch2, tlsOnly, timeout } = int(config);
  const exec = protectedResourceRequest(accessToken, method, url, headers2, body, {
    [customFetch]: fetch2,
    [allowInsecureRequests]: !tlsOnly,
    DPoP: options?.DPoP,
    signal: signal2(timeout)
  });
  let result;
  try {
    result = await exec;
  } catch (err) {
    if (retryable(err, options)) {
      return fetchProtectedResource(config, accessToken, url, method, body, headers2, {
        ...options,
        flag: retry
      });
    }
    errorHandler(err);
  }
  return result;
}
function getContentType2(response) {
  return response.headers.get("content-type")?.split(";")[0];
}
export {
  AuthorizationResponseError,
  ClientError,
  ClientSecretBasic2 as ClientSecretBasic,
  ClientSecretJwt2 as ClientSecretJwt,
  ClientSecretPost2 as ClientSecretPost,
  Configuration,
  None2 as None,
  PrivateKeyJwt2 as PrivateKeyJwt,
  ResponseBodyError,
  TlsClientAuth2 as TlsClientAuth,
  WWWAuthenticateChallengeError,
  allowInsecureRequests2 as allowInsecureRequests,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  buildAuthorizationUrlWithJAR,
  buildAuthorizationUrlWithPAR,
  buildEndSessionUrl,
  calculatePKCECodeChallenge2 as calculatePKCECodeChallenge,
  clientCredentialsGrant,
  clockSkew2 as clockSkew,
  clockTolerance2 as clockTolerance,
  customFetch2 as customFetch,
  discovery,
  enableDecryptingResponses,
  enableDetachedSignatureResponseChecks,
  enableNonRepudiationChecks,
  fetchProtectedResource,
  fetchUserInfo,
  genericGrantRequest,
  getDPoPHandle,
  getJwksCache,
  initiateDeviceAuthorization,
  modifyAssertion2 as modifyAssertion,
  pollDeviceAuthorizationGrant,
  randomDPoPKeyPair,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
  refreshTokenGrant,
  setJwksCache2 as setJwksCache,
  skipStateCheck2 as skipStateCheck,
  skipSubjectCheck2 as skipSubjectCheck,
  tokenIntrospection,
  tokenRevocation,
  useCodeIdTokenResponseType,
  useJwtResponseMode
};
