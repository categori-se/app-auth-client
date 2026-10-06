// Browser lifecycle only: decoded token claims are display data. Resource APIs
// must independently verify tokens and current identity/access policy.
export function createAuthClient({
  configuration,
  storageKeys,
  resolveRedirectUri,
  resolveLogoutUri,
  beforeHostedFlow,
  groupsClaim = "groups",
  logoutRedirectParameter = "post_logout_redirect_uri",
  displayNameFallback = "User",
  sessionMode = "identity-token",
  refreshSession = false,
  displayUser,
  pkceMaxAgeMs,
  capturePkceContext,
  resolveCallbackHash,
  cleanupParameters
} = {}) {
  const config = validateConfiguration(configuration);
  if (typeof groupsClaim !== "string" || !groupsClaim || typeof displayNameFallback !== "string" || !displayNameFallback) {
    throw new TypeError("Display claim names and fallback labels must be nonempty strings.");
  }
  if (typeof logoutRedirectParameter !== "string" || !/^[a-z][a-z0-9_]*$/.test(logoutRedirectParameter) || logoutRedirectParameter === "client_id") {
    throw new TypeError("A distinct provider logout redirect parameter is required.");
  }
  if (!storageKeys || typeof storageKeys.sessionKey !== "string" || !storageKeys.sessionKey ||
      typeof storageKeys.pkceKey !== "string" || !storageKeys.pkceKey || storageKeys.sessionKey === storageKeys.pkceKey) {
    throw new TypeError("Distinct app-owned session and PKCE storage keys are required.");
  }
  for (const hook of [resolveRedirectUri, resolveLogoutUri, beforeHostedFlow, displayUser, capturePkceContext, resolveCallbackHash]) {
    if (hook !== undefined && typeof hook !== "function") throw new TypeError("Authentication hooks must be functions.");
  }
  if (!["identity-token", "access-token"].includes(sessionMode) || typeof refreshSession !== "boolean") {
    throw new TypeError("An explicit supported session mode and boolean refresh option are required.");
  }
  if (pkceMaxAgeMs !== undefined && (!Number.isFinite(pkceMaxAgeMs) || pkceMaxAgeMs <= 0)) {
    throw new TypeError("The pending sign-in lifetime must be a positive finite number.");
  }
  if (cleanupParameters !== undefined && (!Array.isArray(cleanupParameters) || cleanupParameters.some(key => typeof key !== "string" || !key))) {
    throw new TypeError("Callback cleanup parameters must be nonempty strings.");
  }
  const callbackParameters = cleanupParameters === undefined ? null : [...cleanupParameters];
  const {sessionKey, pkceKey} = storageKeys;
  const sessionRecords = new WeakMap();
  let authEpoch = 0;
  let memorySession = null;
  let lastStorage = null;
  let lastStorageWindow = null;
  let refreshFlight = null;

  async function loadAuthSession() {
    const url = new URL(window.location.href);

    if (url.searchParams.has("error")) {
      if (resolveCallbackHash || pkceMaxAgeMs !== undefined || capturePkceContext) return completeProviderError(url);
      authEpoch += 1;
      memorySession = null;
      const error = url.searchParams.get("error_description") || url.searchParams.get("error") || "Sign-in failed.";
      clearUrlParams(url.href);
      return {status: "unauthenticated", session: null, error};
    }

    if (url.searchParams.has("code")) return completeSignIn(url);

    if (url.searchParams.get("auth") === "sign-in") {
      clearUrlParams(url.href);
      await beginSignIn();
      return {status: "loading", session: null, error: null};
    }

    if (url.searchParams.get("auth") === "register") {
      clearUrlParams(url.href);
      await beginRegistration();
      return {status: "loading", session: null, error: null};
    }

    if (url.searchParams.get("auth") === "reset-password") {
      clearUrlParams(url.href);
      await beginPasswordReset();
      return {status: "loading", session: null, error: null};
    }

    return currentAuthResult();
  }

  async function beginSignIn() {
    await beginHostedFlow("sign-in", config.authorizationEndpoint);
  }

  async function beginRegistration() {
    await beginHostedFlow("register", config.registrationEndpoint);
  }

  async function beginPasswordReset() {
    await beginHostedFlow("reset-password", config.passwordResetEndpoint);
  }

  async function beginHostedFlow(action, endpoint) {
    const redirected = beforeHostedFlow?.(action);
    if (redirected && typeof redirected.then === "function") throw new TypeError("Authentication routing hooks must be synchronous.");
    if (redirected === true) return;
    if (!endpoint) throw new Error("The configured provider does not support this sign-in action.");
    const authParams = await createPkceAuthParams();
    if (!authParams || !isAuthContextCurrent(authParams.context)) return;
    const authorizeUrl = new URL(endpoint);
    setAuthParams(authorizeUrl, authParams);
    authorizeUrl.searchParams.set("response_type", "code");
    window.location.assign(authorizeUrl.toString());
  }

  function signOut() {
    authEpoch += 1;
    memorySession = null;
    const storage = getStorage() || (lastStorageWindow === globalThis.window ? lastStorage : null);
    if (storage) {
      const record = getSessionRecord(storage);
      const observed = readStorage(storage, sessionKey);
      const raw = observed.available ? observed.raw : record.lastRaw;
      if (raw) record.signedOut.add(raw);
      const removed = removeStorage(storage, sessionKey);
      if (!removed && !raw) record.blockUnknown = true;
      removeStorage(storage, pkceKey);
    }
    if (!config.logoutEndpoint) return;
    const logoutUrl = new URL(config.logoutEndpoint);
    logoutUrl.searchParams.set("client_id", config.clientId);
    logoutUrl.searchParams.set(logoutRedirectParameter, getLogoutUri());
    window.location.assign(logoutUrl.toString());
  }

  // Only browser storage can confirm authority for API requests. A just-created
  // memory session can be displayed but never substitutes for this read.
  function getStoredAuthSession() {
    return readStoredSession();
  }

  function getAuthState() {
    return currentAuthResult();
  }

  async function getAccessToken() {
    const storage = getStorage();
    const context = {epoch: authEpoch, browser: globalThis.window, storage, sessionRaw: null};
    const observed = readStorage(storage, sessionKey);
    context.sessionRaw = observed.raw;
    const session = readStoredSession({allowRefreshable: true});
    if (!observed.available || !session) return null;
    if (validSession(session) && nonemptyToken(session.accessToken)) return isRefreshContextCurrent(context) ? session.accessToken : null;
    if (!refreshSession || !refreshableSession(session)) return null;
    if (!isRefreshContextCurrent(context)) return null;
    if (refreshFlight && sameRefreshContext(refreshFlight.context, context)) return refreshFlight.promise;
    const flight = {context, promise: null};
    flight.promise = refreshAccessToken(context, session).finally(() => {
      if (refreshFlight === flight) refreshFlight = null;
    });
    refreshFlight = flight;
    return flight.promise;
  }

  async function refreshAccessToken(context, previousSession) {
    let response;
    try {
      response = await fetch(config.tokenEndpoint, {
        method: "POST",
        headers: {"content-type": "application/x-www-form-urlencoded"},
        redirect: "error", credentials: "omit",
        body: new URLSearchParams({grant_type: "refresh_token", client_id: config.clientId, refresh_token: previousSession.refreshToken})
      });
    } catch {
      return finishFailedRefresh(context);
    }
    if (!isRefreshContextCurrent(context)) return null;
    if (!response.ok) return finishFailedRefresh(context);
    let tokenSet;
    try { tokenSet = await response.json(); }
    catch { return finishFailedRefresh(context); }
    if (!isRefreshContextCurrent(context)) return null;
    let session;
    try { session = sessionFromTokens(tokenSet, previousSession, true); }
    catch { return finishFailedRefresh(context); }
    if (!isRefreshContextCurrent(context)) return null;
    const raw = JSON.stringify(session);
    try {
      context.storage.setItem(sessionKey, raw);
      if (context.storage.getItem(sessionKey) !== raw) return finishUnstoredRefresh(context, raw);
    } catch { return finishUnstoredRefresh(context, raw); }
    if (!isRefreshContextCurrent({...context, sessionRaw: raw})) return null;
    const record = getSessionRecord(context.storage);
    record.lastRaw = raw;
    memorySession = null;
    return validSession(session) ? session.accessToken : null;
  }

  function finishFailedRefresh(context) {
    if (isRefreshContextCurrent(context)) {
      getSessionRecord(context.storage).signedOut.add(context.sessionRaw);
      removeStorage(context.storage, sessionKey);
      memorySession = null;
    }
    return null;
  }

  function finishUnstoredRefresh(context, attemptedRaw) {
    if (context.browser === globalThis.window && context.epoch === authEpoch && getStorage() === context.storage) {
      const record = getSessionRecord(context.storage);
      record.signedOut.add(context.sessionRaw);
      record.signedOut.add(attemptedRaw);
      const observed = readStorage(context.storage, sessionKey);
      if (observed.available && [context.sessionRaw, attemptedRaw].includes(observed.raw)) removeStorage(context.storage, sessionKey);
      memorySession = null;
    }
    return null;
  }

  function sameRefreshContext(first, second) {
    return first.epoch === second.epoch && first.browser === second.browser && first.storage === second.storage && first.sessionRaw === second.sessionRaw;
  }

  function isRefreshContextCurrent(context) {
    if (context.browser !== globalThis.window || context.epoch !== authEpoch || getStorage() !== context.storage) return false;
    const observed = readStorage(context.storage, sessionKey);
    const record = getSessionRecord(context.storage);
    return observed.available && observed.raw === context.sessionRaw && !record.blockUnknown && !record.signedOut.has(observed.raw);
  }

  function completeProviderError(url) {
    const storage = getStorage();
    const pkce = readStorage(storage, pkceKey);
    const previousSession = readStorage(storage, sessionKey);
    const pending = parsePendingPkce(pkce.raw);
    if (!pkce.available || !previousSession.available || !pending || getSessionRecord(storage).consumedPkce.has(pkce.raw) ||
        !matchesPendingCallback(url, pending) || url.searchParams.getAll("error").length !== 1) {
      clearUrlParams(url.href);
      return {status: "unauthenticated", session: null, error: "Sign-in state did not match. Start sign-in again."};
    }
    const context = {epoch: ++authEpoch, browser: globalThis.window, storage, pkceRaw: pkce.raw,
      sessionRaw: previousSession.raw, callbackUrl: url.href, callbackHash: callbackHash(pending)};
    return finishFailedSignIn(context, url.searchParams.get("error_description") || url.searchParams.get("error") || "Sign-in failed.");
  }

  async function completeSignIn(url) {
    const storage = getStorage();
    const pkce = readStorage(storage, pkceKey);
    const previousSession = readStorage(storage, sessionKey);
    const pending = parsePendingPkce(pkce.raw);
    if (!pkce.available || !previousSession.available || !pending || getSessionRecord(storage).consumedPkce.has(pkce.raw)) {
      clearUrlParams(url.href);
      return {status: "unauthenticated", session: null, error: "Sign-in state was not found. Start sign-in again."};
    }
    if (url.searchParams.get("state") !== pending.state) {
      // A stale callback must not destroy a newer sign-in's pending state.
      clearUrlParams(url.href);
      return {status: "unauthenticated", session: null, error: "Sign-in state did not match. Start sign-in again."};
    }
    if (!matchesPendingCallback(url, pending) || url.searchParams.getAll("code").length !== 1 || !url.searchParams.get("code")) {
      clearUrlParams(url.href);
      return {status: "unauthenticated", session: null, error: "Sign-in callback did not match this application's configuration. Start sign-in again."};
    }
    const epoch = ++authEpoch;
    const context = {epoch, browser: globalThis.window, storage, pkceRaw: pkce.raw, sessionRaw: previousSession.raw,
      callbackUrl: url.href, callbackHash: callbackHash(pending)};
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      code: url.searchParams.get("code"),
      redirect_uri: pending.redirectUri,
      code_verifier: pending.verifier
    });

    let response;
    try {
      response = await fetch(config.tokenEndpoint, {
        method: "POST",
        headers: {"content-type": "application/x-www-form-urlencoded"},
        redirect: "error",
        credentials: "omit",
        body
      });
    } catch (error) {
      if (!isAuthContextCurrent(context)) return currentAuthResult("Sign-in changed. Start sign-in again.");
      if (sessionMode === "access-token") return finishFailedSignIn(context, "The sign-in response could not be read. Start sign-in again.");
      throw error;
    }
    if (!isAuthContextCurrent(context)) return currentAuthResult("Sign-in changed. Start sign-in again.");
    if (!response.ok) return finishFailedSignIn(context, `Token exchange failed with HTTP ${response.status}.`);

    let tokenSet;
    try {
      tokenSet = await response.json();
    } catch (error) {
      if (!isAuthContextCurrent(context)) return currentAuthResult("Sign-in changed. Start sign-in again.");
      return finishFailedSignIn(context, "The sign-in response could not be read. Start sign-in again.");
    }
    if (!isAuthContextCurrent(context)) return currentAuthResult("Sign-in changed. Start sign-in again.");

    let session;
    try {
      session = sessionFromTokens(tokenSet);
    } catch {
      return finishFailedSignIn(context, "The sign-in response was invalid. Start sign-in again.");
    }
    if (!isAuthContextCurrent(context)) return currentAuthResult("Sign-in changed. Start sign-in again.");

    // No asynchronous work occurs between the final comparison and storage writes.
    const raw = JSON.stringify(session);
    let stored = false;
    try {
      storage.setItem(sessionKey, raw);
      stored = storage.getItem(sessionKey) === raw;
    } catch { /* The current page can retain the session without durable storage. */ }
    if (stored) {
      const record = getSessionRecord(storage);
      record.lastRaw = raw;
      record.blockUnknown = false;
      memorySession = null;
    } else {
      if (context.sessionRaw) getSessionRecord(storage).signedOut.add(context.sessionRaw);
      memorySession = {session, storage, epoch, previousRaw: context.sessionRaw};
    }
    // A failed PKCE removal must not make a consumed callback reusable here.
    authEpoch += 1;
    getSessionRecord(storage).consumedPkce.add(context.pkceRaw);
    removeStorage(storage, pkceKey);
    clearUrlParams(context.callbackUrl, context.callbackHash);
    return {
      status: "authenticated", session, error: null,
      ...(stored ? {} : {storageWarning: "Your sign-in could not be saved in this browser. Private workspace data is unavailable until browser storage works."})
    };
  }

  function finishFailedSignIn(context, error) {
    if (!isAuthContextCurrent(context)) return currentAuthResult("Sign-in changed. Start sign-in again.");
    authEpoch += 1;
    getSessionRecord(context.storage).consumedPkce.add(context.pkceRaw);
    removeStorage(context.storage, pkceKey);
    if (sessionMode === "access-token") {
      if (context.sessionRaw) getSessionRecord(context.storage).signedOut.add(context.sessionRaw);
      removeStorage(context.storage, sessionKey);
      memorySession = null;
    }
    clearUrlParams(context.callbackUrl, context.callbackHash);
    return {status: "unauthenticated", session: null, error};
  }

  function isAuthContextCurrent(context) {
    if (context.browser !== globalThis.window || context.epoch !== authEpoch || getStorage() !== context.storage || window.location.href !== context.callbackUrl) return false;
    const pending = readStorage(context.storage, pkceKey);
    const session = readStorage(context.storage, sessionKey);
    return pending.available && session.available && pending.raw === context.pkceRaw && session.raw === context.sessionRaw;
  }

  async function createPkceAuthParams() {
    const epoch = ++authEpoch;
    memorySession = null;
    const storage = getStorage();
    const session = readStorage(storage, sessionKey);
    const pending = readStorage(storage, pkceKey);
    if (!session.available || !pending.available) throw new Error("Browser storage is unavailable. Enable it before signing in.");
    const initiatingWindow = globalThis.window;
    const initiatingUrl = window.location.href;
    const redirectUri = getRedirectUri();
    const state = randomString(24);
    const verifier = randomString(64);
    const additional = capturePkceContext === undefined ? {} : pkceContext(capturePkceContext());
    const pendingRecord = {...additional, state, verifier, redirectUri,
      ...(pkceMaxAgeMs !== undefined || capturePkceContext ? {createdAt: Date.now()} : {})};
    const pkceRaw = JSON.stringify(pendingRecord);
    const challenge = await sha256Base64Url(verifier);
    const currentSession = readStorage(storage, sessionKey);
    const currentPending = readStorage(storage, pkceKey);
    if (initiatingWindow !== globalThis.window || epoch !== authEpoch || getStorage() !== storage || window.location.href !== initiatingUrl ||
        !currentSession.available || !currentPending.available || currentSession.raw !== session.raw || currentPending.raw !== pending.raw) return null;
    try {
      storage.setItem(pkceKey, pkceRaw);
    } catch {
      throw new Error("Browser storage is unavailable. Enable it before signing in.");
    }
    const context = {epoch, browser: globalThis.window, storage, pkceRaw, sessionRaw: session.raw, callbackUrl: initiatingUrl};
    return {redirectUri, state, challenge, context};
  }

  function setAuthParams(url, {redirectUri, state, challenge}) {
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("scope", config.scopes.join(" "));
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
  }

  function readStoredSession({allowRefreshable = false} = {}) {
    const storage = getStorage();
    const observed = readStorage(storage, sessionKey);
    if (!observed.available) return null;
    const record = getSessionRecord(storage);
    record.lastRaw = observed.raw;
    if (record.blockUnknown || record.signedOut.has(observed.raw)) return null;
    try {
      const session = JSON.parse(observed.raw || "null");
      if (!validSession(session)) {
        if (refreshSession && refreshableSession(session)) return allowRefreshable ? session : null;
        removeStorage(storage, sessionKey);
        return null;
      }
      return session;
    } catch {
      removeStorage(storage, sessionKey);
      return null;
    }
  }

  function validSession(session) {
    const tokenPresent = sessionMode === "access-token" ? nonemptyToken(session?.accessToken) : session?.idToken;
    return Boolean(tokenPresent && Number.isFinite(session.expiresAt) && session.expiresAt > Date.now() + 30000);
  }

  function refreshableSession(session) {
    return Boolean(session && nonemptyToken(session.accessToken) && nonemptyToken(session.refreshToken) && Number.isFinite(session.expiresAt) &&
      (sessionMode === "access-token" || nonemptyToken(session.idToken)));
  }

  function nonemptyToken(value) {
    return typeof value === "string" && value.length > 0;
  }

  function sessionFromTokens(tokenSet, previousSession = null, refreshing = false) {
    if (!tokenSet || typeof tokenSet !== "object" || Array.isArray(tokenSet)) throw new Error("Invalid token response");
    const strict = refreshing || sessionMode === "access-token";
    const lifetime = Number(strict ? tokenSet.expires_in : (tokenSet.expires_in || 3600));
    const expiresAt = Date.now() + lifetime * 1000;
    if (!(strict ? nonemptyToken(tokenSet.access_token) : tokenSet.access_token) || !Number.isFinite(lifetime) || lifetime <= 30 || !Number.isSafeInteger(Math.ceil(expiresAt)) ||
        (strict && !["string", "number"].includes(typeof tokenSet.expires_in))) throw new Error("Invalid token response");
    if (strict && tokenSet.refresh_token !== undefined && !nonemptyToken(tokenSet.refresh_token)) throw new Error("Invalid refresh token");
    let claims = null;
    if (nonemptyToken(tokenSet.id_token)) claims = decodeJwt(tokenSet.id_token);
    else if (sessionMode === "identity-token" && !refreshing) throw new Error("Missing identity token");
    const user = displayUser ? displayUser(claims, previousSession?.user ?? null) : (claims ? {
      id: claims.sub,
      email: claims.email,
      name: claims.name || claims.email || displayNameFallback,
      groups: claims[groupsClaim] || []
    } : previousSession?.user ?? null);
    if (user && typeof user.then === "function") throw new TypeError("Display hooks must be synchronous.");
    const session = {
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token === undefined ? previousSession?.refreshToken : tokenSet.refresh_token,
      expiresAt, user
    };
    if (sessionMode === "identity-token") session.idToken = tokenSet.id_token || previousSession?.idToken;
    return session;
  }

  function currentAuthResult(error = null) {
    const stored = readStoredSession({allowRefreshable: true});
    if (stored) return {status: "authenticated", session: stored, error: null};
    if (memorySession && memorySession.storage === getStorage() && memorySession.epoch + 1 === authEpoch && validSession(memorySession.session)) {
      const observed = readStorage(memorySession.storage, sessionKey);
      if (!observed.available || observed.raw === memorySession.previousRaw) {
        return {status: "authenticated", session: memorySession.session, error: null,
          storageWarning: "Your sign-in could not be saved in this browser. Private workspace data is unavailable until browser storage works."};
      }
    }
    memorySession = null;
    return {status: "unauthenticated", session: null, error};
  }

  function parsePendingPkce(raw) {
    try {
      const value = JSON.parse(raw || "null");
      if (pkceMaxAgeMs !== undefined && (!Number.isFinite(value?.createdAt) || Date.now() - value.createdAt < 0 || Date.now() - value.createdAt > pkceMaxAgeMs)) return null;
      return value && typeof value.state === "string" && value.state && typeof value.verifier === "string" && value.verifier &&
        typeof value.redirectUri === "string" && value.redirectUri ? value : null;
    } catch { return null; }
  }

  function matchesPendingCallback(url, pending) {
    const redirect = new URL(getRedirectUri());
    return pending.redirectUri === redirect.href && url.origin === redirect.origin && url.pathname === redirect.pathname &&
      url.searchParams.getAll("state").length === 1 && url.searchParams.get("state") === pending.state;
  }

  function callbackHash(pending) {
    if (!resolveCallbackHash) return undefined;
    const hash = resolveCallbackHash(pending);
    if (typeof hash !== "string" || (hash !== "" && !hash.startsWith("#")) || /[\r\n\u0000]/.test(hash)) {
      throw new TypeError("Callback navigation hooks must return a safe hash string.");
    }
    return hash;
  }

  function pkceContext(value) {
    if (!value || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("Pending sign-in context must be a small plain JSON object.");
    function validJson(item, depth = 0) {
      if (depth > 8) return false;
      if (item === null || typeof item === "string" || typeof item === "boolean") return true;
      if (typeof item === "number") return Number.isFinite(item);
      if (Array.isArray(item)) return item.every(entry => validJson(entry, depth + 1));
      return Boolean(item && Object.getPrototypeOf(item) === Object.prototype && Object.values(item).every(entry => validJson(entry, depth + 1)));
    }
    if (!validJson(value)) throw new TypeError("Pending sign-in context must contain only JSON data.");
    const raw = JSON.stringify(value);
    if (raw.length > 4096) throw new TypeError("Pending sign-in context must be small.");
    return JSON.parse(raw);
  }

  function getStorage() {
    try {
      const storage = globalThis.sessionStorage || null;
      if (storage) { lastStorage = storage; lastStorageWindow = globalThis.window; }
      return storage;
    } catch { return null; }
  }

  function getSessionRecord(storage) {
    let record = sessionRecords.get(storage);
    if (!record) { record = {signedOut: new Set(), consumedPkce: new Set(), lastRaw: null, blockUnknown: false}; sessionRecords.set(storage, record); }
    return record;
  }

  function readStorage(storage, key) {
    try { return storage ? {available: true, raw: storage.getItem(key)} : {available: false, raw: null}; }
    catch { return {available: false, raw: null}; }
  }

  function removeStorage(storage, key) {
    try { storage?.removeItem(key); return Boolean(storage); } catch { return false; }
  }

  function getRedirectUri() {
    return validateCallbackUri(resolveRedirectUri?.() ?? config.redirectUri);
  }

  function getLogoutUri() {
    return validateCallbackUri(resolveLogoutUri?.() ?? config.logoutUri);
  }

  function decodeJwt(token) {
    const [, payload] = String(token || "").split(".");
    if (!payload) throw new Error("Missing identity token payload");
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`;
    const decoded = atob(padded);
    const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  }

  function clearUrlParams(expectedUrl, restoredHash) {
    if (window.location.href !== expectedUrl) return;
    const url = new URL(expectedUrl);
    if (callbackParameters) for (const name of callbackParameters) url.searchParams.delete(name);
    else url.search = "";
    if (restoredHash !== undefined) url.hash = restoredHash;
    const cleanUrl = `${url.pathname}${url.search}${url.hash}`;
    window.history.replaceState({}, document.title, cleanUrl);
  }

  function randomString(byteCount) {
    const bytes = new Uint8Array(byteCount);
    crypto.getRandomValues(bytes);
    return base64Url(bytes);
  }

  async function sha256Base64Url(value) {
    const bytes = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return base64Url(new Uint8Array(digest));
  }

  function base64Url(bytes) {
    let binary = "";
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  return Object.freeze({loadAuthSession, beginSignIn, beginRegistration, beginPasswordReset, signOut, getStoredAuthSession, getAuthState, getAccessToken});
}

function endpoint(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) {
    throw new TypeError("Provider endpoints must be explicit HTTPS URLs without credentials, query or fragments.");
  }
  return url.href;
}

function validateCallbackUri(value) {
  const url = new URL(value);
  const loopback = url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname);
  if ((!loopback && url.protocol !== "https:") || url.username || url.password || url.hash || url.search) {
    throw new TypeError("Callback URLs must be HTTPS or explicit local loopback URLs.");
  }
  return url.href;
}

function validateConfiguration(configuration) {
  if (!configuration || typeof configuration.clientId !== "string" || !configuration.clientId ||
      !Array.isArray(configuration.scopes) || !configuration.scopes.length ||
      configuration.scopes.some(scope => typeof scope !== "string" || !scope || /\s/.test(scope))) {
    throw new TypeError("An explicit public client ID and scope list are required.");
  }
  const optionalEndpoint = value => value === undefined || value === null ? null : endpoint(value);
  return Object.freeze({
    clientId: configuration.clientId,
    scopes: Object.freeze([...configuration.scopes]),
    authorizationEndpoint: endpoint(configuration.authorizationEndpoint),
    tokenEndpoint: endpoint(configuration.tokenEndpoint),
    registrationEndpoint: optionalEndpoint(configuration.registrationEndpoint),
    passwordResetEndpoint: optionalEndpoint(configuration.passwordResetEndpoint),
    logoutEndpoint: optionalEndpoint(configuration.logoutEndpoint),
    redirectUri: validateCallbackUri(configuration.redirectUri),
    logoutUri: validateCallbackUri(configuration.logoutUri)
  });
}
