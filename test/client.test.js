import assert from "node:assert/strict";
import test from "node:test";
import {createHash} from "node:crypto";
import {createAuthClient} from "../src/index.js";

const configuration = () => ({
  clientId: "fixture-public-client", scopes: ["openid", "profile"],
  authorizationEndpoint: "https://login.fixture.invalid/authorize",
  tokenEndpoint: "https://login.fixture.invalid/token",
  registrationEndpoint: "https://login.fixture.invalid/register",
  passwordResetEndpoint: "https://login.fixture.invalid/reset",
  logoutEndpoint: "https://login.fixture.invalid/logout",
  redirectUri: "https://app.fixture.invalid/",
  logoutUri: "https://app.fixture.invalid/"
});
const deferred = () => {
  let resolve;
  const promise = new Promise(yes => { resolve = yes; });
  return {promise, resolve};
};
const tokenSet = (id = "fixture-user") => ({
  access_token: `fixture-access-${id}`,
  id_token: `fixture.${Buffer.from(JSON.stringify({sub: id, name: "Fixture user", groups: ["fixture-reviewer"]})).toString("base64url")}.signature`,
  expires_in: 3600
});

function browser() {
  const names = ["window", "document", "sessionStorage", "fetch"];
  const original = new Map(names.map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const values = new Map();
  const storage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key)
  };
  const redirects = [];
  const win = {sessionStorage: storage};
  const navigate = href => {
    win.location = new URL(href, "https://app.fixture.invalid/");
    win.location.assign = value => redirects.push(new URL(value));
  };
  navigate("/");
  win.history = {replaceState: (_, __, href) => navigate(href)};
  globalThis.window = win;
  globalThis.document = {title: "Independent application"};
  globalThis.sessionStorage = storage;
  globalThis.fetch = () => { throw new Error("External network is forbidden"); };
  const client = (name = "app", overrides = {}) => createAuthClient({
    configuration: configuration(),
    storageKeys: {sessionKey: `${name}.session`, pkceKey: `${name}.pkce`}, ...overrides
  });
  const callback = (name = "app", state = "fixture-state") => {
    storage.setItem(`${name}.pkce`, JSON.stringify({state, verifier: "v".repeat(64), redirectUri: configuration().redirectUri}));
    navigate(`/?code=fixture-code&state=${state}`);
  };
  return {storage, values, redirects, navigate, client, callback, restore() {
    for (const [name, descriptor] of original) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }};
}

test("independent provider configuration generates S256 PKCE without exposing its verifier", async () => {
  const fixture = browser();
  try {
    const client = fixture.client();
    await client.beginSignIn();
    const first = JSON.parse(fixture.storage.getItem("app.pkce"));
    const url = fixture.redirects[0];
    assert.equal(url.origin, "https://login.fixture.invalid");
    assert.equal(url.searchParams.get("client_id"), "fixture-public-client");
    assert.equal(url.searchParams.get("scope"), "openid profile");
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.match(first.verifier, /^[A-Za-z0-9_-]{43,128}$/);
    assert.equal(url.searchParams.get("code_challenge"), createHash("sha256").update(first.verifier).digest("base64url"));
    assert.equal(url.searchParams.get("state"), first.state);
    assert.equal(url.searchParams.has("code_verifier"), false);
    await client.beginSignIn();
    const second = JSON.parse(fixture.storage.getItem("app.pkce"));
    assert.notEqual(second.verifier, first.verifier);
    assert.notEqual(second.state, first.state);
  } finally { fixture.restore(); }
});

test("callback exchanges use the configured endpoint and reject credential-forwarding redirects", async () => {
  const fixture = browser();
  try {
    fixture.callback();
    const requests = [];
    globalThis.fetch = async (url, options) => { requests.push({url, options}); return Response.json(tokenSet()); };
    const client = fixture.client();
    assert.equal((await client.loadAuthSession()).session.user.id, "fixture-user");
    assert.equal(requests[0].url, configuration().tokenEndpoint);
    assert.equal(requests[0].options.redirect, "error");
    assert.equal(requests[0].options.credentials, "omit");
    assert.equal(requests[0].options.body.get("code_verifier"), "v".repeat(64));
    assert.equal(fixture.storage.getItem("app.pkce"), null);
    assert.equal(client.getStoredAuthSession().accessToken, "fixture-access-fixture-user");
    assert.deepEqual(client.getStoredAuthSession().user.groups, ["fixture-reviewer"]);
  } finally { fixture.restore(); }
});

test("foreign, duplicate and empty callbacks cannot exchange codes or replace the pending transaction", async t => {
  for (const href of ["/other?code=fixture-code&state=fixture-state", "/?code=fixture-code&code=other&state=fixture-state",
    "/?code=&state=fixture-state", "/?code=fixture-code&state=fixture-state&state=other"]) {
    await t.test(href, async () => {
      const fixture = browser();
      try {
        fixture.callback();
        const previous = fixture.storage.getItem("app.pkce");
        fixture.navigate(href);
        assert.equal((await fixture.client().loadAuthSession()).status, "unauthenticated");
        assert.equal(fixture.storage.getItem("app.pkce"), previous);
      } finally { fixture.restore(); }
    });
  }
});

test("signout during a token exchange prevents later body parsing and session resurrection", async () => {
  const fixture = browser();
  try {
    fixture.callback();
    const client = fixture.client(), wait = deferred();
    globalThis.fetch = () => wait.promise;
    const running = client.loadAuthSession();
    client.signOut();
    let parsed = false;
    wait.resolve({ok: true, json() { parsed = true; return tokenSet(); }});
    assert.equal((await running).status, "unauthenticated");
    assert.equal(parsed, false);
    assert.equal(client.getStoredAuthSession(), null);
  } finally { fixture.restore(); }
});

test("two app instances preserve separate sessions and cancellation epochs", async () => {
  const fixture = browser();
  try {
    const first = fixture.client("first"), second = fixture.client("second");
    fixture.storage.setItem("first.session", JSON.stringify({idToken: "fixture-old", expiresAt: Date.now() + 3600000}));
    fixture.callback("second");
    const wait = deferred();
    globalThis.fetch = () => wait.promise;
    const running = second.loadAuthSession();
    first.signOut();
    wait.resolve(Response.json(tokenSet("second-user")));
    assert.equal((await running).session.user.id, "second-user");
    assert.equal(first.getStoredAuthSession(), null);
    assert.equal(second.getStoredAuthSession().user.id, "second-user");
    assert.equal(fixture.storage.getItem("first.pkce"), null);
    assert.equal(fixture.redirects[0].searchParams.get("post_logout_redirect_uri"), configuration().logoutUri);
    assert.equal(fixture.redirects[0].searchParams.has("logout_uri"), false);
  } finally { fixture.restore(); }
});

test("later changes to caller configuration cannot change a client's provider or requested scopes", async () => {
  const fixture = browser();
  try {
    const config = configuration();
    const client = fixture.client("app", {configuration: config});
    config.authorizationEndpoint = "https://other.fixture.invalid/authorize";
    config.scopes.push("admin");
    await client.beginSignIn();
    assert.equal(fixture.redirects[0].origin, "https://login.fixture.invalid");
    assert.equal(fixture.redirects[0].searchParams.get("scope"), "openid profile");
  } finally { fixture.restore(); }
});

test("app routing can retain its own navigation while unsupported provider flows fail explicitly", async () => {
  const fixture = browser();
  try {
    const client = fixture.client("app", {beforeHostedFlow: action => action === "sign-in"});
    await client.beginSignIn();
    assert.equal(fixture.redirects.length, 0);
    assert.equal(fixture.storage.getItem("app.pkce"), null);
    const config = configuration(); delete config.passwordResetEndpoint;
    await assert.rejects(fixture.client("other", {configuration: config}).beginPasswordReset(), /does not support/);
  } finally { fixture.restore(); }
});

test("unsafe endpoints, callbacks and shared storage keys are rejected before a flow begins", () => {
  const fixture = browser();
  try {
    for (const [field, value] of [["tokenEndpoint", "http://remote.fixture.invalid/token"],
      ["authorizationEndpoint", "https://login.fixture.invalid/authorize#fragment"],
      ["redirectUri", "http://remote.fixture.invalid/"], ["logoutUri", "https://user:password@app.fixture.invalid/"]]) {
      assert.throws(() => fixture.client("app", {configuration: {...configuration(), [field]: value}}), TypeError);
    }
    assert.throws(() => fixture.client("app", {storageKeys: {sessionKey: "same", pkceKey: "same"}}), /Distinct/);
    assert.throws(() => fixture.client("app", {logoutRedirectParameter: "client_id"}), /distinct/);
  } finally { fixture.restore(); }
});

const legacyAccessSession = (overrides = {}) => ({
  user: {sub: "fixture-user", name: "Workbench user"},
  accessToken: "fixture-expired-access", refreshToken: "fixture-refresh",
  expiresAt: Date.now() - 1000, ...overrides
});
const accessOptions = {sessionMode: "access-token", refreshSession: true};

test("access sessions remain refreshable and concurrent requests use one durable renewal without adding identity tokens", async () => {
  const fixture = browser();
  try {
    const previous = legacyAccessSession();
    fixture.storage.setItem("app.session", JSON.stringify(previous));
    const mapped = [];
    const client = fixture.client("app", {...accessOptions, displayUser(claims, user) { mapped.push({claims, user}); return user; }});
    assert.equal((await client.loadAuthSession()).status, "authenticated");
    assert.equal(client.getStoredAuthSession(), null);
    assert.equal(client.getAuthState().session.user.name, "Workbench user");
    assert.equal(JSON.parse(fixture.storage.getItem("app.session")).refreshToken, "fixture-refresh");
    const wait = deferred(), requests = [];
    globalThis.fetch = (url, options) => { requests.push({url, options}); return wait.promise; };
    const first = client.getAccessToken(), second = client.getAccessToken();
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, configuration().tokenEndpoint);
    assert.equal(requests[0].options.body.get("grant_type"), "refresh_token");
    assert.equal(requests[0].options.body.get("refresh_token"), "fixture-refresh");
    assert.equal(requests[0].options.redirect, "error");
    assert.equal(requests[0].options.credentials, "omit");
    wait.resolve(Response.json({access_token: "fixture-renewed", expires_in: 3600}));
    assert.deepEqual(await Promise.all([first, second]), ["fixture-renewed", "fixture-renewed"]);
    assert.equal(await client.getAccessToken(), "fixture-renewed");
    assert.equal(requests.length, 1);
    assert.deepEqual(mapped, [{claims: null, user: previous.user}]);
    const saved = JSON.parse(fixture.storage.getItem("app.session"));
    assert.equal(saved.refreshToken, "fixture-refresh");
    assert.deepEqual(saved.user, previous.user);
    assert.equal("idToken" in saved, false);
    assert.equal(client.getStoredAuthSession().accessToken, "fixture-renewed");
  } finally { fixture.restore(); }
});

test("refresh failures clear only the current session and reject malformed lifetimes and bodies", async t => {
  for (const [name, response] of [
    ["HTTP failure", () => ({ok: false, status: 401})],
    ["unreadable response", () => ({ok: true, json: async () => { throw new Error("fixture malformed JSON"); }})],
    ["missing lifetime", () => Response.json({access_token: "fixture-renewed"})],
    ["unsafe lifetime", () => Response.json({access_token: "fixture-renewed", expires_in: 1e30})]
  ]) {
    await t.test(name, async () => {
      const fixture = browser();
      try {
        fixture.storage.setItem("app.session", JSON.stringify(legacyAccessSession()));
        globalThis.fetch = async () => response();
        const client = fixture.client("app", accessOptions);
        assert.equal(await client.getAccessToken(), null);
        assert.equal(fixture.storage.getItem("app.session"), null);
        assert.equal(client.getAuthState().status, "unauthenticated");
      } finally { fixture.restore(); }
    });
  }
});

test("signout during refresh prevents parsing a late fetch and restoring a session", async () => {
  const fixture = browser();
  try {
    fixture.storage.setItem("app.session", JSON.stringify(legacyAccessSession()));
    const client = fixture.client("app", accessOptions), wait = deferred();
    globalThis.fetch = () => wait.promise;
    const running = client.getAccessToken();
    client.signOut();
    let parsed = false;
    wait.resolve({ok: true, json() { parsed = true; return {access_token: "fixture-late", expires_in: 3600}; }});
    assert.equal(await running, null);
    assert.equal(parsed, false);
    assert.equal(fixture.storage.getItem("app.session"), null);
    assert.equal(client.getAuthState().status, "unauthenticated");
  } finally { fixture.restore(); }
});

test("a fresh token lookup rejects storage replacement during its final durable read", async () => {
  const fixture = browser();
  try {
    const previous = JSON.stringify(legacyAccessSession({accessToken: "fixture-first", expiresAt: Date.now() + 3600000}));
    const replacement = JSON.stringify(legacyAccessSession({accessToken: "fixture-next", user: {sub: "next-user"}, expiresAt: Date.now() + 3600000}));
    fixture.storage.setItem("app.session", previous);
    const read = fixture.storage.getItem;
    let reads = 0;
    fixture.storage.getItem = key => {
      const raw = read(key);
      if (key === "app.session" && ++reads === 2) fixture.values.set(key, replacement);
      return raw;
    };
    const client = fixture.client("app", accessOptions);
    assert.equal(await client.getAccessToken(), null);
    assert.equal(fixture.storage.getItem("app.session"), replacement);
    assert.equal(await client.getAccessToken(), "fixture-next");
  } finally { fixture.restore(); }
});

test("a replacement session survives a late refresh body or failure without returning the old identity's token", async t => {
  for (const failed of [false, true]) {
    await t.test(failed ? "late failure" : "late body", async () => {
      const fixture = browser();
      try {
        fixture.storage.setItem("app.session", JSON.stringify(legacyAccessSession()));
        const body = deferred(), started = deferred();
        globalThis.fetch = async () => ({ok: true, json() { started.resolve(); return body.promise; }});
        const client = fixture.client("app", accessOptions), running = client.getAccessToken();
        await started.promise;
        const replacement = legacyAccessSession({user: {sub: "other-user"}, accessToken: "fixture-new-identity", expiresAt: Date.now() + 3600000});
        const raw = JSON.stringify(replacement);
        fixture.storage.setItem("app.session", raw);
        if (failed) body.resolve({access_token: "fixture-late", expires_in: "invalid"});
        else body.resolve({access_token: "fixture-late", expires_in: 3600});
        assert.equal(await running, null);
        assert.equal(fixture.storage.getItem("app.session"), raw);
        assert.equal(await client.getAccessToken(), "fixture-new-identity");
      } finally { fixture.restore(); }
    });
  }
});

test("new sign-in and storage replacement cancel an outstanding refresh even when the old stored record remains", async t => {
  for (const replacement of ["sign-in", "storage"]) {
    await t.test(replacement, async () => {
      const fixture = browser();
      try {
        const raw = JSON.stringify(legacyAccessSession());
        fixture.storage.setItem("app.session", raw);
        const client = fixture.client("app", accessOptions), wait = deferred();
        globalThis.fetch = () => wait.promise;
        const running = client.getAccessToken();
        if (replacement === "sign-in") await client.beginSignIn();
        else globalThis.sessionStorage = {getItem: () => null, setItem() {}, removeItem() {}};
        let parsed = false;
        wait.resolve({ok: true, json() { parsed = true; return {access_token: "fixture-late", expires_in: 3600}; }});
        assert.equal(await running, null);
        assert.equal(parsed, false);
        assert.equal(fixture.storage.getItem("app.session"), raw);
      } finally { fixture.restore(); }
    });
  }
});

test("signout during refresh body parsing and a failed storage write cannot supply a request token", async t => {
  await t.test("late body after signout", async () => {
    const fixture = browser();
    try {
      fixture.storage.setItem("app.session", JSON.stringify(legacyAccessSession()));
      const body = deferred(), started = deferred();
      globalThis.fetch = async () => ({ok: true, json() { started.resolve(); return body.promise; }});
      const client = fixture.client("app", accessOptions), running = client.getAccessToken();
      await started.promise;
      client.signOut();
      body.resolve({access_token: "fixture-late", expires_in: 3600});
      assert.equal(await running, null);
      assert.equal(fixture.storage.getItem("app.session"), null);
    } finally { fixture.restore(); }
  });
  await t.test("storage persistence failure", async () => {
    const fixture = browser();
    try {
      fixture.storage.setItem("app.session", JSON.stringify(legacyAccessSession()));
      let requests = 0;
      globalThis.fetch = async () => { requests += 1; return Response.json({access_token: "fixture-renewed", expires_in: 3600}); };
      fixture.storage.setItem = () => { throw new Error("fixture unavailable storage"); };
      fixture.storage.removeItem = () => { throw new Error("fixture unavailable removal"); };
      const client = fixture.client("app", accessOptions);
      assert.equal(await client.getAccessToken(), null);
      assert.equal(client.getStoredAuthSession(), null);
      assert.equal(await client.getAccessToken(), null);
      assert.equal(requests, 1);
    } finally { fixture.restore(); }
  });
});

test("app callback context stays in PKCE storage and restores a validated hash while preserving unrelated query parameters", async () => {
  const fixture = browser();
  try {
    fixture.navigate("/?view=cards#project/fixture-project");
    const client = fixture.client("app", {...accessOptions, pkceMaxAgeMs: 600000,
      capturePkceContext: () => ({returnHash: "#project/fixture-project", state: "override", verifier: "override", redirectUri: "override", createdAt: 0}),
      resolveCallbackHash: pending => pending.returnHash,
      cleanupParameters: ["code", "state", "error", "error_description"],
      displayUser: claims => ({sub: claims.sub, name: claims.name})
    });
    await client.beginSignIn();
    const pending = JSON.parse(fixture.storage.getItem("app.pkce"));
    assert.equal(pending.returnHash, "#project/fixture-project");
    assert.notEqual(pending.state, "override");
    assert.notEqual(pending.verifier, "override");
    assert.equal(pending.redirectUri, configuration().redirectUri);
    assert.ok(pending.createdAt > 0);
    const provider = fixture.redirects[0];
    for (const field of ["returnHash", "createdAt", "verifier", "code_verifier"]) assert.equal(provider.searchParams.has(field), false);
    fixture.navigate(`/?view=cards&code=fixture-code&state=${pending.state}#provider-fragment`);
    globalThis.fetch = async (_, options) => {
      for (const field of ["returnHash", "createdAt"]) assert.equal(options.body.has(field), false);
      return Response.json(tokenSet());
    };
    assert.equal((await client.loadAuthSession()).status, "authenticated");
    assert.equal(window.location.href, "https://app.fixture.invalid/?view=cards#project/fixture-project");
    assert.equal(fixture.storage.getItem("app.pkce"), null);
    assert.equal("idToken" in JSON.parse(fixture.storage.getItem("app.session")), false);
  } finally { fixture.restore(); }
});

test("expired or mismatched callback state cannot restore app navigation or exchange a code", async t => {
  for (const reason of ["expired", "mismatched"]) {
    await t.test(reason, async () => {
      const fixture = browser();
      try {
        const pending = {state: "fixture-state", verifier: "v".repeat(64), redirectUri: configuration().redirectUri,
          returnHash: "#private-project", createdAt: Date.now() - (reason === "expired" ? 600001 : 0)};
        const raw = JSON.stringify(pending);
        fixture.storage.setItem("app.pkce", raw);
        fixture.navigate(`/?view=cards&code=fixture-code&state=${reason === "mismatched" ? "foreign-state" : pending.state}#callback`);
        let restored = false;
        const client = fixture.client("app", {...accessOptions, pkceMaxAgeMs: 600000,
          resolveCallbackHash(value) { restored = true; return value.returnHash; }, cleanupParameters: ["code", "state"]});
        assert.equal((await client.loadAuthSession()).status, "unauthenticated");
        assert.equal(restored, false);
        assert.equal(fixture.storage.getItem("app.pkce"), raw);
        assert.equal(window.location.href, "https://app.fixture.invalid/?view=cards#callback");
      } finally { fixture.restore(); }
    });
  }
});

test("only matching current provider and exchange failures consume PKCE and restore app callback navigation", async t => {
  for (const failure of ["provider", "exchange"]) {
    await t.test(failure, async () => {
      const fixture = browser();
      try {
        fixture.storage.setItem("app.session", JSON.stringify(legacyAccessSession()));
        fixture.storage.setItem("app.pkce", JSON.stringify({state: "fixture-state", verifier: "v".repeat(64), redirectUri: configuration().redirectUri,
          createdAt: Date.now(), returnHash: "#project/fixture"}));
        fixture.navigate(failure === "provider" ? "/?view=cards&error=access_denied&error_description=Declined&state=fixture-state" : "/?view=cards&code=fixture-code&state=fixture-state");
        globalThis.fetch = async () => { throw new Error("fixture exchange failure"); };
        const client = fixture.client("app", {...accessOptions, pkceMaxAgeMs: 600000,
          resolveCallbackHash: pending => pending.returnHash, cleanupParameters: ["code", "state", "error", "error_description"]});
        const result = await client.loadAuthSession();
        assert.equal(result.status, "unauthenticated");
        assert.ok(result.error);
        assert.equal(fixture.storage.getItem("app.pkce"), null);
        assert.equal(fixture.storage.getItem("app.session"), null);
        assert.equal(window.location.href, "https://app.fixture.invalid/?view=cards#project/fixture");
      } finally { fixture.restore(); }
    });
  }
});
