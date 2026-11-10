/* Perathos Gate approver pages: vanilla WebAuthn (navigator.credentials). */
(function () {
  "use strict";

  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function $(id) { return document.getElementById(id); }
  function showError(msg) { var e = $("error"); e.textContent = msg; e.hidden = false; }
  function clearError() { var e = $("error"); e.hidden = true; e.textContent = ""; }

  async function postJSON(url, body) {
    var r = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body)
    });
    var data = {};
    try { data = await r.json(); } catch (e) { /* empty */ }
    if (!r.ok) throw new Error((data && data.detail) || ("HTTP " + r.status));
    return data;
  }

  function friendly(err) {
    if (err && err.name === "NotAllowedError") return "The passkey request was cancelled or timed out.";
    if (err && err.name === "InvalidStateError") return "This passkey is already registered.";
    return (err && err.message) || String(err);
  }

  if (!window.PublicKeyCredential) {
    document.addEventListener("DOMContentLoaded", function () {
      if ($("error")) showError("This browser does not support passkeys. Open the link in an up-to-date browser over HTTPS.");
    });
  }

  function assertionJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || null,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        authenticatorData: bufToB64url(r.authenticatorData),
        clientDataJSON: bufToB64url(r.clientDataJSON),
        signature: bufToB64url(r.signature),
        userHandle: r.userHandle ? bufToB64url(r.userHandle) : null
      }
    };
  }

  /* ------------------------------------------------------ push notifications */
  /* The #push block exists only when the server has a VAPID key. pushToken arrives with a
     successful passkey ceremony and is what lets this browser subscribe for that approver. */
  var pushToken = null;
  var NO_PUSH_HERE = "This browser cannot show notifications for this page. On iPhone or iPad, add this " +
    "site to the Home Screen (Share, then Add to Home Screen) and open it from there.";

  function pushSupported() {
    return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  }

  async function currentSubscription() {
    var reg = await navigator.serviceWorker.getRegistration("/");
    return reg ? reg.pushManager.getSubscription() : null;
  }

  async function refreshPush() {
    var box = $("push");
    if (!box) return;
    if (!pushSupported()) {
      if (pushToken) { $("push-note").textContent = NO_PUSH_HERE; box.hidden = false; }
      return;
    }
    var sub = null;
    try {
      sub = await currentSubscription();
      // A subscription made for another server key can never be delivered to: drop it.
      var key = sub && sub.options && sub.options.applicationServerKey;
      if (key && bufToB64url(key) !== box.dataset.vapidKey) { await sub.unsubscribe(); sub = null; }
    } catch (e) { sub = null; }
    $("push-on").hidden = !(pushToken && !sub);
    $("push-off").hidden = !sub;
    if (sub) $("push-note").textContent = "Notifications are on for this device.";
    box.hidden = $("push-on").hidden && $("push-off").hidden;
  }

  function offerPush(token) {
    if (!token) return;
    pushToken = token;
    refreshPush();
  }

  function initPush() {
    var box = $("push");
    if (!box) return;
    var on = $("push-on"), off = $("push-off");
    on.addEventListener("click", async function () {
      clearError();
      on.disabled = true;
      try {
        // Asked for directly in the click handler: browsers require a user gesture.
        if ((await Notification.requestPermission()) !== "granted") {
          throw new Error("Notifications are blocked for this site. Allow them in the browser settings and try again.");
        }
        await navigator.serviceWorker.register("/sw.js", { scope: "/" });
        var reg = await navigator.serviceWorker.ready;
        var sub = await reg.pushManager.subscribe({
          userVisibleOnly: true, applicationServerKey: b64urlToBuf(box.dataset.vapidKey)
        });
        try {
          await postJSON("/push/subscribe", { token: pushToken, subscription: sub.toJSON() });
        } catch (err) {
          await sub.unsubscribe();
          throw err;
        }
      } catch (err) {
        showError((err && err.message) || String(err));
      }
      on.disabled = false;
      refreshPush();
    });
    off.addEventListener("click", async function () {
      clearError();
      off.disabled = true;
      try {
        var sub = await currentSubscription();
        if (sub) {
          var endpoint = sub.endpoint;
          await sub.unsubscribe();
          await postJSON("/push/unsubscribe", { endpoint: endpoint });
        }
        $("push-note").textContent = "Notifications are off for this device.";
      } catch (err) {
        showError((err && err.message) || String(err));
      }
      off.disabled = false;
      refreshPush();
    });
    refreshPush();
  }

  /* -------------------------------------------------------------- home page */
  function initHome() {
    var btn = $("push-signin");
    if (!pushSupported()) {
      btn.hidden = true;
      // iPadOS reports itself as a Mac; a Mac with a touch screen is an iPad.
      var ios = /iPhone|iPad|iPod/.test(navigator.userAgent) ||
        (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
      if (ios && $("ios-steps")) {
        $("home-intro").hidden = true;
        $("ios-steps").hidden = false;
      } else {
        $("push-note").textContent = NO_PUSH_HERE;
        $("push").hidden = false;
      }
      return;
    }
    btn.addEventListener("click", async function () {
      clearError();
      btn.disabled = true;
      try {
        var o = await postJSON("/push/options", {});
        var cred = await navigator.credentials.get({ publicKey: {
          challenge: b64urlToBuf(o.challenge), rpId: o.rpId, timeout: o.timeout,
          userVerification: o.userVerification, allowCredentials: []
        } });
        var res = await postJSON("/push/verify", { credential: assertionJSON(cred) });
        var out = $("result");
        out.textContent = "Confirmed: " + res.approver + ".";
        out.hidden = false;
        btn.hidden = true;
        offerPush(res.push_token);
      } catch (err) {
        showError(friendly(err));
        btn.disabled = false;
      }
    });
  }

  /* ------------------------------------------------------------ approve page */
  function initApprove() {
    var body = document.body, id = body.dataset.id;
    var t = new URLSearchParams(window.location.search).get("t") || "";
    var expires = Date.parse(body.dataset.expires);
    var left = $("time-left");

    function tick() {
      if (!left || isNaN(expires)) return;
      var s = Math.max(0, Math.floor((expires - Date.now()) / 1000));
      left.textContent = s > 0 ? Math.floor(s / 60) + " min " + (s % 60) + " s" : "expired";
      if (s === 0 && $("buttons")) { $("buttons").hidden = true; }
    }
    if (body.dataset.status === "pending") { tick(); setInterval(tick, 1000); }
    else if (left) { left.textContent = body.dataset.status; }

    var buttons = document.querySelectorAll("[data-decision]");
    buttons.forEach(function (btn) {
      btn.addEventListener("click", async function () {
        var decision = btn.dataset.decision;
        clearError();
        buttons.forEach(function (b) { b.disabled = true; });
        try {
          var opts = await postJSON("/a/" + id + "/options", { t: t, decision: decision });
          var publicKey = {
            challenge: b64urlToBuf(opts.challenge),
            rpId: opts.rpId,
            timeout: opts.timeout,
            userVerification: opts.userVerification,
            allowCredentials: (opts.allowCredentials || []).map(function (c) {
              return { type: c.type, id: b64urlToBuf(c.id), transports: c.transports };
            })
          };
          var cred = await navigator.credentials.get({ publicKey: publicKey });
          var res = await postJSON("/a/" + id + "/verify",
            { t: t, decision: decision, credential: assertionJSON(cred), via: body.dataset.via });
          var out = $("result");
          out.className = "result " + res.status;
          out.textContent = (res.status === "approved" ? "Approved" : "Denied") + " by " + res.approver +
            ". Receipt " + res.receipt_hash;
          out.hidden = false;
          if ($("buttons")) $("buttons").hidden = true;
          offerPush(res.push_token);
        } catch (err) {
          showError(friendly(err));
          buttons.forEach(function (b) { b.disabled = false; });
        }
      });
    });
  }

  /* ------------------------------------------------------------- enrol page */
  function initEnroll() {
    var token = window.location.pathname.split("/").filter(Boolean)[1];
    var btn = $("enroll-btn");
    btn.addEventListener("click", async function () {
      clearError();
      btn.disabled = true;
      try {
        var o = await postJSON("/enroll/" + token + "/options", {});
        var publicKey = {
          challenge: b64urlToBuf(o.challenge),
          rp: o.rp,
          user: { id: b64urlToBuf(o.user.id), name: o.user.name, displayName: o.user.displayName },
          pubKeyCredParams: o.pubKeyCredParams,
          timeout: o.timeout,
          attestation: o.attestation,
          authenticatorSelection: o.authenticatorSelection,
          excludeCredentials: (o.excludeCredentials || []).map(function (c) {
            return { type: c.type, id: b64urlToBuf(c.id), transports: c.transports };
          })
        };
        var cred = await navigator.credentials.create({ publicKey: publicKey });
        var r = cred.response;
        var credential = {
          id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
          authenticatorAttachment: cred.authenticatorAttachment || null,
          clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
          response: {
            clientDataJSON: bufToB64url(r.clientDataJSON),
            attestationObject: bufToB64url(r.attestationObject),
            transports: r.getTransports ? r.getTransports() : []
          }
        };
        var res = await postJSON("/enroll/" + token + "/verify", { credential: credential });
        var out = $("result");
        out.textContent = "Passkey created for " + res.approver + ". You can close this page; approval requests will arrive by link.";
        out.hidden = false;
        btn.hidden = true;
        offerPush(res.push_token);
      } catch (err) {
        showError(friendly(err));
        btn.disabled = false;
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var p = document.body.dataset.page;
    if (p === "approve") initApprove();
    else if (p === "enroll") initEnroll();
    else if (p === "home") initHome();
    initPush();
  });
})();
