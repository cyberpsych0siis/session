/*!
 * express-session
 * Copyright(c) 2010 Sencha Inc.
 * Copyright(c) 2011 TJ Holowaychuk
 * Copyright(c) 2014-2015 Douglas Christopher Wilson
 * MIT Licensed
 */

"use strict";

/**
 * Module dependencies.
 * @private
 */

// var Buffer = require("safe-buffer").Buffer;
// var cookie = require("cookie");
var crypto = require("crypto");
var debug = require("debug")("express-session");
var deprecate = require("depd")("express-session");
var onHeaders = require("on-headers");
var parseUrl = require("parseurl");
// var signature = require("cookie-signature");
var uid = require("uid-safe").sync;

var Cookie = require("./session/cookie");
var MemoryStore = require("./session/memory");
var Session = require("./session/session");
var Store = require("./session/store");

// environment

var env = process.env.NODE_ENV;

/**
 * Expose the middleware.
 */

exports = module.exports = session;

/**
 * Expose constructors.
 */

exports.Store = Store;
exports.Cookie = Cookie;
exports.Session = Session;
exports.MemoryStore = MemoryStore;

/**
 * Warning message for `MemoryStore` usage in production.
 * @private
 */

var warning =
  "Warning: connect.session() MemoryStore is not\n" +
  "designed for a production environment, as it will leak\n" +
  "memory, and will not scale past a single process.";

/**
 * Node.js 0.8+ async implementation.
 * @private
 */

/* istanbul ignore next */
var defer =
  typeof setImmediate === "function"
    ? setImmediate
    : function (fn) {
        process.nextTick(fn.bind.apply(fn, arguments));
      };

/**
 * Setup session store with the given `options`.
 *
 * @param {Object} [options]
 * @param {Object} [options.cookie] Options for cookie
 * @param {Function} [options.genid]
 * @param {String} [options.name=connect.sid] Session ID cookie name
 * @param {Boolean} [options.proxy]
 * @param {Boolean} [options.resave] Resave unmodified sessions back to the store
 * @param {Boolean} [options.rolling] Enable/disable rolling session expiration
 * @param {Boolean} [options.saveUninitialized] Save uninitialized sessions to the store
 * @param {String|Array} [options.secret] Secret for signing session ID
 * @param {Object} [options.store=MemoryStore] Session store
 * @param {String} [options.unset]
 * @return {Function} middleware
 * @public
 */

function session(options) {
  var opts = options || {};

  // get the cookie options
  // var cookieOptions = opts.cookie || {}

  // get the session id generate function
  var generateId = opts.genid || generateSessionId;

  // get the session cookie name
  // var name = opts.name || opts.key || "connect.sid";

  // get the session store
  var store = opts.store || new MemoryStore();

  // get the trust proxy setting
  var trustProxy = opts.proxy;

  // get the resave session option
  var resaveSession = opts.resave;

  // get the rolling session option
  var rollingSessions = Boolean(opts.rolling);

  // get the save uninitialized session option
  var saveUninitializedSession = opts.saveUninitialized;

  // get the cookie signing secret
  var secret = opts.secret;

  if (typeof generateId !== "function") {
    throw new TypeError("genid option must be a function");
  }

  if (resaveSession === undefined) {
    deprecate("undefined resave option; provide resave option");
    resaveSession = true;
  }

  if (saveUninitializedSession === undefined) {
    deprecate(
      "undefined saveUninitialized option; provide saveUninitialized option"
    );
    saveUninitializedSession = true;
  }

  if (opts.unset && opts.unset !== "destroy" && opts.unset !== "keep") {
    throw new TypeError('unset option must be "destroy" or "keep"');
  }

  // TODO: switch to "destroy" on next major
  var unsetDestroy = opts.unset === "destroy";

  if (Array.isArray(secret) && secret.length === 0) {
    throw new TypeError("secret option array must contain one or more strings");
  }

  if (secret && !Array.isArray(secret)) {
    secret = [secret];
  }

  if (!secret) {
    deprecate("req.secret; provide secret option");
  }

  // notify user that this store is not
  // meant for a production environment
  /* istanbul ignore next: not tested */
  if (env === "production" && store instanceof MemoryStore) {
    console.warn(warning);
  }

  // generates the new session
  store.generate = function (req) {
    req.sessionID = generateId(req);
    req.session = new Session(req);
    // req.session.cookie = new Cookie(cookieOptions);

    // if (cookieOptions.secure === 'auto') {
    // req.session.cookie.secure = issecure(req, trustProxy);
    // }
  };

  var storeImplementsTouch = typeof store.touch === "function";

  // register event listeners for the store to track readiness
  var storeReady = true;
  store.on("disconnect", function ondisconnect() {
    storeReady = false;
  });
  store.on("connect", function onconnect() {
    storeReady = true;
  });

  return function session(req, res, next) {
    // self-awareness
    if (req.session) {
      next();
      return;
    }

    // Handle connection as if there is no session if
    // the store has temporarily disconnected etc
    if (!storeReady) {
      debug("store is disconnected");
      next();
      return;
    }

    // pathname mismatch
    // var originalPath = parseUrl.original(req).pathname || "/";
    // if (originalPath.indexOf(cookieOptions.path || "/") !== 0) return next();

    // ensure a secret is available or bail
    if (!secret && !req.secret) {
      next(new Error("secret option required for sessions"));
      return;
    }

    // backwards compatibility for signed cookies
    // req.secret is passed from the cookie parser middleware
    var secrets = secret || [req.secret];

    var originalHash;
    var originalId;
    var savedHash;
    var touched = false;

    // expose store
    req.sessionStore = store;

    // get the session ID from the cookie
    // var cookieId = req.sessionID = getcookie(req, name, secrets);
    var cookieId = (req.sessionID = req.headers["x-session"]);
    var exCookieId = (req.sessionID = req.headers["x-session"]);

    // generate the session
    function generate() {
      store.generate(req);
      originalId = req.sessionID;
      originalHash = hash(req.session);
      wrapmethods(req.session);
    }

    // inflate the session
    function inflate(req, sess) {
      store.createSession(req, sess);
      originalId = req.sessionID;
      originalHash = hash(sess);

      if (!resaveSession) {
        savedHash = originalHash;
      }

      wrapmethods(req.session);
    }

    function rewrapmethods(sess, callback) {
      return function () {
        if (req.session !== sess) {
          wrapmethods(req.session);
        }

        callback.apply(this, arguments);
      };
    }

    // wrap session methods
    function wrapmethods(sess) {
      var _reload = sess.reload;
      var _save = sess.save;

      function reload(callback) {
        debug("reloading %s", this.id);
        _reload.call(this, rewrapmethods(this, callback));
      }

      function save() {
        debug("saving %s", this.id);
        savedHash = hash(this);
        _save.apply(this, arguments);
      }

      Object.defineProperty(sess, "reload", {
        configurable: true,
        enumerable: false,
        value: reload,
        writable: true,
      });

      Object.defineProperty(sess, "save", {
        configurable: true,
        enumerable: false,
        value: save,
        writable: true,
      });
    }

    // check if session has been modified
    function isModified(sess) {
      return originalId !== sess.id || originalHash !== hash(sess);
    }

    // check if session has been saved
    function isSaved(sess) {
      return originalId === sess.id && savedHash === hash(sess);
    }

    // determine if session should be destroyed
    function shouldDestroy(req) {
      return req.sessionID && unsetDestroy && req.session == null;
    }

    // determine if session should be saved to store
    function shouldSave(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== "string") {
        debug(
          "session ignored because of bogus req.sessionID %o",
          req.sessionID
        );
        return false;
      }

      /*return !saveUninitializedSession && exCookieId !== req.sessionID
        ? isModified(req.session)
        : !isSaved(req.session);*/
      return true;
    }

    // determine if session should be touched
    function shouldTouch(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== "string") {
        debug(
          "session ignored because of bogus req.sessionID %o",
          req.sessionID
        );
        return false;
      }

      // return exCookieId === req.sessionID && !shouldSave(req);
      return true;
    }

    // generate a session if the browser doesn't send a sessionID
    if (!req.sessionID) {
      debug("no SID sent, generating session");
      generate();
      next();
      return;
    }

    // generate the session object
    debug("fetching %s", req.sessionID);
    store.get(req.sessionID, function (err, sess) {
      // error handling
      if (err && err.code !== "ENOENT") {
        debug("error %j", err);
        next(err);
        return;
      }

      try {
        if (err || !sess) {
          debug("no session found");
          generate();
        } else {
          debug("session found");
          inflate(req, sess);
        }
      } catch (e) {
        next(e);
        return;
      }

      next();
    });
  };
}

/**
 * Generate a session ID for a new session.
 *
 * @return {String}
 * @private
 */

function generateSessionId(sess) {
  return uid(24);
}

/**
 * Hash the given `sess` object omitting changes to `.cookie`.
 *
 * @param {Object} sess
 * @return {String}
 * @private
 */

function hash(sess) {
  // serialize
  var str = JSON.stringify(sess, function (key, val) {
    return val;
  });

  // hash
  return crypto.createHash("sha1").update(str, "utf8").digest("hex");
}
