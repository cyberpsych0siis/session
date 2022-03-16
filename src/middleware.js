import MemoryStore from "./MemoryStore.js";

/**
 * @deprecated
 * DO NOT USE!!!!!!!!!
 */
export default class Session {
  constructor(opts = {}) {
    if (Boolean(opts.genid)) Object.defineProperty(this, "getId", opts.genid);

    this.store = opts.store ?? new MemoryStore();

    // get the trust proxy setting
    this.trustProxy = opts.proxy;

    // get the resave session option
    this.resaveSession = opts.resave ?? true;

    // get the rolling session option
    this.rollingSessions = Boolean(opts.rolling);

    // get the save uninitialized session option
    this.saveUninitializedSession = opts.saveUninitialized ?? true;

    // get the cookie signing secret
    this.secret = opts.secret;

    if (opts.unset && opts.unset !== "destroy" && opts.unset !== "keep") {
      throw new TypeError('unset option must be "destroy" or "keep"');
    }

    this.unsetDestroy = opts.unset === "destroy";

    if (Array.isArray(this.secret) && this.secret.length === 0) {
      throw new TypeError(
        "secret option array must contain one or more strings"
      );
    }

    if (this.secret && !Array.isArray(this.secret)) {
      this.secret = [this.secret];
    }

    const storeImplementsTouch = typeof this.store.touch === "function";

    let storeReady = true;
    this.store.on("disconnect", () => {
      storeReady = false;
    });

    this.store.on("connect", () {
      storeReady = true;
    });
  }

  applyFunctions() {
    this.store.generate = (req) => {
      req.sessionID = this.getSessionIdFromHeader("x-session");
      req.session = new Session(req);
    };
  }
}
