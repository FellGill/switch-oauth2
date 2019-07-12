var uid = require('uid2');
function PKCESessionStore(options) {
    if (!options.key) { 
        throw new TypeError('Session-based state store requires a session key'); 
    }
    this._key = options.key;
}
PKCESessionStore.prototype.store = function(req, verifier, state, meta, callback) {
    if (!req.session) { 
        return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); 
    }
    var key = this._key;
    var state = {
      handle: uid(24),
      code_verifier: verifier
    };
    if (!req.session[key]) { req.session[key] = {}; }
    req.session[key].state = state;
    callback(null, state.handle);
};
PKCESessionStore.prototype.verify = function(req, providedState, callback) {
    if (!req.session) { 
        return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); 
    }
    var key = this._key;
    if (!req.session[key]) {
        return callback(null, false, { 
          message: 'Unable to verify authorization request state.' 
        });
    }
    var state = req.session[key].state;
    if (!state) {
      return callback(null, false, { 
          message: 'Unable to verify authorization request state.' 
        });
    }
    delete req.session[key].state;
    if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
    }
    if (state.handle !== providedState) {
        return callback(null, false, { 
          message: 'Invalid authorization request state.' 
        });
    }
    return callback(null, state.code_verifier);
};
module.exports = PKCESessionStore;