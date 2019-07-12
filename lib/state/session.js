var uid = require('uid2');
function SessionStore(options) {
    if (!options.key) { throw new TypeError('Session-based state store requires a session key'); }
    this._key = options.key;
}
SessionStore.prototype.store = function(req, callback) {
    if (!req.session) { 
        return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); 
    }
    var key = this._key;
    var state = uid(24);
    if (!req.session[key]) { req.session[key] = {}; }
    req.session[key].state = state;
    callback(null, state);
};
SessionStore.prototype.verify = function(req, providedState, callback) {
    if (!req.session) { 
        return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); 
    }
    var key = this._key;
    if (!req.session[key]) {
      return callback(null, false, { message: 'Unable to verify authorization request state.' });
    }
    var state = req.session[key].state;
    if (!state) {
      return callback(null, false, { message: 'Unable to verify authorization request state.' });
    }
    delete req.session[key].state;
    if (Object.keys(req.session[key]).length === 0) {
      delete req.session[key];
    }
    if (state !== providedState) {
      return callback(null, false, { message: 'Invalid authorization request state.' });
    }
    return callback(null, true);
};
module.exports = SessionStore;