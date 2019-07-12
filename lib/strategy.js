var passport = require('passport-strategy');
var url = require('url');
var uid = require('uid2');
var crypto = require('crypto');
var base64url = require('base64url');
var util = require('util');
var utils = require('./utils');
var OAuth2 = require('oauth').OAuth2;
var NullStateStore = require('./state/null');
var SessionStateStore = require('./state/session');
var PKCESessionStateStore = require('./state/pkcesession');
var AuthorizationError = require('./errors/authorizationerror');
var TokenError = require('./errors/tokenerror');
var InternalOAuthError = require('./errors/internaloautherror');
function OAuth2Strategy(options, verify) {
    if (typeof options == 'function') {
        verify = options;
        options = undefined;
    }
    options = options || {};
    if (!verify) {
        throw new TypeError('OAuth2Strategy requires a verify callback');
    }
    if (!options.authorizationURL) {
        throw new TypeError('OAuth2Strategy requires a authorizationURL option');
    }
    if (!options.tokenURL) { 
        throw new TypeError('OAuth2Strategy requires a tokenURL option'); 
    }
    if (!options.clientID) { 
        throw new TypeError('OAuth2Strategy requires a clientID option'); 
    }
    passport.Strategy.call(this);
    this.name = 'oauth2';
    this._verify = verify;
    this._oauth2 = new OAuth2(options.clientID, options.clientSecret, '', options.authorizationURL, options.tokenURL, options.customHeaders);
    this._callbackURL = options.callbackURL;
    this._scope = options.scope;
    this._scopeSeparator = options.scopeSeparator || ' ';
    this._pkceMethod = (options.pkce === true) ? 'S256' : options.pkce;
    this._key = options.sessionKey || ('oauth2:' + url.parse(options.authorizationURL).hostname);
    if (options.store) {
        this._stateStore = options.store;
    } else {
        if (options.state) {
            this._stateStore = options.pkce ? new PKCESessionStateStore({
                key: this._key
            }) : new SessionStateStore({
                key: this._key
            });
        } else {
            if (options.pkce) { 
                throw new TypeError('OAuth2Strategy requires `state: true` option when PKCE is enabled'); 
            }
            this._stateStore = new NullStateStore();
        }
    }
    this._trustProxy = options.proxy;
    this._passReqToCallback = options.passReqToCallback;
    this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}
util.inherits(OAuth2Strategy, passport.Strategy);
OAuth2Strategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var self = this;
    if (req.query && req.query.error) {
      if (req.query.error == 'access_denied') {
        return this.fail({ message: req.query.error_description });
      } else {
        return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
      }
    }
    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
      }
    }
    var meta = {
      authorizationURL: this._oauth2._authorizeUrl,
      tokenURL: this._oauth2._accessTokenUrl,
      clientID: this._oauth2._clientId
    }
    if (req.query && req.query.code) {
      function loaded(err, ok, state) {
        if (err) { return self.error(err); }
        if (!ok) {
          return self.fail(state, 403);
        }
        var code = req.query.code;
        var params = self.tokenParams(options);
        params.grant_type = 'authorization_code';
        if (callbackURL) { params.redirect_uri = callbackURL; }
        if (typeof ok == 'string') {
          params.code_verifier = ok;
        }
        self._oauth2.getOAuthAccessToken(code, params,
          function(err, accessToken, refreshToken, params) {
            if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
            self._loadUserProfile(accessToken, function(err, profile) {
              if (err) { return self.error(err); }
              function verified(err, user, info) {
                if (err) { return self.error(err); }
                if (!user) { return self.fail(info); }
                info = info || {};
                if (state) { info.state = state; }
                self.success(user, info);
              }
              try {
                if (self._passReqToCallback) {
                  var arity = self._verify.length;
                  if (arity == 6) {
                    self._verify(req, accessToken, refreshToken, params, profile, verified);
                  } else {
                    self._verify(req, accessToken, refreshToken, profile, verified);
                  }
                } else {
                  var arity = self._verify.length;
                  if (arity == 5) {
                    self._verify(accessToken, refreshToken, params, profile, verified);
                  } else {
                    self._verify(accessToken, refreshToken, profile, verified);
                  }
                }
              } catch (ex) {
                return self.error(ex);
              }
            });
          }
        );
      }
      var state = req.query.state;
      try {
        var arity = this._stateStore.verify.length;
        if (arity == 4) {
          this._stateStore.verify(req, state, meta, loaded);
        } else {
          this._stateStore.verify(req, state, loaded);
        }
      } catch (ex) {
        return this.error(ex);
      }
    } else {
      var params = this.authorizationParams(options);
      params.response_type = 'code';
      if (callbackURL) { params.redirect_uri = callbackURL; }
      var scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
        params.scope = scope;
      }
      var verifier, challenge;
      if (this._pkceMethod) {
        verifier = base64url(crypto.pseudoRandomBytes(32))
        switch (this._pkceMethod) {
        case 'plain':
          challenge = verifier;
          break;
        case 'S256':
          challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
          break;
        default:
          return this.error(new Error('Unsupported code verifier transformation method: ' + this._pkceMethod));
        }
        params.code_challenge = challenge;
        params.code_challenge_method = this._pkceMethod;
      }
      var state = options.state;
      if (state) {
        params.state = state;
        var parsed = url.parse(this._oauth2._authorizeUrl, true);
        utils.merge(parsed.query, params);
        parsed.query['client_id'] = this._oauth2._clientId;
        delete parsed.search;
        var location = url.format(parsed);
        this.redirect(location);
      } else {
        function stored(err, state) {
          if (err) { return self.error(err); }
          if (state) { params.state = state; }
          var parsed = url.parse(self._oauth2._authorizeUrl, true);
          utils.merge(parsed.query, params);
          parsed.query['client_id'] = self._oauth2._clientId;
          delete parsed.search;
          var location = url.format(parsed);
          self.redirect(location);
        }
        try {
          var arity = this._stateStore.store.length;
          if (arity == 5) {
            this._stateStore.store(req, verifier, undefined, meta, stored);
          } else if (arity == 3) {
            this._stateStore.store(req, meta, stored);
          } else {
            this._stateStore.store(req, stored);
          }
        } catch (ex) {
          return this.error(ex);
        }
      }
    }
};
OAuth2Strategy.prototype.userProfile = function(accessToken, done) {
    return done(null, {});
};
OAuth2Strategy.prototype.authorizationParams = function(options) {
    return {};
};
OAuth2Strategy.prototype.tokenParams = function(options) {
    return {};
};
OAuth2Strategy.prototype.parseErrorResponse = function(body, status) {
    var json = JSON.parse(body);
    if (json.error) {
      return new TokenError(json.error_description, json.error, json.error_uri);
    }
    return null;
};
OAuth2Strategy.prototype._loadUserProfile = function(accessToken, done) {
    var self = this;
    function loadIt() {
      return self.userProfile(accessToken, done);
    }
    function skipIt() {
      return done(null);
    }
    if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
      this._skipUserProfile(accessToken, function(err, skip) {
        if (err) { return done(err); }
        if (!skip) { return loadIt(); }
        return skipIt();
      });
    } else {
      var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
      if (!skip) { return loadIt(); }
      return skipIt();
    }
};
OAuth2Strategy.prototype._createOAuthError = function(message, err) {
    var e;
    if (err.statusCode && err.data) {
      try {
        e = this.parseErrorResponse(err.data, err.statusCode);
      } catch (_) {}
    }
    if (!e) { e = new InternalOAuthError(message, err); }
    return e;
};
module.exports = OAuth2Strategy;