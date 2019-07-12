function InternalOAuthError(message, err) {
    Error.call(this);
    Error.captureStackTrace(this, this.constructor);
    this.name = this.constructor.name;
    this.message = message;
    this.oauthError = err;
}
InternalOAuthError.prototype.__proto__ = Error.prototype;
InternalOAuthError.prototype.toString = function() {
    var m = this.name;
    if (this.message) { m += ': ' + this.message; }
    if (this.oauthError) {
      if (this.oauthError instanceof Error) {
        m = this.oauthError.toString();
      } else if (this.oauthError.statusCode && this.oauthError.data) {
        m += ' (status: ' + this.oauthError.statusCode + ' data: ' + this.oauthError.data + ')';
      }
    }
    return m;
};
module.exports = InternalOAuthError;