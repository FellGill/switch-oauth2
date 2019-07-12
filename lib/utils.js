exports.merge = require('utils-merge');
exports.originalURL = function(req, options) {
    options = options || {};
    var app = req.app;
    if (app && app.get && app.get('trust proxy')) {
        options.proxy = true;
    }
    var trustProxy = options.proxy;
    var proto = (req.headers['x-forwarded-proto'] || '').toLowerCase();
    var tls = req.connection.encrypted || (trustProxy && 'https' == proto.split(/\s*,\s*/)[0]);
    var host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host;
    var protocol = tls ? 'https' : 'http';
    var path = req.url || '';
    return protocol + '://' + host + path; 
}