var express = require('express');
var passport = require('passport');
var httpProxy = require('http-proxy');
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn();
var fs = require('file-system');
var crypto = require('crypto');
var router = express.Router();

var proxy = httpProxy.createProxyServer({
  target: {
      host: process.env.SHINY_HOST,
      port: process.env.SHINY_PORT
    }
});

proxy.on('error', function(e) {
  console.log('Error connecting');
  console.log(e);
});

var setIfExists = function(proxyReq, header, value){
  if(value){
    proxyReq.setHeader(header, value);
  }
};

/*
LOGOUT_URL=http://sagis.paypredict.net/callback
LOGOUT_AUTH0=true
*/

let saveUserJson = function(proxyReq, req, res, options) {
  let pp_sid = null;
  let sid = req.cookies["connect.sid"];
  if (sid) {
    pp_sid = crypto
        .createHash("sha256")
        .update(sid)
        .digest("hex");

    let fileName = "req.user." + pp_sid + ".json";
    let tempDir = "/tmp/pp-auth0";
    let filePath = tempDir + "/" + fileName;
    if (!fs.fs.existsSync(filePath)) {
      fs.mkdirSync(tempDir);
      fs.writeFileSync(filePath, JSON.stringify(req.user._json, null, 4))
    }
  }
  return pp_sid;
};

proxy.on('proxyReq', function(proxyReq, req, res, options) {
  setIfExists(proxyReq, 'x-auth0-nickname', req.user._json.nickname);
  setIfExists(proxyReq, 'x-auth0-user_id', req.user._json.user_id);
  setIfExists(proxyReq, 'x-auth0-email', req.user._json.email);
  setIfExists(proxyReq, 'x-auth0-name', req.user._json.name);
  setIfExists(proxyReq, 'x-auth0-picture', req.user._json.picture);
  setIfExists(proxyReq, 'x-auth0-locale', req.user._json.locale);
  req.session.pp_sid = saveUserJson(proxyReq, req, res, options);
});

proxy.on('proxyRes', function(proxyRes, req, res, options) {
  let pp_sid = req.session.pp_sid;
  if (pp_sid)
      proxyRes.headers['set-cookie'] = "pp.sid=" + pp_sid + "; Path=/"
});

/* Proxy all requests */
router.all(/.*/, ensureLoggedIn, function(req, res, next) {
  proxy.web(req, res);
});

module.exports = router;
