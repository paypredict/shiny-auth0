var express = require('express');
var passport = require('passport');
var httpProxy = require('http-proxy');
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn();
var router = express.Router();

var env = process.env;

// This adds support for the current way to sso
var authenticateWithDefaultPrompt = passport.authenticate('auth0', {});
var authenticateWithPromptNone = passport.authenticate('auth0', {
  prompt: 'none'
});

function renderHome(res) {
    res.render('home', {
        pp: {
            shinyUrl: "/reports/",
            javaUrl: env.PP_JAVA_URL || 'http://localhost:8080/'
        }
    });
}

/* GET home page. */
router.get('/', function(req, res, next) {
    if (req.user) {
        renderHome(res)
    } else {
        res.render('ROOT');
    }
});

router.get('/home/', function(req, res, next) {
    if (req.user) {
        renderHome(res);
    } else {
        req.session.returnTo = '/home/';
        res.redirect("/login")
    }
});

router.get('/login',
  function (req, res, next) {
    if (env.CHECK_SESSION === 'true' && req.query.sso !== 'false') {
      return authenticateWithPromptNone(req, res, next);
    }
    return authenticateWithDefaultPrompt(req, res, next);
  },
  function (req, res) {
    res.redirect('/home/');
  });

router.get('/logout', function(req, res){
  var logoutUrl = env.LOGOUT_URL;

  if (env.LOGOUT_AUTH0 === 'true') {
    logoutUrl = 'https://' + env.AUTH0_DOMAIN + '/v2/logout?returnTo=' 
      + env.LOGOUT_URL + '&client_id=' + env.AUTH0_CLIENT_ID
      + (env.LOGOUT_FEDERATED === 'true'? '&federated' : '');
  }
  
  req.logout();
  res.redirect(logoutUrl);
});

router.get('/callback',
  function (req, res, next) {
    passport.authenticate('auth0', function (err, user, info) {
      if (err) {
        next(err);
      }

      if (info === 'login_required') {
        return res.redirect('/login?sso=false');
      }

        if (info === 'unauthorized') {
            return res.render('authPending');
        }

      if (user) {
        return req.login(user, function (err) {
          if (err) {
            next(err);
          }
          res.redirect(req.session.returnTo || '/home/');
        });
      }

      next(new Error(info));
    })(req, res, next);
  });

module.exports = router;
