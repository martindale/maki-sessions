// session handling
var redis = require('redis');
var connectRedis = require('connect-redis');
var session = require('express-session');
var cookieParser = require('cookie-parser');

var flash = require('connect-flash');
var async = require('async');

function Sessions( config ) {
  var self = this;
  if (!config) config = {};
  self.config = config;

  self.extends = {
    services: {
      http: {
        middleware: function(req, res, next) {
          var stack = [];
          if (!req.session.hash) {
            stack.push(function(done) {
              req.session.hash = require('crypto').createHash('sha256').update( req.session.id ).digest('hex');
              req.session.save( done );
            });
          }
          async.series( stack , function(err, results) {
            res.locals.session = req.session;
            return next();
          });
        },
        setup: function( maki ) {
          // TODO: p2p datastore
          maki.redis = redis.createClient( maki.config.redis.port , maki.config.redis.host );
          var RedisStore = connectRedis( session );
          maki.app.use( cookieParser( maki.config.sessions.secret ) )
          
          maki.app.use( session({
            name: maki.config.service.namespace + '.id',
            store: new RedisStore({ client: maki.redis }),
            secret: maki.config.sessions.secret,
            cookie: {
              //secure: true,
              maxAge: 30 * 24 * 60 * 60 * 1000
            },
            rolling: true
          }));

          maki.app.use( flash() );
          maki.app.use(function(req, res, next) {
            req.flash = req.flash;
            res.format({
              html: function() {
                res.locals.messages = {
                  info: req.flash('info'),
                  warning: req.flash('warning'),
                  error: req.flash('error'),
                  success: req.flash('success'),
                };
              }
            });
            next();
          });

          maki.app.get('/sessions', function(req, res, next) {
            res.render('login');
          });
          /*maki.app.post('/sessions', maki.passport.authenticate('local') , function(req, res, next) {
            console.log('created session.', req.user._id );
            req.flash('success', 'logged in');
            return res.redirect('/');
          });*/
          maki.app.delete('/sessions/:sessionID', function(req, res, next) {
            req.logout();
            req.flash('success', 'logged out');
            res.redirect('/');
          });
          
        }
      }
    }
  };
  
  return self;
}

module.exports = Sessions;
