var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var passportLocalMongoose = require('passport-local-mongoose');

// session handling
var redis = require('redis');
var connectRedis = require('connect-redis');
var session = require('express-session');
var cookieParser = require('cookie-parser');

function Sessions( config ) {
  var self = this;
  
  self.config = config;

  var resources = {};
  if (self.config.resource) {
    resources[ self.config.resource ] = {
      plugin: passportLocalMongoose
    }
  }
  
  self.extends = {
    resources: resources,
    services: {
      http: {
        middleware: function(req, res, next) {
          // set a user context (from passport)
          res.locals.user = req.user;
          return next();
        },
        setup: function( maki ) {
          maki.passport = passport;
          
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
  
          /* Configure the registration and login system */
          maki.app.use( maki.passport.initialize() );
          maki.app.use( maki.passport.session() );
          //maki.app.use( require('connect-flash')() );
  
          maki.passport.use( new LocalStrategy( verifyUser ) );
          function verifyUser( username , password , done ) {
            var Resource = maki.resources[ self.config.resource ];
            Resource.query({ username: username }, function(err, users) {
              if (err) return done(err);
              var user = users[0];
              
              if (!user) return done( null , false , { message: 'Invalid login.' } );
  
              user.authenticate( password , function(err) {
                if (err) return done( null , false , { message: 'Invalid login.' } );
                return done( null , user );
              });
            });
          }
          
          maki.resources[ self.config.resource ].pre('create', function(done) {
            var self = this;
            maki.resources[ self.config.resource ].Model.register({
              email: self.email,
              username: self.username
            }, self.password , function(err, user) {
              done();
            });
          });
          
          maki.app.get('/register', function(req, res, next) {
            res.render('register');
          });
          maki.app.get('/sessions', function(req, res, next) {
            res.render('login');
          });
          maki.app.post('/sessions', maki.passport.authenticate('local') , function(req, res, next) {
            console.log('created session.', req.user._id );
            return res.redirect('/');
          });
          maki.passport.serializeUser(function(user, done) {
            done( null , user._id );
          });
          maki.passport.deserializeUser(function(id, done) {
            maki.resources[ self.config.resource ].query({ _id: id }, function(err, users) {
              done( err , users[0] );
            });
          });
          
        }
      }
    }
  };
  
  return self;
}

module.exports = Sessions;
