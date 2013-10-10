/**
 * Module dependencies.
 */
var passport = require('passport');
var util = require('util');

/**
 * `Strategy` constructor.
 *
 * The Windows Authentication Strategy authenticate requests based on a IIS Server Variable.
 * IIS node puts this variable in a request header.
 *
 * Applications might supply credentials for an Active Directory and the strategy will fetch
 * the profile from there.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new WindowsAuthentication({
 *      ldap: {
 *        url:         'ldap://mydomain.com/',
 *        base:        'DC=wellscordobabank,DC=com',
 *        bindDN:          'AppUser',
 *        bindCredentials: 'APassword'
 *      }
 *        }, function(profile, done) {
 *         User.findOrCreate({ waId: profile.id }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
var Strategy = module.exports.Strategy = function (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('Active Directory authentication strategy requires a verify function!');

  if(!options.ldap || !options.ldap.url) {
    throw new Error('ldap url should be provided in order to validate user and passwords');
  }
  
  passport.Strategy.call(this);

  this.name = 'ad';
  this._verify = verify;

  this._getUserNameFromHeader = options.getUserNameFromHeader || function (req) {
    if (!req.headers['x-iisnode-logon_user']) return null;
    return req.headers['x-iisnode-logon_user'].split('\\')[1];
  };

  this.ldap = new (require('./ldap').Ldap)(options.ldap);
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * maps the user profile.
 */
Strategy.prototype.userProfile = function (i) {
  return this.ldap.userProfile(i);
};

/**
 * Authenticate request based on the contents of the x-iisnode-logon_user header
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  var self = this;
  var username, password;

  username = req.body.username;
  password = req.body.password;

  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

  this.ldap.authenticate(username, password, function(err, res){
    var p;
    if(res){
      self.ldap.getUsers("sAMAccountName="+username.substring(0,username.indexOf("@")), function(err, r){
        if(err){
          self.error(err);
        }else{
          var userProfile = self.userProfile(r[0]);
          if (self._passReqToCallback) {
            self._verify(req, userProfile, verified);
          } else {
            self._verify(userProfile, verified);
          }
        }
      });
    }else{
      if (self._passReqToCallback) {
        self._verify(req, null, verified);
      } else {
        self._verify(null, verified);
      }
    }
  });

};

