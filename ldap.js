var Ldap = module.exports.Ldap = function(config){
	this.config = config;
	this.ldap = require('ldapjs');
	this.ldap.Attribute.settings.guid_format = this.ldap.GUID_FORMAT_D;
}

Ldap.prototype.getUsers = function(f, cb){
	var ldap = this.ldap
		, config = this.config
	;

	if(!cb){
		cb = f;
		f = null;
	}

	if(f){
		var filter = "(&"+"(&(objectClass=user)(!(objectClass=computer)))"+"("+f+"))";
	}else{
		var filter = "(&(objectClass=user)(!(objectClass=computer)))";
	}

	var client = ldap.createClient({
	  url: config.url
	});

	client.bind(config.bindDN, config.bindCredentials, function(err) {
		if(err){
			cb(err);
		}else{
			console.log(filter);
			client.search(config.base, {
				scope: "sub", 
				filter: filter, 
			}, function(err, res){
				if(err){
					cb(err);
				}else{
					var r = [];
					res.on('searchEntry', function(entry) {
						r.push(entry.object);
					});

					res.on('end', function(result) {
						cb(null, r);
					});
				}
			})
		}


	});
}

Ldap.prototype.getGroups = function(f, cb){
	var ldap = this.ldap
		, config = this.config
	;

	if(!cb){
		cb = f;
		f = null;
	}

	if(f){
		var filter = "(&"+"(&(objectClass=group)(!(objectClass=computer)))"+"("+f+"))";
	}else{
		var filter = "(&(objectClass=group)(!(objectClass=computer)))";
	}

	var client = ldap.createClient({
	  url: config.url
	});

	client.bind(config.bindDN, config.bindCredentials, function(err) {
		if(err){
			cb(err);
		}else{
			console.log(filter);
			client.search(config.base, {
				scope: "sub", 
				filter: filter, 
			}, function(err, res){
				if(err){
					cb(err);
				}else{
					var r = [];
					res.on('searchEntry', function(entry) {
						r.push(entry.object);
					});

					res.on('end', function(result) {
						cb(null, r);
					});
				}
			})
		}


	});
}

Ldap.prototype.userProfile = function(i){
  var result = {
    id:          i.objectGUID,
    displayName: i.displayName || i.cn,
    name: {
      familyName: i.sn,
      givenName: i.givenName
    },
    emails: [{value: i.mail }],
    _json: i
  };
  return result;
 }

Ldap.prototype.authenticate = function(usr, pas, cb){
	var ldap = this.ldap
		, config = this.config
	;

	var client = ldap.createClient({
	  url: config.url
	});

	client.bind(usr, pas, function(err) {
		if(err){
			cb(err);
		}else{
			cb(null, true);
		}
	});
}