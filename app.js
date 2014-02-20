/*
 *
 *  puush proxy
 *  2011 mave
 *
 *  This is a mess, but it fits in 1 file.
 *
 */

var http = require('http');
var url = require('url');
var querystring = require('querystring');
var formidable = require('formidable');
var fs = require('fs');
var util = require('util');
var mongoose = require('mongoose');
var crypto = require('crypto');
var path = require('path');
var mime = require('mime');

mongoose.connect('mongodb://localhost/puush');

// Configuration
var proxyPort = 9123;
var maxFileSize = 5 * 1024 * 1024; // 5 MB
var uploadedUrl = 'http://localhost:' + proxyPort + '/';
var uploadPath = 'upload/';
var passwordSalt = '';
var registerEnabled = false;

var Schema = mongoose.Schema;
var UserSchema = new Schema(
{
	email:			{ type: String },
	password:		{ type: String },
	ts:				{ type: Date, default: Date.now },
	apiKey:			{ type: String },
	quotaUsed:		{ type: Number, default: 0 }
});
var UserModel = mongoose.model('User', UserSchema);

var FileSchema = new Schema(
{
	owner:			{ type: Schema.ObjectId },
	shortname:		{ type: String },
	name:			{ type: String },
	ts:				{ type: Date, default: Date.now }
});
var FileModel = mongoose.model('File', FileSchema);

function hashPassword(password)
{
	var shasum = crypto.createHash('sha1');
	shasum.update(passwordSalt + String(password));
	return shasum.digest('hex');
}

function generateApiKey()
{
	var rand = String(Math.random());
	var magic = (new Date().getTime()).toString() + rand.substr(rand.indexOf('.') + 1);
	
	var shasum = crypto.createHash('sha1');
	shasum.update(magic);
	return shasum.digest('hex').toUpperCase();
}

function generateShortName()
{
	var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split("");
	return chars[Math.random() * 62 >> 0]
		+ chars[Math.random() * 62 >> 0]
		+ chars[Math.random() * 62 >> 0]
		+ chars[Math.random() * 62 >> 0];
}

function safeFilename(filename)
{
	return filename.replace(/\//g, '_').replace(/\\/g, '_');
}

function customPuush(req, res)
{
	var form = new formidable.IncomingForm();
	form.maxFieldsSize = maxFileSize; // 5mb

	form.on('error', function (err)
	{
		res.end('-1');
	});

	form.parse(req, function (err, fields, files)
	{
		var apiKey = fields['k'];
		var unk = fields['c'];
		
		UserModel.findOne({ apiKey: apiKey }, function (err, doc)
		{
			if (doc == null)
			{
				res.end('-1');
				return;
			}
			
			var success = 0;
			for (var i in files)
			{
				var f = files[i];
				
				if (f.size > maxFileSize) // second 5mb check
				{
					console.log('exceed 5mb');
					continue;
				}
				++success;
				
				var fn = function (f, name, callback)
				{
					path.exists(uploadPath + name, function (exists)
					{
						if (!exists)
						{
							callback(f, name);
						}
						else
						{
							var from = 1000; var to = 9999;
							var rand = Math.floor(Math.random() * (to - from + 1) + from);
							var idx = name.lastIndexOf('.');
							name = idx != -1 ? (name.substr(0, idx) + '_' + rand + name.substr(idx)) : (name + '_' + rand);
							fn(f, name, callback);
						}
					});
				};
				var fn2 = function (f, short, callback)
				{
					FileModel.findOne({ shortname: short }, function (err, doc)
					{
						if (doc == null)
						{
							callback(f, short);
						}
						else
						{
							name = generateShortName();
							fn2(f, name, callback);
						}
					});
				};
				var final = function (user, fx, name, shortname)
				{					
					// move file
					var is = fs.createReadStream(fx.path);
					var os = fs.createWriteStream(uploadPath + name);
					var ext = "." + name.split(".")[name.split(".").length-1];

					util.pump(is, os, (function (file, s)
					{
						fs.unlinkSync(file.path);
						
						var doc = new FileModel();
						doc.owner = user;
						doc.shortname = shortname;
						doc.name = name;
						doc.save();
						
						user.quotaUsed += file.size;
						user.save();
						
						res.end('0,' + uploadedUrl + s + ext + ',133337,12345');
					}).bind(this, fx, shortname));
				}
				
				// This attempts to generate a unique filename and short name for this file.
				// Asynchronous. Very messy.
				var a = {};
				fn(f, safeFilename(f.name), (function (u, a_, f_, name)
				{
					// got name
					a_.name = name;
					if (a_.name && a_.short && !(a_.done))
					{
						final(u, f_, a_.name, a_.short);
						a_.done = true;
					}
				}).bind(this, doc, a));
				fn2(f, generateShortName(), (function (u, a_, f_, short)
				{
					// got short name
					a_.short = short;
					if (a_.name && a_.short && !(a_.done))
					{
						final(u, f_, a_.name, a_.short);
						a_.done = true;
					}
				}).bind(this, doc, a));
			}
			
			if (success == 0)
			{
				res.end('-1');
			}
		});
	});
}

function handleRegister(req, res)
{
	res.writeHead(200, { 'Content-Type': 'text/html' });

	if (!registerEnabled)
	{
		res.end('Registration is disabled for this service');
		return;
	}
	
	if (req.method == 'POST')
	{
		var buf = '';
		req.on('data', function (chunk)
		{
			buf += chunk;
		});
		req.on('end', function ()
		{
			var query = querystring.parse(buf);
			
			var email = query['email'];
			var password = query['password'];
			if (!email || !password || email.length < 5 || password.length < 5)
			{
				res.write('Error: Your email/password can\'t be shorter than 5 characters');
				res.end('<br /><br /><a href="/register" onclick="history.back(); return false;">Back</a>');
				return;
			}
			if (email.indexOf('@') == -1 || email.indexOf('.') == -1)
			{
				res.write('Error: invalid email address');
				res.end('<br /><br /><a href="/register" onclick="history.back(); return false;">Back</a>');
				return;
			}
			
			var fn = function (apikey, callback)
			{
				UserModel.findOne({ apiKey: apikey }, function (err, doc)
				{
					if (doc == null)
					{
						callback(apikey);
					}
					else
					{
						apikey = generateApiKey();
						fn(apikey, callback);
					}
				});
			};
			fn(generateApiKey(), function (apikey)
			{
				var doc = new UserModel();
				doc.email = email;
				doc.password = hashPassword(password);
				doc.apiKey = apikey;
				doc.save();
				
				res.write('You have been registered successfully');
				res.end();
			});
		});
		return;
	}
	
	res.write(
		  '<h1>Register</h1>'
		+ '<form action="" method="post" />'
		+ 'Email: <input type="text" name="email" /><br />'
		+ 'Password: <input type="password" name="password" /><br />'
		+ '<br /><input type="submit" value="Register" />'
		+ '</form>'
	);
	res.end();
}

function format_date(d)
{
	return d.toISOString().replace("T", " ").split(".")[0];
}

http.createServer(function (request, response)
{
	var method = request.method;
	var uri = url.parse(request.url);
	var path = uri.pathname;
	
	var pathparts = (path[0] == '/' ? path.substr(1) : path).split('/');
	
	if (pathparts.length == 1)
	{
		if (pathparts[0] == 'register')
		{
			handleRegister(request, response);
			return;
		}
		else if (pathparts[0].split(".")[0].length == 4)
		{
			var short = pathparts[0].split(".")[0];
			
			FileModel.findOne({ shortname: short }, function (err, doc)
			{
				if (doc == null)
				{
					response.writeHead(404, { 'Content-Type': 'text/html' });
					response.end('<h1>404 Not Found</h1>');
				}
				else
				{
					fs.readFile(uploadPath + doc.name, 'binary', function (err, file)
					{
						if (err)
						{
							response.writeHead(500, { 'Content-Type': 'text/html' });
							response.end('<h1>500 Internal Server Error</h1>');
							return;
						}
						
						var mimetype = mime.lookup(doc.name);
						var headers = { 'Content-Type': mimetype };

						var needle = "application/";
						if (mimetype.length >= needle.length && mimetype.substr(0, needle.length) == needle)
						{
							headers['Content-Disposition'] = 'attachment; filename=' + doc.name
						}

						response.writeHead(200, headers);
						response.write(file, 'binary');
						response.end();
					});
				}
			});
			return;
		}
	}
	
	response.writeHead(200, { 'Content-Type': 'text/plain' });
	
	if (path == '/dl/puush-win.txt')
	{
		response.end('81');
		return;
	}
	
	if (pathparts.length < 2 || pathparts[0] != 'api')
	{
		response.end('This is a puush proxy service.');
		return;
	}
	
	var apiact = pathparts[1];
	
	if (apiact == 'auth')
	{
		var buf = '';
		request.on('data', function (chunk)
		{
			buf += chunk.toString();
		});
		request.on('end', function ()
		{	
			var query = querystring.parse(buf);
			var email = query['e'];
			var password = query['p'];
			var apikey = query['k'];
			var unknown = query['z'];
			
			if (!email || (!password && !apikey))
			{
				response.end('-1');
				return;
			}
			
			var cond = { email: String(email) };
			if (password) cond['password'] = hashPassword(password);
			else cond['apiKey'] = apikey;
			
			UserModel.findOne(cond, function (err, doc)
			{
				if (doc == null)
				{
					response.end('-1');
					return;
				}
				
				// ispremium,apikey,[expireday],quotaused
				response.end('1,' + doc.apiKey + ',,' + doc.quotaUsed);
			});
		});
		return;
	}
	else if (apiact == 'up')
	{
		customPuush(request, response);
		return;
	}
	else if (apiact == 'hist')
	{
		var buf = '';
		request.on('data', function (chunk)
		{
			buf += chunk.toString();
		});
		request.on('end', function ()
		{
			var query = querystring.parse(buf);
			var apikey = query['k'];
			if (!apikey)
			{
				response.end("0\n");
				return;
			}
			var cond = { apiKey: String(query['k']) };
			UserModel.findOne(cond, function(err, doc)
			{
				var user = doc["_id"];
				FileModel.find({ owner: String(user) }).limit(9).sort('_id', -1).exec(function(err, result)
				{
					if (result == null || err)
					{
						response.end('0\n');
						return;
					}
					var output = "0\n";
					result.map( function(item)
					{
						out = "5623457,";
						out += format_date(item["ts"]) + ",";
						out += uploadedUrl + item["shortname"] + ",";
						out += item["name"] + ",1337,0\n";
						output += out;
					});
					response.end(output);
					return;
				});
			});
		});
		return;
	}
}).listen(proxyPort);
