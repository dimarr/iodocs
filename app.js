//
// Copyright (c) 2011 Mashery, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// 'Software'), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

//
// Module dependencies
//
var express     = require('express'),
    util        = require('util'),
    fs          = require('fs'),
    sys         = require('sys'),
    OAuth       = require('oauth').OAuth,
    query       = require('querystring'),
    url         = require('url'),
    http        = require('http'),
    redis       = require('redis'),
    RedisStore  = require('connect-redis')(express),
    hashlib     = require('hashlib'),
    eyes        = require('eyes'),
    HttpProxy   = require('http-proxy').HttpProxy
    rbytes      = require('rbytes'),
    _           = require('./vendor/underscore'),
    async       = require('./vendor/async')
    ApiKeyStore = require('./app/ApiKeyStore').ApiKeyStore;

// Configuration
try {
    var configJSON = fs.readFileSync(__dirname + "/config.json");
    var config = JSON.parse(configJSON.toString());
} catch(e) {
    sys.puts("File config.json not found or is invalid.  Try: `cp config.json.sample config.json`");
    process.exit(1);
}

//
// Redis connection
//
var defaultDB = '0';
var db;

if (process.env.REDISTOGO_URL) {
    var rtg   = require("url").parse(process.env.REDISTOGO_URL);
    db = require("redis").createClient(rtg.port, rtg.hostname);
    db.auth(rtg.auth.split(":")[1]);
} else {
    db = redis.createClient(config.redis.port, config.redis.host);
    db.auth(config.redis.password);
}

db.on("error", function(err) {
    if (config.debug) {
         console.log("Error " + err);
    }
});

var apiKeyStore = new ApiKeyStore({
    'redisDb': db
});

//
// Load API Configs
//
var apisConfigFile = config.apiConfig || 'public/data/apiconfig.json';
var apisConfig;
fs.readFile(apisConfigFile, 'utf-8', function(err, data) {
    if (err) throw err;
    apisConfig = JSON.parse(data);
    if (config.debug) {
         console.log(util.inspect(apisConfig));
    }
});

var app = module.exports = express.createServer();

if (process.env.REDISTOGO_URL) {
    var rtg   = require("url").parse(process.env.REDISTOGO_URL);
    config.redis.host = rtg.hostname;
    config.redis.port = rtg.port;
    config.redis.password = rtg.auth.split(":")[1];
}

app.configure(function() {
    app.set('views', __dirname + '/views');
    app.set('view engine', 'jade');
    app.use(express.logger());
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.cookieParser());
    app.use(express.session({
        secret: config.sessionSecret,
        store:  new RedisStore({
            'host':   config.redis.host,
            'port':   config.redis.port,
            'pass':   config.redis.password,
            'maxAge': 1209600000
        })
    }));

    app.use(app.router);

    app.use(express.static(__dirname + '/public'));
});

app.configure('development', function() {
    app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});

app.configure('production', function() {
    app.use(express.errorHandler());
});

//
// Middleware
//
function oauth(req, res, next) {
    console.log('OAuth process started');
    var apiName = req.body.apiName,
        apiConfig = apisConfig[apiName];

    if (apiConfig.oauth) {
        var apiKey = req.body.apiKey || req.body.key,
            apiSecret = req.body.apiSecret || req.body.secret,
            refererURL = url.parse(req.headers.referer),
            callbackURL = refererURL.protocol + '//' + refererURL.host + '/authSuccess/' + apiName,
            oa = new OAuth(apiConfig.oauth.requestURL,
                           apiConfig.oauth.accessURL,
                           apiKey,
                           apiSecret,
                           apiConfig.oauth.version,
                           callbackURL,
                           apiConfig.oauth.crypt);

        if (config.debug) {
            console.log('OAuth type: ' + apiConfig.oauth.type);
            console.log('Method security: ' + req.body.oauth);
            console.log('Session authed: ' + req.session[apiName]);
            console.log('apiKey: ' + apiKey);
            console.log('apiSecret: ' + apiSecret);
        };

        // Check if the API even uses OAuth, then if the method requires oauth, then if the session is not authed
        if (apiConfig.oauth.type == 'three-legged' && req.body.oauth == 'authrequired' && (!req.session[apiName] || !req.session[apiName].authed) ) {
            if (config.debug) {
                console.log('req.session: ' + util.inspect(req.session));
                console.log('headers: ' + util.inspect(req.headers));

                console.log(util.inspect(oa));
                // console.log(util.inspect(req));
                console.log('sessionID: ' + util.inspect(req.sessionID));
                // console.log(util.inspect(req.sessionStore));
            };

            oa.getOAuthRequestToken(function(err, oauthToken, oauthTokenSecret, results) {
                if (err) {
                    res.send("Error getting OAuth request token : " + util.inspect(err), 500);
                } else {
                    // Unique key using the sessionID and API name to store tokens and secrets
                    var key = req.sessionID + ':' + apiName;

                    db.set(key + ':apiKey', apiKey, redis.print);
                    db.set(key + ':apiSecret', apiSecret, redis.print);

                    db.set(key + ':requestToken', oauthToken, redis.print);
                    db.set(key + ':requestTokenSecret', oauthTokenSecret, redis.print);

                    // Set expiration to same as session
                    db.expire(key + ':apiKey', 1209600000);
                    db.expire(key + ':apiSecret', 1209600000);
                    db.expire(key + ':requestToken', 1209600000);
                    db.expire(key + ':requestTokenSecret', 1209600000);

                    // res.header('Content-Type', 'application/json');
                    res.send({ 'signin': apiConfig.oauth.signinURL + oauthToken });
                }
            });
        } else if (apiConfig.oauth.type == 'two-legged' && req.body.oauth == 'authrequired') {
            // Two legged stuff... for now nothing.
            next();
        } else {
            next();
        }
    } else {
        next();
    }

}

//
// OAuth Success!
//
function oauthSuccess(req, res, next) {
    var oauthRequestToken,
        oauthRequestTokenSecret,
        apiKey,
        apiSecret,
        apiName = req.params.api,
        apiConfig = apisConfig[apiName],
        key = req.sessionID + ':' + apiName; // Unique key using the sessionID and API name to store tokens and secrets

    if (config.debug) {
        console.log('apiName: ' + apiName);
        console.log('key: ' + key);
        console.log(util.inspect(req.params));
    };

    db.mget([
        key + ':requestToken',
        key + ':requestTokenSecret',
        key + ':apiKey',
        key + ':apiSecret'
    ], function(err, result) {
        if (err) {
            console.log(util.inspect(err));
        }
        oauthRequestToken = result[0],
        oauthRequestTokenSecret = result[1],
        apiKey = result[2],
        apiSecret = result[3];

        if (config.debug) {
            console.log(util.inspect(">>"+oauthRequestToken));
            console.log(util.inspect(">>"+oauthRequestTokenSecret));
            console.log(util.inspect(">>"+req.query.oauth_verifier));
        };

        var oa = new OAuth(apiConfig.oauth.requestURL,
                           apiConfig.oauth.accessURL,
                           apiKey,
                           apiSecret,
                           apiConfig.oauth.version,
                           null,
                           apiConfig.oauth.crypt);

        if (config.debug) {
            console.log(util.inspect(oa));
        };

        oa.getOAuthAccessToken(oauthRequestToken, oauthRequestTokenSecret, req.query.oauth_verifier, function(error, oauthAccessToken, oauthAccessTokenSecret, results) {
            if (error) {
                res.send("Error getting OAuth access token : " + util.inspect(error) + "["+oauthAccessToken+"]"+ "["+oauthAccessTokenSecret+"]"+ "["+util.inspect(results)+"]", 500);
            } else {
                if (config.debug) {
                    console.log('results: ' + util.inspect(results));
                };
                db.mset([key + ':accessToken', oauthAccessToken,
                    key + ':accessTokenSecret', oauthAccessTokenSecret
                ], function(err, results2) {
                    req.session[apiName] = {};
                    req.session[apiName].authed = true;
                    if (config.debug) {
                        console.log('session[apiName].authed: ' + util.inspect(req.session));
                    };

                    next();
                });
            }
        });

    });
}

//
// processRequest - handles API call
//
function processRequest(req, res, next) {
    if (config.debug) {
        console.log(util.inspect(req.body, null, 3));
    };

    var reqQuery = req.body,
        params = reqQuery.params || {},
        methodURL = reqQuery.methodUri,
        httpMethod = reqQuery.httpMethod,
        apiKey = reqQuery.apiKey,
        apiSecret = reqQuery.apiSecret,
        apiName = reqQuery.apiName
        apiConfig = apisConfig[apiName],
        key = req.sessionID + ':' + apiName;

    // Replace placeholders in the methodURL with matching params
    for (var param in params) {
        if (params.hasOwnProperty(param)) {
            if (params[param] !== '') {
                // URL params are prepended with ":"
                var regx = new RegExp(':' + param);

                // If the param is actually a part of the URL, put it in the URL and remove the param
                if (!!regx.test(methodURL)) {
                    methodURL = methodURL.replace(regx, params[param]);
                    delete params[param]
                }
            } else {
                delete params[param]; // Delete blank params
            }
        }
    }

    var baseHostInfo = apiConfig.baseURL.split(':');
    var baseHostUrl = baseHostInfo[0],
        baseHostPort = (baseHostInfo.length > 1) ? baseHostInfo[1] : "";

    var paramString = query.stringify(params),
        //privateReqURL = apiConfig.protocol + '://' + apiConfig.baseURL + apiConfig.privatePath + methodURL + ((paramString.length > 0) ? '?' + paramString : ""),
        privateReqURL = '/' + apiName + '/api' + apiConfig.privatePath + methodURL + ((paramString.length > 0) ? '?' + paramString: ""),
        options = {
            headers: {},
            //protocol: apiConfig.protocol,
            //host: baseHostUrl,
            //port: baseHostPort,
            method: httpMethod,
            //path: apiConfig.publicPath + methodURL + ((paramString.length > 0) ? '?' + paramString : "")
            path: privateReqURL,
            port: config.port,
            host: config.address
        };

    if (apiConfig.oauth) {
        console.log('Using OAuth');

        // Three legged OAuth
        if (apiConfig.oauth.type == 'three-legged' && (reqQuery.oauth == 'authrequired' || (req.session[apiName] && req.session[apiName].authed))) {
            if (config.debug) {
                console.log('Three Legged OAuth');
            };

            db.mget([key + ':apiKey',
                     key + ':apiSecret',
                     key + ':accessToken',
                     key + ':accessTokenSecret'
                ],
                function(err, results) {

                    var apiKey = (typeof reqQuery.apiKey == "undefined" || reqQuery.apiKey == "undefined")?results[0]:reqQuery.apiKey,
                        apiSecret = (typeof reqQuery.apiSecret == "undefined" || reqQuery.apiSecret == "undefined")?results[1]:reqQuery.apiSecret,
                        accessToken = results[2],
                        accessTokenSecret = results[3];
                    console.log(apiKey);
                    console.log(apiSecret);
                    console.log(accessToken);
                    console.log(accessTokenSecret);
                    
                    var oa = new OAuth(apiConfig.oauth.requestURL || null,
                                       apiConfig.oauth.accessURL || null,
                                       apiKey || null,
                                       apiSecret || null,
                                       apiConfig.oauth.version || null,
                                       null,
                                       apiConfig.oauth.crypt);

                    if (config.debug) {
                        console.log('Access token: ' + accessToken);
                        console.log('Access token secret: ' + accessTokenSecret);
                        console.log('key: ' + key);
                    };

                    oa.getProtectedResource(privateReqURL, httpMethod, accessToken, accessTokenSecret,  function (error, data, response) {
                        req.call = privateReqURL;

                        // console.log(util.inspect(response));
                        if (error) {
                            console.log('Got error: ' + util.inspect(error));

                            if (error.data == 'Server Error' || error.data == '') {
                                req.result = 'Server Error';
                            } else {
                                req.result = error.data;
                            }

                            res.statusCode = error.statusCode

                            next();
                        } else {
                            req.resultHeaders = response.headers;
                            req.result = JSON.parse(data);

                            next();
                        }
                    });
                }
            );
        } else if (apiConfig.oauth.type == 'two-legged' && reqQuery.oauth == 'authrequired') { // Two-legged
            if (config.debug) {
                console.log('Two Legged OAuth');
            };

            var body,
                oa = new OAuth(null,
                               null,
                               apiKey || null,
                               apiSecret || null,
                               apiConfig.oauth.version || null,
                               null,
                               apiConfig.oauth.crypt);

            var resource = options.protocol + '://' + options.host + options.path,
                cb = function(error, data, response) {
                    if (error) {
                        if (error.data == 'Server Error' || error.data == '') {
                            req.result = 'Server Error';
                        } else {
                            console.log(util.inspect(error));
                            body = error.data;
                        }

                        res.statusCode = error.statusCode;

                    } else {
                        console.log(util.inspect(data));

                        var responseContentType = response.headers['content-type'];

                        switch (true) {
                            case /application\/javascript/.test(responseContentType):
                            case /text\/javascript/.test(responseContentType):
                            case /application\/json/.test(responseContentType):
                                body = JSON.parse(data);
                                break;
                            case /application\/xml/.test(responseContentType):
                            case /text\/xml/.test(responseContentType):
                            default:
                        }
                    }

                    // Set Headers and Call
                    if (response) {
                        req.resultHeaders = response.headers || 'None';
                    } else {
                        req.resultHeaders = req.resultHeaders || 'None';
                    }

                    req.call = url.parse(options.host + options.path);
                    req.call = url.format(req.call);

                    // Response body
                    req.result = body;

                    next();
                };

            switch (httpMethod) {
                case 'GET':
                    console.log(resource);
                    oa.get(resource, '', '',cb);
                    break;
                case 'PUT':
                case 'POST':
                    oa.post(resource, '', '', JSON.stringify(obj), null, cb);
                    break;
                case 'DELETE':
                    oa.delete(resource,'','',cb);
                    break;
            }

        } else {
            // API uses OAuth, but this call doesn't require auth and the user isn't already authed, so just call it.
            unsecuredCall();
        }
    } else {
        // API does not use authentication
        unsecuredCall();
    }

    // Unsecured API Call helper
    function unsecuredCall() {
        console.log('Unsecured Call');
        
        // Add API Key to params, if any.
        if (apiKey != '' && apiKey != 'undefined' && apiKey != undefined) {
            options.path += (!paramString.length ? '?' : '&') + apiConfig.keyParam + '=' + apiKey;
        }

        // Perform signature routine, if any.
        if (apiConfig.signature) {
            if (apiConfig.signature.type == 'signed_md5') {
                // Add signature parameter
                var timeStamp = Math.round(new Date().getTime()/1000);
                var sig = hashlib.md5('' + apiKey + apiSecret + timeStamp + '', { asString: true });
                options.path += '&' + apiConfig.signature.sigParam + '=' + sig;
            }
            else if (apiConfig.signature.type == 'signed_sha256') { // sha256(key+secret+epoch)
                // Add signature parameter
                var timeStamp = Math.round(new Date().getTime()/1000);
                var sig = hashlib.sha256('' + apiKey + apiSecret + timeStamp + '', { asString: true });
                options.path += '&' + apiConfig.signature.sigParam + '=' + sig;
            }
        }

        // Setup headers, if any
        if (reqQuery.headerNames && reqQuery.headerNames.length > 0) {
            if (config.debug) {
                console.log('Setting headers');
            };
            var headers = {};

            for (var x = 0, len = reqQuery.headerNames.length; x < len; x++) {
                if (config.debug) {
                  console.log('Setting header: ' + reqQuery.headerNames[x] + ':' + reqQuery.headerValues[x]);
                };
                if (reqQuery.headerNames[x] != '') {
                    headers[reqQuery.headerNames[x]] = reqQuery.headerValues[x];
                }
            }

            options.headers = headers;
        }

        if (!options.headers['Content-Length']) {
            options.headers['Content-Length'] = 0;
        }

        if (config.debug) {
            console.log(util.inspect(options));
        };

        // API Call. response is the response from the API, res is the response we will send back to the user.
        var apiCall = http.request(options, function(response) {
            response.setEncoding('utf-8');
            if (config.debug) {
                console.log('HEADERS: ' + JSON.stringify(response.headers));
                console.log('STATUS CODE: ' + response.statusCode);
            };

            res.statusCode = response.statusCode;

            var body = '';

            response.on('data', function(data) {
                body += data;
            })

            response.on('end', function() {
                delete options.agent;

                var responseContentType = response.headers['content-type'];

                switch (true) {
                    case /application\/javascript/.test(responseContentType):
                    case /application\/json/.test(responseContentType):
                        console.log(util.inspect(body));
                        // body = JSON.parse(body);
                        break;
                    case /application\/xml/.test(responseContentType):
                    case /text\/xml/.test(responseContentType):
                    default:
                }

                // Set Headers and Call
                req.resultHeaders = response.headers;
                req.call = url.parse(options.host + (options.port == 80 ? '' : ':' + options.port) + options.path);
                req.call = url.format(req.call);
                
                // Response body
                req.result = body;

                console.log(util.inspect(body));

                next();
            })
        }).on('error', function(e) {
            if (config.debug) {
                console.log('HEADERS: ' + JSON.stringify(res.headers));
                console.log("Got error: " + e.message);
                console.log("Error: " + util.inspect(e));
            };
        });

        apiCall.end();
    }
}

// Dynamic Helpers
// Passes variables to the view
app.dynamicHelpers({
    session: function(req, res) {
    // If api wasn't passed in as a parameter, check the path to see if it's there
 	    if (!req.params.api) {
 	    	pathName = req.url.replace('/','');
 	    	// Is it a valid API - if there's a config file we can assume so
 	    	fs.stat('public/data/' + pathName + '.json', function (error, stats) {
   				if (stats) {
   					req.params.api = pathName;
   				}
 			});
 	    }       
 	    // If the cookie says we're authed for this particular API, set the session to authed as well
        if (req.params.api && req.session[req.params.api] && req.session[req.params.api]['authed']) {
         	req.session['authed'] = true;
        }

        return req.session;
    },
    apiInfo: function(req, res) {
        if (req.params.api) {
            return apisConfig[req.params.api];
        } else {
            return apisConfig;
        }
    },
    apiName: function(req, res) {
        if (req.params.api) {
            return req.params.api;
        }
    },
    apiDefinition: function(req, res) {
        if (req.params.api) {
            var data = fs.readFileSync('public/data/' + req.params.api + '.json');
            return JSON.parse(data);
        }
    }
})

//
// Routes
//

/**
 * API proxy, key authenticator, rate limiter
 */
app.all('/:api([^/]+)/api/:uri(*)', function(req, res) {
    var api_key = req.body.api_key != null ? req.body.api_key : req.query.api_key;
    var api_conf = apisConfig[req.params.api];
    var api = req.params.api;
    var split = api_conf.baseURL.split(':'),
        host = split[0],
        port = (split.length == 2) ? port[1] : 80;


    if (api_key == null) 
        return res.send('Error: API key required', 500);

    if (!apiKeyStore.getRegistry()[api + ':' + api_key])
        return res.send('Error: invalid API key: ' + api_key, 500);

    var options = {
        'target' : {
            'host' : host,
            'port' : port
        }
    };

    //
    // rewrite the URL
    //  [ /my-api-name/api/my-method-name.xml ] --> [ baseURL + /my-method-name.xml ]
    req.url = '/' + req.url.split('/api/')[1];

    var proxy = new HttpProxy(options);

    proxy.on('start', function(req, res, target) {
        console.log('Start proxy request...');
    });
    proxy.on('proxyError', function(err, req, res) {
        console.log('!!!proxy error!!! ' + err);
    });
    proxy.on('end', function(req, res) {
        console.log('End proxy request');
    });

    proxy.proxyRequest(req, res);
});

/**
 * Wipes clean all of the API keys and registry
 */
app.get('/clean-db', function(req, res) {
    console.log('Cleaning db');
    apiKeyStore.cleanDb();
    res.send('OK');
});

/**
 * Dumps db contents
 */
app.get('/dump-db', function(req, res) {
    function callback(err, apiKeys, registry) {
        if (err != null) return res.send(err, 500);

        var json = {
            'apiKeys': apiKeys,
            'registry': registry
        };

        res.send(json);
    }

    apiKeyStore.refreshCache(callback);
});

/**
 * Outputs APIs in a kv object
 * Each key is the APIs name, each value containing API data and registered keys
 */
app.get('/apis', function(req, res) {
    var apis = {};
    // make a deep copy of apisConfig
    _.each(apisConfig, function(props, api) {
        apis[api] = {};
        _.extend(apis[api], props);
    });
    db.smembers('api_registry', function(err, registry) {
        registry.forEach(function(entry) {
            var split = entry.split(':'),
                api = split[1],
                key = split[2];

            if (!apis[api].keys) apis[api]['keys'] = [];
            apis[api].keys.push(key);
        });

        res.send(apis);
    });
});


app.get('/keys', function(req, res) {
    // hash to filter uniq keys and store key data
    var keyHash = {};
    // get a unique and trimmed list of keys
    var keys = _.filter(req.query.keys.split(/\s*,\s*/), function(key) { if (!keyHash[key]) { keyHash[key]=1; return true; } return false; });
    
    // retrieve data for each key
    _.each(keys, function(key, index) {
        apiKeyStore.findKey(key, function(err, data) {
            keyHash[key] = data;
            if (index == keys.length - 1) 
                res.send(keyHash);
        });
    });
});

app.get('/manageKeys', function(req, res) {
    res.render('manageKeys', {
        title: config.title
    });
});
app.get('/createKey', function(req, res) {
    res.render('createKey', {
        title: config.title    
    });
});

/**
 * Generates an api key and registers it with the specified api(s)
 *
 * @param apis {array}  List of APIs for which key will have access to
 * @param appName       Name of consumer application which will use the key
 * @param description   Description of the consumer app
 * @param email         Contact email
 */
app.post('/keys', function(req, res) {
    var reqQuery = req.body,
        rbuff = rbytes.randomBytes(16),
        key = rbuff.toHex(),
        apis = reqQuery.apis;       

    if (apis == null || apis.length == 0) 
        return res.send('No APIs provided', 500);

    if (!_.isArray(apis))
        apis = [apis];

    function callback(err, results) {
        if (err != null) return res.send(err, 500);

        res.send({
            'key': key
        });
    }

    apiKeyStore.registerKey({
        'key': key,
        'apis': apis,
        'keyData': {
            'description': reqQuery.description,
            'appName': reqQuery.appName,
            'email': reqQuery.email,
            'createTime': new Date()
        }
    }, callback);

});


app.get('/', function(req, res) {
    res.render('listAPIs', {
        title: config.title
    });
});


// Process the API request
app.post('/processReq', oauth, processRequest, function(req, res) {
    var result = {
        headers: req.resultHeaders,
        response: req.result,
        call: req.call
    };

    res.send(result);
});

// Just auth
app.all('/auth', oauth);

// OAuth callback page, closes the window immediately after storing access token/secret
app.get('/authSuccess/:api', oauthSuccess, function(req, res) {
    res.render('authSuccess', {
        title: 'OAuth Successful'
    });
});

app.post('/upload', function(req, res) {
  console.log(req.body.user);
  res.redirect('back');
});

// API shortname, all lowercase
app.get('/:api([^\.]+)', function(req, res) {
    res.render('api');
});
// Only listen on $ node app.js

if (!module.parent) {
    var port = process.env.PORT || config.port;
    app.listen(port);
    console.log("Express server listening on port %d", app.address().port);
}
