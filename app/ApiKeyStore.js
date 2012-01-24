var eyes   = require('eyes'),
    events = require('events');
    async  = require('../vendor/async');

var db;

//
// Cached variables maintained to eliminate async calls to redis db 
var apiKeyHash;
var apiLinkHash;

var ApiKeyStore = exports.ApiKeyStore = function (options) {
    if (!options || !options.redisDb) {
        throw new Error("Both 'options' and 'options.redisDb' are required");
    }
    
    db = options.redisDb;

    events.EventEmitter.call(this);

    var self = this;

    // create cache upon module initialization
    setTimeout(function() {
        self.refreshCache();
    }, 500);
}

ApiKeyStore.prototype.getApiKeys = function() {
    return apiKeyHash;
}

ApiKeyStore.prototype.getApiLinks = function() {
    return apiLinkHash;
}

/**
 * Looks up APIs for the specified key
 *
 * @param api_key {string} key for which to look up APIs for
 * @param callback {function} Callback with params for err and list of APIs
 */
ApiKeyStore.prototype.findApisForKey = function(api_key, callback) {
    db.multi()
    .scard('api_links')
    .smembers('api_links')
    .keys('api_link:*:' + api_key, function(err, links) {
        // take a full link key ("api_link:api-name:key") and return back just the api
        var apis = _.map(links, function(link) {
            return link.split(':')[1];
        });
        callback(err, apis);
    })
    .dbsize()
    .exec(); 
}

/**
 * Looks up keys for the specified API
 *
 * @param api {string} API for which to look up keys for
 * @param callback {function} Callback with params for err and list of keys
 */
ApiKeyStore.prototype.findKeysForApi = function(api, callback) {
    db.multi()
    .scard('api_links')
    .smembers('api_links')
    .keys('api_link:' + api + ':*', function(err, links) {
        // take a full link key ("api_link:api-name:key") and return back just the api key
        var apis = _.map(links, function(link) {
            return link.split(':')[2];
        });
        callback(err, apis);
    })
    .dbsize()
    .exec(); 
}

ApiKeyStore.prototype.findLink = function(link, callback) {
    callback = callback || function(err) {if (err) console.log("Error: " + err);};
    db.get('api_link:' + link, function(err, json) {
        callback(err, JSON.parse(json));
    });
}


ApiKeyStore.prototype.findKey = function(api_key, callback) {
    callback = callback || function(err) {if (err) console.log("Error: " + err);};
    db.get('api_key:' + api_key, function(err, json) {
        callback(err, JSON.parse(json));
    });
}

ApiKeyStore.prototype.unlinkApi = function(api_key, api, callback) {
    callback = callback || function(err) {if (err) console.log("Error: " + err);};
    db.del('api_links', 'api_link:' + api + ':' + api_key , function(err, result) {
        callback(err);
    });
}

ApiKeyStore.prototype.linkApi = function(api_key, api, callback) {
    callback = callback || function(err) {if (err) console.log("Error: " + err);};
    var reg_key   = api + ':' + api_key;
    var store_key = 'api_link:' + reg_key;  // api_link:foo-api:98024dh2h9034723s23js49
    db.sadd('api_links', store_key, function(err, result) {
        if (err) return callback(err); 
        db.set(store_key, '{}', function(err, result) {
            if (err) return callback(err); 

            // cache link
            apiLinkHash[reg_key] = {};

            callback();
        });
    });
}

/**
 * Asynchronously wipes clean all API keys and links
 */
ApiKeyStore.prototype.cleanDb = function() {
    var self = this;

    // fetch api keys
    db.smembers('api_keys', function(err, replies) {
        // iterate api keys
        replies.forEach(function(reply) {
            // delete api key
            db.del('api_keys', reply, function(err, result) {
                console.log('delete api_key: ' + (result == 1 ? 'good' : 'bad'));
            });
        });
    });

    // delete root hash "api_keys"
    db.del('api_keys', function(err, result) {
        console.log('delete api_keys: ' + (result == 1 ? 'good' : 'bad'));
    });


    // fetch api reg entries
    db.smembers('api_links', function(err, replies) {
        // iterate api reg entries
        replies.forEach(function(reply) {
            // delete api reg entry
            var split = reply.split(':'),
                api = split[1],
                api_key = split[2];

            self.unlinkApi(api_key, api, function(err) {
                console.log('delete api_link: ' + (!err ? 'good' : 'bad'));
            });

        });
    });

    // delete root hash "api_links"
    db.del('api_links', function(err, result) {
        console.log('delete api_links: ' + (result == 1 ? 'good' : 'bad'));
    });

    // fetch request log buckets
    db.smembers('request_log_buckets', function(err, replies) {
        replies.forEach(function(bucket) {
            db.del('request_log_buckets', bucket, function(err, result) {
                console.log('delete request_logs: ' + (result == 1 ? 'good' : 'bad'));
            });
        });
    });

    // delete root hash "request_log_buckets"
    db.del('request_log_buckets', function(err, result) {
        console.log('delete request_log_buckets: ' + (result == 1 ? 'good' : 'bad'));
    });
}

ApiKeyStore.prototype.saveKey = function(key, keyData, callback) {
    var store_key = 'api_key:' + key;
    db.set(store_key, JSON.stringify(keyData), function(err, result) {
        if (err) return callback(err);

        // cache API key
        apiKeyHash[key] = keyData;

        callback(null);
    });
}

/**
 * 1) Stores the api key and data 
 * 2) Creates key <-> api links
 * 
 * @param options {object} kv param containing apis, key, data
 * @param callback {function} callback with err param which is null if method is successful
 */
ApiKeyStore.prototype.registerKey = function(options, callback) {
    callback = callback || function(err) {if (err) console.log("Error: " + err);};

    var self = this;
    var apis = options.apis,
        key = options.key,
        keyData = options.keyData;

    // store API key
    function store_key(callback) {
        var store_key = 'api_key:' + key;
        db.sadd('api_keys', store_key, function(err, result) {
            if (err) return callback(err); 
            self.saveKey(key, keyData, callback);
        });
    }

    // links APIs with specified key
    function link_apis(callback) {
        var numApis = apis.length;
        apis.forEach(function(api) {
            self.linkApi(key, api, function(err) {
                if (--numApis == 0) 
                    callback();
            });
        });
    }

    async.series([
        store_key,
        link_apis
    ], callback); 
}

/**
 * Refreshes the cached variables 
 * @param callback {function} A function containing params for apiKeyHash, apiLinkHash, err
 */
ApiKeyStore.prototype.refreshCache = function(callback) {
    callback = callback || function(err, apiKeys, links) {if (err) console.log("Error: " + err); };

    console.log('Refreshing API keys cache');

    function find_api_keys(callback) {
        apiKeyHash = {};
        db.smembers('api_keys', function(err, api_keys) {
            callback(err, api_keys);
        });
    }

    function get_api_properties(api_keys, callback) {
        if (api_keys.length == 0) 
            return callback(null);
        var numKeys = api_keys.length;
        api_keys.forEach(function(api_key, index) {
            db.get(api_key, function(err, json) {
                api_key = api_key.split(':')[1];
                apiKeyHash[api_key] = JSON.parse(json);

                if (--numKeys == 0) 
                    callback(null);
            }); 
        });
    }

    function find_linked(callback) {
        apiLinkHash = {};
        db.smembers('api_links', function(err, links) {
            callback(err, links);
        });
    }
    
    function get_link_properties(links, callback) {
        var numLinks = links.length;
        if (numLinks == 0)
            return callback();
        links.forEach(function(api_link, index) {
            db.get(api_link, function(err, json) {
                api_link = api_link.split(':').slice(1).join(':');
                apiLinkHash[api_link] = JSON.parse(json);
                if (--numLinks == 0) 
                    callback(); 
            });
        });
    }

    // get request log keys for each {api, key} pair
    function get_log_buckets(callback) {
        db.smembers('request_log_buckets', function(err, buckets) {
            callback(err, buckets);
        });
    }

    // get num logs for each {api, key} pair
    function get_log_counts(buckets, callback) {
        var numBuckets = buckets.length;
        var bucketHash = {};
        if (numBuckets == 0)
            callback(null, apiKeyHash, apiLinkHash, bucketHash); 
        buckets.forEach(function(bucket, index) {
            db.llen(bucket, function(err, len) {
                bucketHash[bucket] = {
                    'numLogs' : len
                };
                if (--numBuckets == 0) 
                    callback(null, apiKeyHash, apiLinkHash, bucketHash); 
            });
        });
    }

    async.waterfall([
        find_api_keys,
        get_api_properties,
        find_linked,
        get_link_properties,
        get_log_buckets,
        get_log_counts
    ], callback);
}

ApiKeyStore.prototype.findRequestLogs = function(api_key, api, callback) {
    callback = callback || function(err) {if (err) console.log("Error: " + err);};
    var bucket_key = 'request_logs:' + api + ':' + api_key;    
    var myLogs = [];
    var keys = ['time', 'ip', 'method', 'pathname'];
    db.lrange(bucket_key, 0, 9999, function(err, log_keys) {
        if (err) return callback(err); 

        for (var i = 0; i < log_keys.length; i++) {
            var j = 0;
            myLogs.push(
                _.chain(log_keys[i].split(':').slice(3, 3 + keys.length))
                .reduce(function(hash, val) { 
                    var key = keys[j];
                    if (key == 'time')
                        hash[key] = 1*val;
                    else
                        hash[key] = val; 
                    j++;
                    return hash; 
                }, {})
                .value()
            );
        }

        return callback(null, myLogs);
    });
}

ApiKeyStore.prototype.logRequest = function(options) {
    options = options || {};

    var apiName = options.apiName,
        apiKey = options.apiKey,
        time = options.time,
        ip = options.ip,
        method = options.method,
        pathname = options.pathname;

    var bucket_key = 'request_logs:' + apiName + ':' + apiKey;
    var log_key = 'request_log:' + apiName + ':' + apiKey + ':' + time + ':' + ip + ':' + method + ':' + pathname;

    db.multi()
    .sadd('request_log_buckets', bucket_key, function(err, replies) {
        if (err) console.dir(err);
    })
    .lpush(bucket_key, log_key, function(err, replies) {
        if (err) console.dir(err);
        console.log('logging ' + log_key + '... log count = ' + replies);
    })
    .exec();
}
