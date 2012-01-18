var eyes   = require('eyes'),
    events = require('events');
    async  = require('../vendor/async');

var db;

//
// Cached variables maintained to eliminate async calls to redis db 
var apiKeyHash;
var registryHash;

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

ApiKeyStore.prototype.getRegistry = function() {
    return registryHash;
}

/*
ApiKeyStore.prototype.findKeyRegistry = function(api, api_key, callback) {
    db.get('api_reg:' + api + ':' + api_key, function(err, json) {
        if (json == null)
            return callback('Error: invalid API key: ' + api_key);

        callback(null);
    });
}
*/

ApiKeyStore.prototype.findKey = function(api_key, callback) {
    db.get('api_key:' + api_key, function(err, json) {
        callback(err, JSON.parse(json));
    });
}

/**
 * Asynchronously wipes clean all API keys and registry
 */
ApiKeyStore.prototype.cleanDb = function() {
    // fetch api keys
    db.smembers('api_keys', function(err, replies) {
        // iterate api keys
        replies.forEach(function(reply) {
            console.log('deleting: ' + reply);
            // delete api key
            db.del('api_keys', reply, function(err, result) {
                console.log('delete result: ' + (result == 1 ? 'good' : 'bad'));
            });
        });
    });

    // delete root hash "api_keys"
    console.log('deleting root "api_keys"');
    db.del('api_keys', function(err, result) {
        console.log('delete result: ' + (result == 1 ? 'good' : 'bad'));
    });


    // fetch api reg entries
    db.smembers('api_registry', function(err, replies) {
        // iterate api reg entries
        replies.forEach(function(reply) {
            console.log('deleting: ' + reply);
            // delete api reg entry
            db.del('api_registry', reply, function(err, result) {
                console.log('delete result: ' + (result == 1 ? 'good' : 'bad'));
            });
        });
    });

    // delete root hash "api_registry"
    console.log('deleting root "api_registry"');
    db.del('api_registry', function(err, result) {
        console.log('delete result: ' + (result == 1 ? 'good' : 'bad'));
    });
}

/**
 * Stores the api key and data as well as registers the key with the specified API
 * 
 * @param options {object} kv param containing apis, key, data
 * @param callback {function} callback with err param which is null if method is successful
 */
ApiKeyStore.prototype.registerKey = function(options, callback) {
    callback = callback || function(err) {if (err) console.log("Error: " + err);};

    var apis = options.apis,
        key = options.key,
        data = options.keyData;

    // store API key
    function store_key(callback) {
        var store_key = 'api_key:' + key;
        db.sadd('api_keys', store_key, function(err, result) {
            if (err) return callback(err); 
            db.set(store_key, JSON.stringify(data), function(err, result) {
                if (err) return callback(err);

                // cache API key
                apiKeyHash[key] = data;

                callback(null);
            });
        });
    }

    // register key with specified APIs
    function register_key(callback) {
        var numApis = apis.length;
        apis.forEach(function(api) {
            var reg_key   = api + ':' + key;
            var store_key = 'api_reg:' + reg_key;  // api_reg:foo-api:98024dh2h9034723s23js49
            db.sadd('api_registry', store_key, function(err, result) {
                if (err) return callback(err); 
                db.set(store_key, '{}', function(err, result) {
                    if (err) return callback(err); 

                    // cache registry entry
                    registryHash[reg_key] = {};
        
                    if (--numApis == 0) 
                        callback(null);
                });
            });
        });
    }

    async.series([
        store_key,
        register_key
    ], callback); 
}

/**
 * Refreshes the cached variables 
 *
 * @param callback {function} A function containing params for apiKeyHash, registryHash, err
 */
ApiKeyStore.prototype.refreshCache = function(callback) {
    callback = callback || function(err, apiKeys, registry) {if (err) console.log("Error: " + err); };

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

    function find_registered(callback) {
        registryHash = {};
        db.smembers('api_registry', function(err, registry) {
            callback(err, registry);
        });
    }
    
    function get_reg_properties(registry, callback) {
        if (registry.length == 0)
            return callback(null);
        var numReg = registry.length;
        registry.forEach(function(api_reg, index) {
            db.get(api_reg, function(err, json) {
                api_reg = api_reg.split(':').slice(1).join(':');
                registryHash[api_reg] = JSON.parse(json);
                if (--numReg == 0) 
                    // pass apiKeyHash and registryHash to caller
                    callback(null, apiKeyHash, registryHash); 
            });
        });
    }

    async.waterfall([
        find_api_keys,
        get_api_properties,
        find_registered,
        get_reg_properties
    ], callback);
}
