// common functions and values for utilities

const fs      = require('fs');
const path    = require('path');
const jsYaml = require('js-yaml');
const request = require('request-promise-native');
const atob    = require('atob');


const started = Date.now();

let commander;
let logger;
let state;
let protoHostPort;
//
// Must call this before executing other functions
function setVars(c, l, s) {
  commander = c;
  logger = l;
  state = s;

  state.started = new Date(started).toGMTString();
}
// resolve dotted path into obj
function resolvePath(obj, path) {
  let paths = path.split('.');
  let val = obj;
  while (paths.length && typeof(obj) !== 'undefined') {
    obj = obj[paths[0]];
    paths.shift();
  }
  return obj;
}
// (state,'debug', commander.debug)
function setPath(obj, path, val) {
  let paths = path.split('.');
  while (paths.length > 1 && typeof(obj) !== 'undefined') {
    if (typeof(obj[paths[0]]) === 'undefined') {
      obj = obj[paths[0]] = {};
    } else {
      obj = obj[paths[0]];
    }
    paths.shift();
  }
  if (typeof(obj) === 'object') {
    obj[paths[0]] = val;
  }
  return obj;
}
// @param name - the name of the item in the state object, can be dotted path
// @param commanderProp - the optional commander (command line) argument name if different from name
// #param configProp - optional configuration file prop name if different from name, can be dotted path
// Note - can be used for item that is not available on the command line, pass false for commanderProp
function processConfigItem(stateName, commanderProp, configProp) {
  if (!commanderProp && commanderProp !== false) {
    commanderProp = stateName;
  }
  if (!configProp) {
    configProp = stateName;
  }
  if (commanderProp !== false && commander[commanderProp]) {
    logger.info(`Using command line parameter - ${commanderProp}, ${commander[commanderProp]}`);
    setPath(state, stateName, commander[commanderProp]); // command line overrides default
  } else if (typeof(resolvePath(state.config, configProp)) !== 'undefined') {
    logger.info(`Using config file parameter - ${configProp}, ${resolvePath(state.config, configProp)}`);
    setPath(state, stateName, resolvePath(state.config, configProp)); // config file overrides default
  } else {
    logger.info(`Using default parameter: - ${stateName}, ${resolvePath(state, stateName)}`);
  }
}
// returns config object, read synchronously
// if exception, logs and exit process
// if file extension is yaml loads as yaml, else as json
// Also sets state.verbose and state.debugMode if specified in command-line or config-file
function readConfig() {

// Note - one cannot override the config file in the config file
  if (commander.config) {
    logger.info(`Using command line parameter - config ${commander.config}`);
    state.configFile = commander.config;
  } else {
    logger.info(`default parameter - config ${state.configFile}`);
  }
  // Read the configuration file (yaml or json) -> state.config
  try {
    // read the file and parse it as JSON then don't need './filename.json', can just specify 'filename.json'
    const configText = fs.readFileSync(state.configFile, 'utf8');
    if (path.extname(state.configFile) === '.yaml') {
      state.config = jsYaml.safeLoad(configText);
    } else {
      state.config = JSON.parse(configText);
    }

    processConfigItem('verbose');
    if (state.verbose) {
      logger.info(JSON.stringify(state.config, null, '  '));
    }
    processConfigItem('debugMode', 'debug', 'debug');

    return state.config;
  } catch (ex1) {
    logger.info(`Exception loading config file "${state.configFile}": ${ex1}`);
    logger.error('Exiting...');
    process.exit(1);
  }
}
//
function setProtoHostPort(x) {
  // so can reference common.protoHostPort
  module.exports.protoHostPort = x;
  protoHostPort = x;
}
function getProtoHostPort() {
  return protoHostPort;
}
//
function getPing() {
  return new Promise((fulfill, reject) => {
    const url = `${protoHostPort}/api/ping`;
    request(url).then((body) => {
      logger.info(body);
      fulfill(body); //
    }, (err) => {
      reject(err);
    });
  });
}
//
function getAuthenticate() {
  return new Promise((fulfill, reject) => {
    request({
      url: `${protoHostPort}/api/authenticate`,
      qs: {
        clientid: state.clientid,
        secret: state.secret
      },
      json: true
    }).then((data) => {
      if (state.verbose) {
        logger.info(data.jwt);
      }
      const pieces = data.jwt.split('.');
      state.jwt = data.jwt;
      state.jwtPayload = JSON.parse(atob(pieces[1]));
      fulfill(state.jwtPayload);
    }, (err) => {
      reject(err);
    });
  });
}
//
function getCustomer(id) {
  return new Promise((fulfill, reject) => {
    request({
      url: `${protoHostPort}/api/customer/${encodeURIComponent(id)}`,
      headers: {
        'Authorization': `Bearer ${state.jwt}`
      },
      json: true
    }).then((customer) => {
      //logger.info(customer);
      fulfill(customer);
    }, (err) => {
      logger.error(`failed to fetch customer ${id}`);
      reject(err);
    });
  });
}
// must call after authenticated (and state.jwt exists
function getAuthClient() {
  if (!state.jwtPayload || !state.jwtPayload.clientid) {
    return Promise.reject('not authenticated as a client');
  }
  return getClient(state.jwtPayload.clientid);
}
//
function getClient(id) {
  return new Promise((fulfill, reject) => {
    request({
      url: `${protoHostPort}/api/client/${encodeURIComponent(id)}`,
      headers: {
        'Authorization': `Bearer ${state.jwt}`
      },
      json: true
    }).then((client) => {
      //logger.info(client);
      fulfill(client);
    }, (err) => {
      logger.error(`failed to fetch client ${id}`);
      reject(err);
    });
  });
}
//
function findCustomerByName(name) {
  return new Promise((fulfill, reject) => {
    request({
      url: `${protoHostPort}/api/customer?name=${encodeURIComponent(name)}`,
      headers: {
        'Authorization': `Bearer ${state.jwt}`
      },
      json: true
    }).then((result) => {
      //logger.info(customer);
      fulfill(result.data[0]);
    }, (err) => {
      logger.error(`failed to fetch customer ${name}`);
      reject(err);
    });
  });
}
//
function findCustomerById(id) {
  return new Promise((fulfill, reject) => {
    request({
      url: `${protoHostPort}/api/customer/${encodeURIComponent(id)}`,
      headers: {
        'Authorization': `Bearer ${state.jwt}`
      },
      json: true
    }).then((customer) => {
      if (state.verbose || state.debugMode) {
        logger.info(JSON.stringify(customer));
      }
      fulfill(customer);
    }, (err) => {
      logger.error(`error attempting to fetch customer ${id}, ${err}`);
      reject(err);
    });
  });
}
//
function get(path) {
  return new Promise((fulfill, reject) => {
    request({
      url: `${protoHostPort}${path}`,
      headers: {
        'Authorization': `Bearer ${state.jwt}`
      },
      json: true
    }).then((result) => {
      if (state.verbose || state.debugMode) {
        logger.info(`GET success: ${JSON.stringify(result).substring(0, 128)}`);
      }
      fulfill(result);
    }, (err) => {
      logger.error(`error attempting to GET ${path}, ${err}`);
      reject(err);
    });
  });
}
//
function deleteCustomerData(customerid, documents) {
  return new Promise((fulfill, reject) => {
    // ensure that all messageType, system, and connection documents with the state.forCustomerId
    // are removed in preparation for adding them wholesale.
    request({
      url: `${protoHostPort}/api/customerDeleteData/${encodeURIComponent(customerid)}`,
      method: 'post',
      headers: {
        'Authorization': `Bearer ${state.jwt}`
      },
      json: true,
      body: documents
    }).then((result) => {
      logger.info(`deleted data for customer ${customerId}, ${JSON.stringify(result)}`);
      fulfill(result);
    }, (err) => {
      logger.error(`failed to delete data for customer ${customerId}, ${err}`);
      reject(err);
    });
  });
}
//
function canCreateCustomer(jwtPayload) {
  return (jwtPayload.clientRoles && jwtPayload.clientRoles['root']) || jwtPayload.clientRoles['createCustomer'];
  // if !jwtPayload.customerId then need user auth TODO
}
// exits if fail to: ping server, authenticatet, fetch customer by id
// fulfills with customer and state updated.
function pingAuthGetCustomer() {
  return new Promise((fulfill, reject) => {
    getPing().then((ping) => {
      logger.success(`Success pinging server ${state.protocol}://${state.hostName}:${state.port}`);

      //
      // next, authenticate this client so we can make further calls
      // Also, after successful authentication each request needs to have the `Authorization: Bearer ${state.jwt}` header
      //
      getAuthenticate().then((jwtPayload) => {
        logger.success(`Success authenticating ${jwtPayload.clientid}`)

        findCustomerById(state.customerid).then((customer) => {
          if (!customer) {
            logger.error(`Could not fetch customer with id ${state.customerid}`);
            process.exit(1);
          }
          state.customer = customer;
          if (state.verbose || state.debug) {
            logger.success(`ran ${Date.now() - started} milliseconds`)
          }
          fulfill(customer);

        }, (err) => {
          logger.error(`Error fetching customer ${state.customerid}, ${err}`);
          process.exit(1);
        });
      }, (err) => {
        logger.error(`error attempting to authenticate with ${state.clientId}, ${err}`);
        process.exit(1);
      });

    }, (err) => {
      logger.error(`Error attempting to ping server ${protoHostPort}, ${err}`);
      process.exit(1);
    });
  });
}
//
function canImportCustomer(jwtPayload, forCustomerId) {
  if (jwtPayload.customerId === forCustomerId) {
    return true; //  customer can import to self
  }
  if (jwtPayload.clientRoles) {
    if (jwtPayload.clientRoles['root']) {
      return true;
    }
    if (jwtPayload.clientRoles['importCustomer']) {
      return true;
    }
  }
  return false;
}
module.exports = {
  setVars: setVars, // call before those below
  resolvePath: resolvePath,
  setPath: setPath,
  processConfigItem: processConfigItem,
  readConfig: readConfig,
  setProtoHostPort: setProtoHostPort, // call before those below
  getProtoHostPort: getProtoHostPort,
  getPing: getPing,
  getAuthenticate: getAuthenticate,
  getCustomer: getCustomer,
  findCustomerByName: findCustomerByName,
  findCustomerById: findCustomerById,
  pingAuthGetCustomer: pingAuthGetCustomer,
  canCreateCustomer: canCreateCustomer,
  canImportCustomer: canImportCustomer,
  getAuthClient: getAuthClient,
  getClient: getClient,
  deleteCustomerData: deleteCustomerData,
  get: get,
  protoHostPort: null,
  started: started
};
