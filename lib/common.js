// common functions and values for utilities

const fs      = require('fs');
const path    = require('path');
const jsYaml = require('js-yaml');
const request = require('request-promise-native');
const atob    = require('atob');

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
}
//
function getLogger() {
  return logger;
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
    if (!state.quiet) {
      logger.info(`Using command line parameter - ${commanderProp}, ${commander[commanderProp]}`);
    }
    setPath(state, stateName, commander[commanderProp]); // command line overrides default
  } else if (typeof(resolvePath(state.config, configProp)) !== 'undefined') {
    if (!state.quiet) {
      logger.info(`Using config file parameter - ${configProp}, ${resolvePath(state.config, configProp)}`);
    }
    setPath(state, stateName, resolvePath(state.config, configProp)); // config file overrides default
  } else {
    if (!state.quiet) {
      logger.info(`Using default parameter: - ${stateName}, ${resolvePath(state, stateName)}`);
    }
  }
}
// returns config object, read synchronously
// if exception, logs and exit process
// if file extension is yaml loads as yaml, else as json
function readConfig() {

// Note - one cannot override the config file in the config file
  if (commander.config) {
    if (!state.quiet) {
      logger.info(`Using command line parameter - config ${commander.config}`);
    }
    state.configFile = commander.config;
  } else {
    if (!state.quiet) {
      logger.info(`default parameter - config ${state.configFile}`);
    }
  }
  // Read the configuration file -> state.config
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
// @return promise with jwt payload, also sets state.synergyCheck.jwt and state.synergyCheck.jwtPayload
function getAuthenticate() {
  return new Promise((fulfill, reject) => {
    request({
      url: `${protoHostPort}/api/authenticate`,
      qs: {
        clientid: state.synergyCheck.clientid,
        secret: state.synergyCheck.secret
      },
      json: true
    }).then((data) => {
      if (state.verbose) {
        logger.info(data.jwt);
      }
      const pieces = data.jwt.split('.');
      state.synergyCheck.jwt = data.jwt;
      state.synergyCheck.jwtPayload = JSON.parse(atob(pieces[1]));
      fulfill(state.synergyCheck.jwtPayload);
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
        'Authorization': `Bearer ${state.synergyCheck.jwt}`
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
// must call after authenticated (and state.synergyCheck.jwt exists)
function getAuthClient() {
  if (!state.synergyCheck.jwtPayload || !state.synergyCheck.jwtPayload.clientid) {
    return Promise.reject('not authenticated as a client');
  }
  return getClient(state.synergyCheck.jwtPayload.clientid);
}
//
function getClient(id) {
  return new Promise((fulfill, reject) => {
    request({
      url: `${protoHostPort}/api/client/${encodeURIComponent(id)}`,
      headers: {
        'Authorization': `Bearer ${state.synergyCheck.jwt}`
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
module.exports = {
  setVars: setVars, // call before those below
  resolvePath: resolvePath,
  setPath: setPath,
  getLogger: getLogger,
  processConfigItem: processConfigItem,
  readConfig: readConfig,
  setProtoHostPort: setProtoHostPort, // call before those below
  getProtoHostPort: getProtoHostPort,
  getPing: getPing,
  getAuthenticate: getAuthenticate,
  getCustomer: getCustomer,
  getAuthClient: getAuthClient,
  getClient: getClient
};
