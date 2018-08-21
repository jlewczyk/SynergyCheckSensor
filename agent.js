// This program sits in the middle between the sensors installed on a network and the synergyCheck cloud service.
// It takes data reported by the sensors and combines their data, compresses it, and reports it to the
// synergyCheck.com cloud service.
// It also tracks the health of the sensor's.
// The sensors are programs that monitor the interfaces (tcp/ip traffic and/or file-based)
// The sensor report data more often to the agent than the agent reports to synergyCheck.com

// Auto configuration is the ability to just provide in the config file the following
// agent.agentId
// agent.autoConfigure
// synergyCheck.customerId
// synergyCheck.apiBase
// synergyCheck.apiKeys
//
// after reading configuration file,
// if the agent.autoConfigure is truthy
// then make request to the synergyCheck server for configuration info
// and use the result (is successful) to configure this agent.
//
// The information returned also can be used to auto configure any sensors
// that are autoConfigured.

const express    = require('express');
const http       = require('http');
const https      = require('https');
const RateLimit  = require('express-rate-limit');
const request    = require('request-promise-native');
const mkdirp     = require('mkdirp');
const fs         = require('fs');
const path       = require('path');
const jsYaml     = require('js-yaml')
const swaggerUI  = require('swagger-ui-express');
// manage command line arguments
const commander  = require('commander');

// TO DO - real logger!
const logger = {
  info: function() { console.log.apply(null, arguments); },
  error: function() { console.error.apply(null, arguments); }
};

const app = express();

// todo - logging

let config; // contents of configuration file
let swaggerDocument;

let started = new Date();
// used to generate unique transaction number
// by combining this with the id of the sensor and a counter
const startedMills = started.getTime();
let transactionCounter = 0;

let sensorsAcc = []; // list of sensors supplying daa
let connectionsAcc = []; // accumulating reports from sensors

let priorReport = false; // intiialize to false so recognize first time

const state = {
  release: '0.0.1',
  autoConfig: false,
  commandLine: {}, // copy of arguments
  configFile: './agent.json',
  autoConfigUrl: undefined,
  httpProtocol: 'http', // protocol (to inform swagger)
  hostName: 'localhost', // name of host listening on (to inform swagger)
  port: 19999, // port to listen to requests from sensors
  lastTransactionId: '',
  synergyCheck: {
    apiBase: 'http://synergyCheck.com/api/v1/'
  },
  swagger: {
    swaggerFile: './swagger/agent.yaml',
  },
  started: started.toISOString(),
  verbose: false,
  debug: false
};

// list of valid top level keys in config file
// todo - add type, required, and deeper paths to validate config oontents
const configKeys = [
    'name', // string
    'port', // 1025 - 49151
    'swagger.swaggerFile', // a yaml file
    'swagger.httpProtocol', // 'http' or 'https'
    'swagger.hostName', // ip4 address, or dns name
    'agent.agentId', // unique id for this agent
    'synergyCheck.apiBase', // for api calls to synergyCheck.com
    'synergyCheck.customerId', // string
    'report.period', // integer >= 0
    'report.compress', // boolean
    'sensors' // array of Sensor objects
    ];
// list of valid arguments in command line
const commanderArgs = [
  'config',
  'swagger',
  'synergyCheck',
  'port',
  'verbose',
  'debug'
];
commander
    .version(state.releaseNumber) // THIS IS WRONG!  IT MAY BE OVERRIDDEN BY config file value
    //.usage('[options] ...')
    .option(`-c, --config [value]`, `The configuration file, overrides "${state.configFile}"`)
    .option(`-a, --auto`, `perform auto configuration from synergyCheck server specified`)
    .option(`-s, --swagger [value]`, `the swagger specification file, overrides "${state.swagger.swaggerFile}"`)
    .option(`-s, --synergyCheck [value]`, `The protocol://host:port/api overrides "${state.synergyCheck.apiBase}"`)
    .option(`-p, --port [value]`, `port the web server is listening on, override default of "${state.port}"`)
    .option(`-b, --verbose`, `output verbose messages for debugging`)
    .option(`-d, --debug`, `output debug messages for debugging`)
    .parse(process.argv);

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
// (state,'swagger.host', 'www.foo.com')
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
  } else if (resolvePath(config, configProp)) {
    logger.info(`Using config file parameter - ${configProp}, ${resolvePath(config, configProp)}`);
    setPath(state, stateName, resolvePath(config, configProp)); // config file overrides default
  } else {
    logger.info(`Using default parameter: - ${stateName}, ${resolvePath(state, stateName)}`);
  }
}
// Copy specified command line arguments into state
commanderArgs.forEach((k) => {
  state.commandLine[k] = commander[k];
});

// Note - one cannot override the config file in the config file
if (commander.config) {
  logger.info(`Using command line parameter - config ${commander.config}`);
  state.configFile = commander.config;
} else {
  logger.info(`default parameter - config ${state.configFile}`);
}
// Read the configuration file
try {
  // read the file and parse it as JSON then don't need './filename.json', can just specify 'filename.json'
  let configText = fs.readFileSync(state.configFile, 'utf8');
  config = JSON.parse(configText);
  // config = require(state.configFile); // using require to synchronously load JSON file parsed directly into an object
} catch (ex1) {
  logger.error(`Cannot load configuration file ${state.configFile}`);
  if (commander.verbose) {
    logger.error(ex1.toString());
  }
  logger.info(`exception loading config file "${state.configFile}": ${ex1}`);
  logger.error('Exiting...');
  process.exit(1);
}

processConfigItem('autoConfig', 'auto');

if (state.autoConfig) {
  ['synergyCheck', 'agent', 'swagger'].forEach(name => {
    if (typeof(config[name]) !== 'object') {
      logger.error(`for autoConfig, missing ${name} object in config file`);
      process.exit(1);
    }
  });
} else {
  ['synergyCheck', 'agent', 'swagger', 'report', 'sensors'].forEach(name => {
    if (typeof(config[name]) !== 'object') {
      logger.error(`for non-autoConfig, missing ${name} object in config file`);
      process.exit(1);
    }
  });
}
processConfigItem('synergyCheck.apiBase', 'synergyCheck');

//------------ validate the properties in the config.agent -------------
//------------------ validate config.agent.agentId ---------------------
if (typeof(config.agent.agentId) === 'undefined') {
  logger.error(`missing agent.agentId in config file`);
  process.exit(1);
}
if (typeof(config.agent.agentId) === 'string' && config.agent.agentId.length === 0) {
  logger.error(`agent.agentId in config file must be a non-empty string string`);
  process.exit(1);
}

//------------ validate the properties in the config.sensors -----------
// todo
if (state.autoConfig) {
  if (typeof(config.sensors) !== 'undefined') {
    logger.info('config.sensors ignored when autoConfig is enabled. It will be auto configured');
  }
}

// Copy original config file values into state.config
state.config = {};
Object.keys(config).forEach((k) => {
  state.config[k] = config[k];
});

//------------ validate the properties in the config.report ------------
if (state.autoConfig) {
  if (typeof(config.report) !== 'undefined') {
    logger.info('config.report ignored when autoConfig is enabled. It will be auto configured');
  }
} else {
  if (typeof(config.report.period) === 'string') {
    if (/^\d+$/.test(config.report.period)) {
      // assume ms
      config.report.period = Number.parseInt(config.report.period);
    } else {
      // todo - recognize '10m', etc.
      logger.error(`report.period is not a positive integer "${config.report.period}"`);
      process.exit(1);
    }
  }
  if (typeof(config.report.period) === 'number') {
    if (config.report.period < 1000) {
      logger.error('cannot accept report.period < 1000 ms');
      process.exit(1);
    }
  }
}

processConfigItem('verbose');
if (state.verbose) {
  logger.info(JSON.stringify(config, null, '  '));
}

processConfigItem('debug');

//------------- web server for swagger docs needs to be self aware ------------
processConfigItem('httpProtocol', false, 'swagger.httpProtocol');
processConfigItem('hostName', false, 'swagger.hostName');
processConfigItem('hostName', false, 'swagger.hostName');

processConfigItem('port');

// Start the app by listening on the default Heroku port
// as port is specified by OS environment variable
state.port = process.env.PORT || state.port;
state.protoHostPort = `${state.httpProtocol}://${state.hostName}:${state.port}`;

if (state.verbose) {
  logger.info(JSON.stringify(state, null, '  '));
}

// Serve only the static files form the dist directory
const distFolder = __dirname + '/dist';
if (!fs.existsSync(distFolder)) {
  logger.error("distribution folder does not exist:" + distFolder);
  process.exit(1);
}
app.use(express.static(distFolder));
app.use(express.json());

//------------- swagger specification document -------------------
processConfigItem('swagger.swaggerFile', 'swagger', 'swagger.swaggerFile');
// when state.port is finalized, can set up to server swagger

function prepareSwagger() {
  try {
    let swaggerText = fs.readFileSync(state.swagger.swaggerFile, 'utf8');
    swaggerText = swaggerText.replace(/___HOST_AND_PORT___/g, state.hostName + ':' + state.port)
        .replace(/___PROTOCOL___/g, state.httpProtocol);
    if (/[.]json$/i.test(state.swagger.swaggerFile)) {
      swaggerDocument = JSON.parse(swaggerText);
    } else {
      swaggerDocument = jsYaml.safeLoad(swaggerText);
    }
  } catch (ex2) {
    logger.error('Cannot load the swagger document ', state.swagger.swaggerFile);
    if (state.verbose) {
      logger.error(ex2.toString());
    }
    logger.error('exiting...');
    process.exit(1);
  }
  // Swagger SPA has its own static resources to be served which are found in the installed package
  app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDocument));
}

//--------------------------- APIs -------------------------------

// is the server up and responding?
app.get('/api/v1/ping', function(req, res) {
  res.status(200).send({
    timestamp: (new Date()).toISOString()
  });
});

// state
app.get('/api/v1/state', function(req, res) {
  res.status(200).send(state);
});

//--------------------- Sensor reporting ---------------------------
// Sensor reports data to this agent
app.post('/api/v1/sensor/report', function (req, res) {
  const errors = [];
  const obj = req.body;
  let sensor;
  let timestampDate;
  let timestampIso;

  if (state.autoConfig && !state.config.sensors) {
    res.status(412).send({ status: 'error', errors: ['agent has not been auto configured'] });
    if (state.debug) {
      logger.error('errors: ' + JSON.stringify(errors, null, '  '));
    }
    return;
  }
  if (obj && typeof(obj.snapshot) === 'object') {
    // de-structure
    let {sensorId, customerId, timestamp, duration, connections} = obj.snapshot;
    if (state.debug) {
      logger.info(JSON.stringify(obj, null, '  '));
    }

    // validate sensorId?
    if (typeof(sensorId) === 'undefined') {
      errors.push('sensorId is required');
    } else {
      sensor = state.config.sensors.find(o => o.sensorId === sensorId)
      if (!sensor) {
        errors.push(`unrecognized sensorId "${sensorId}"`);
      }
    }
    // validate customerId
    if (typeof(customerId) === 'undefined') {
      errors.push('customerId is required');
    } else if (state.config.synergyCheck.customerId !== customerId) {
      errors.push(`unrecognized customerId "${customerId}"`);
    }

    // validate timestamp
    if (typeof(timestamp) === 'undefined') {
      errors.push('timestamp is required');
    } else {
      try {
        timestampDate = new Date(timestamp);
        if (Number.isNaN(timestampDate.getTime())) {
          errors.push(`invalid format for timestamp "${timestamp}"`);
          timestampDate = undefined;
          timestampIso = '?';
        } else {
          // so all the connection timestamps are the same
          timestampIso = timestampDate.toISOString();
        }
      } catch (exDate) {
        errors.push(`invalid format for timestamp "${timestamp}"`);
        timestampDate = undefined;
        timestampIso = '?';
      }
    }

    // validate duration - todo

    // process and validate each connection update in report
    if (connections && connections.length) {
      connections.forEach(ic => { // ic is incoming connection update
        let icId; // connectionId that is a number
        let charCount; // # of characters received in packets over sampling period
        let packetCount; // # of packets received during sampling period
        let connection; // found connection registered with icId

        if (typeof(ic.connectionId) === 'string') {
          if (/^\d+$/.test(ic.connectionId)) {
            icId = Number.parseInt(ic.connectionId);
          } else {
            errors.push(`connectionId not in expected form '${ic.connectionId}'`);
          }
        } else if (typeof(ic.connectionId) === 'number') {
          icId = ic.connectionId;
        } else {
          errors.push(`connectionId must be number "${ic.connectionId}"`)
        }
        if (sensor && typeof(icId) !== 'undefined') {
          connection = sensor.connections.find(c => c.connectionId === icId);
          if (!connection) {
            errors.push(`unregistered connectionId "${icId}"`);
          }
        }

        // process the character count being reported (if any)
        if (typeof(ic.charCount) !== 'undefined') {
          if (typeof(ic.charCount) === 'number') {
            charCount = ic.charCount;
            if (charCount < 0) {
              errors.push(`cannot report negative charCount (${charCount}) for connectionId ${icId}`);
            }
          } else if (typeof(ic.charCount) === 'string') {
            if (/^-\d+$/.test(ic.charCount)) {
              charCount = Number.parseInt(ic.charCount);
              if (charCount < 0) {
                errors.push(`cannot report negative charCount (${charCount}) for connectionId ${icId}`);
              }
            } else {
              errors.push(`expected number or parsable number string, got ${typeof(ic.charCount)} for connectionId ${icId}`);
            }
          } else {
            errors.push(`expected number or parsable number string, got ${typeof(ic.charCount)} for connectionId ${icId}`);
          }
        }

        if (typeof(ic.packetCount) !== 'undefined') {
          if (typeof(ic.packetCount) === 'string') {
            if (/^\d+$/.test(ic.packetCount)) {
              packetCount = Number.parseInt(ic.packetCount);
              if (packetCount < 0) {
                errors.push(`packetCount must be >= 0, ${packetCount}`);
              }
            } else {
              errors.push(`packetCount not expected form '${ic.packetCount}'`);
            }
          } else if (typeof(ic.packetCount) === 'number') {
            packetCount = ic.packetCount;
            if (packetCount < 0) {
              errors.push(`packetCount must be >= 0, ${packetCount}`);
            }
          } else {
            errors.push(`packetCount not expected form '${ic.packetCount}'`);
          }
        }

        if (typeof(ic.disconnected) !== 'undefined') {
          if (typeof(ic.disconnected) !== 'boolean') {
            errors.push(`disconnected if present must be boolean, but it is ${typeof(ic.disconnected)}`);
          }
        }

        if (errors.length === 0) {

          // note the sensor contributing to the next report
          if (sensorsAcc.indexOf(sensorId) === -1) {
            sensorsAcc.push(sensorId);
          }

          let connection = connectionsAcc.find(o => o.connectionId === icId);
          if (connection) {
            if (charCount) {
              // have some volume of data to report
              connection.charCount += charCount;
              connection.lastMessageTimestamp = timestampIso;
            }
            if (packetCount) {
              connection.packetCount += packetCount;
            }
            if (typeof(ic.disconnected) === 'boolean') {
              // sensor reported either true of false (when changed)
              // the last one reported in the reporting period will be passed on
              if (!!connection.disconnected !== ic.disconnected) {
                connection.lastChangeInConnectionTimestamp = timestampIso;
              }
              connection.disconnected = ic.disconnected;
            }
            // connection.timestamps.push(timestampIso);
          } else {
            connectionsAcc.push({
              connectionId: icId,
              charCount: charCount || 0,
              packetCount: packetCount || 0,
              disconnected: ic.disconnected || false,
              // timestamps: [timestampIso],
              lastMessage: ic.charCount ? timestampIso : undefined
            });
          }
        }
      });
      if (errors.length) {
        res.status(412).send({ status: 'errors', errors: errors });
        if (state.debug) {
          logger.error('errors: ' + JSON.stringify(errors, null, '  '));
        }
      } else {
        res.status(200).send({status: 'ok'});
        if (state.debug) {
          logger.info('ok');
        }
      }
    }
  } else {
    res.status(412).send({ status: 'errors', errors: ['no snapshot property']});
    if (state.debug) {
      logger.error('errors: ' + JSON.stringify(errors, null, '  '));
    }
  }
});
// Sensor is reporting that it has started
app.post('/api/v1/sensor/start', function(req, res) {
  res.status(500).send({ status: 'error', errors: ['not implemented']});
});
// Sensor is reporting that it has stopped
app.post('/api/v1/sensor/stop', function(req, res) {
  res.status(500).send({ status: 'error', errors: ['not implemented']});
});
// Can ask agent - what was that last report that was sent?
app.get('/api/v1/sensor/priorReport', function(req, res) {
  res.send(priorReport || {});
});
// Can ask agent for a report on demand, not waiting for next report period
app.get('/api/v1/sensor/nextReport', function(req, res) {
  res.send(getReport());
});
//
app.get('/api/v1/sensor/autoConfig', function(req, res) {
  let errors = [];
  const sensorId = req.query.sensorId;
  const agentId = req.query.agentId;
  const customerId = req.query.customerId;
  logger.info(`/api/v1/sensor/autoConfig?sensorId=${sensorId}&agentId=${agentId}&customerId=${customerId}`);
  // validate customerId
  if (typeof(customerId) === 'undefined') {
    errors.push(`customerId is required`);
  } else if (customerId !== state.config.synergyCheck.customerId) {
    errors.push(`unknown customerId "${customerId}"`);
  }
  // todo - validate agentId specified on startup.
  // assume agent knows its own valid id!
  if (typeof(agentId) === 'undefined') {
    errors.push(`agentId is required`);
  } else if (agentId !== state.config.agent.agentId) {
    errors.push(`unknown agentId "${agentId}"`);
  }

  if (typeof(sensorId) === 'undefined') {
    errors.push(`sensorId is required`);
  } else {
    const sensor = state.config.sensors.find(s => s.sensorId === sensorId);
    if (sensor) {
      res.send({
        sensorId: sensorId,
        agentId: agentId,
        customerId: customerId,
        name: sensor.name,
        version: sensor.version,
        deviceName: sensor.deviceName,
        device: sensor.device,
        sampleRate: sensor.sampleRate,
        connections: sensor.connections
      }); // not found (for now, TODO)
    } else {
      errors.push('sensor not found');
    }
  }
  if (errors.length) {
    res.status(412).send({status: 'error', errors: errors});
  }
});

// start an interval timer to send updates to synergyCheck service in the cloud
function startReporting() {
  let timer = setInterval(function () {
    logger.info(`time to send report! ${new Date().toISOString()}`);
    sendReport();
  }, state.config.report.period);
}

let postReportUrl = `${state.config.synergyCheck.apiBase}agent/report`;
logger.info(`report to url: ${postReportUrl}`);

function sendReport() {
  let theReport = getReport();
  request({
    method: 'POST',
    uri: postReportUrl,
    body: theReport,
    json: true // automatically stringifies body
  }).then(obj => {
    logger.info(JSON.stringify(obj));
  }).catch(err => {
    logger.error(err);
  });
  if (state.verbose) {
    logger.info(JSON.stringify(theReport, null, '  '));
  }
  // remember what you just sent
  priorReport = theReport;

}
// return object containing body of post request to be sent to SynergyCheck.com server
function getReport() {
  // generate unique transaction number
  // by combining this with the id of the sensor and a counter
  transactionCounter++;
  let transactionId = `${state.config.agent.agentId}|${startedMills}|${transactionCounter}`
  state.lastTransactionId = transactionId;

  const snapshot = {
    customerId: state.config.synergyCheck.customerId,
    agentId: state.config.agent.agentId,
    transactionId: transactionId,
    timestamp: new Date().toISOString(),
    duration: state.config.report.period,
    sensors: sensorsAcc.slice(0),
    connections: connectionsAcc.map(o => {
      return {
        connectionId: o.connectionId,
        charCount: o.charCount || 0,
        packetCount: o.packetCount || 0,
        lastMessageTimestamp: o.lastMessageTimestamp,
        disconnected: o.disconnected,
        lastChangeInConnectionTimestamp: o.lastChangeInConnectionTimestamp,
        timestamps: o.timestamps
      };
    })
  };
  connectionsAcc = []; // reset accumulator for next report
  sensorsAcc = [];

  if (state.config.report.compress) {
    // remove reporting those connections with no change from last report
    if (priorReport) {
      snapshot.connections = snapshot.connections.filter(o => {
        if (o.charCount) {
          return true; // always report if has messages
        }
        // no messages, check if change in disconnected? status
        if (typeof(o.disconnected) !== 'undefined') {
          // we have a value for disconnected
          let connectionPrior = priorReport.connections.find(c => c.connectionId === o.connectionId);
          if (connectionPrior) {
            return connectionPrior.disconnected !== o.disconnected;
          }
          // we had no value prior
          return true;
        }
        // no value for disconnected, so no change assumed from last report
        return false;
      });
    }
  }
  return snapshot;
}

if (state.autoConfig) {
  const errors = [];
  state.autoConfigUrl = `${state.config.synergyCheck.apiBase}agent/autoConfig`;
  request({
    method: 'GET',
    uri: state.autoConfigUrl,
    qs: {
      customerId: state.config.synergyCheck.customerId,
      agentId: state.config.agent.agentId
    },
    json: true // parse body
  }).then(obj => {
    if (state.debug || state.verbose) {
      logger.info(`autoConfig data is ${JSON.stringify(obj, null, '  ')}`);
    }
    // todo - validate configuration data and incorporate
    if (obj.customerId !== state.config.synergyCheck.customerId) {
      errors.push(`expected customerId to be ${state.config.synergyCheck.customerId} but received ${obj.customerId}`);
    }
    if (obj.agentId !== state.config.agent.agentId) {
      errors.push(`expected agentId to be ${state.config.agent.agentId} but received ${obj.agentid}`);
    }

    if (errors.length === 0) {

      state.port = obj.port; // todo - validate
      state.protoHostPort = `${state.httpProtocol}://${state.hostName}:${state.port}`;

      state.config.report = obj.report; // todo - validate
      state.config.sensors = obj.sensors; // todo - validate

      prepareSwagger(); // we have state.port
      startListening();
      startReporting();
    }
    if (errors.length) {
      logger.error(`Errors detected on incoming data from ${state.autoConfigUrl}`);
      errors.forEach(e => { logger.error(e); });
    }

  }).catch(err => {
    logger.error(`error on GET ${state.autoConfigUrl}, err=${err}`);
  });
  if (state.verbose) {
    logger.info(`auto configuration call GET ${state.autoConfigUrl}`);
  }
}
if (state.autoConfig) {
  if (state.debug || state.verbose) {
    logger.info('autoConfig, so server not started until it received valid configuration');
  }
} else {
  prepareSwagger(); // we have state.port
  startListening();
  startReporting();
}

function startListening() {
  app.listen(state.port);
  logger.info(`Server listening on port ${state.port}`);
  logger.info(`swagger api docs available at ${state.protoHostPort}/api-docs`);
  logger.info(`service api docs available at ${state.protoHostPort}/api/*`);
}


