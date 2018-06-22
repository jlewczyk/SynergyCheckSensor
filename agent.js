// This program sits in the middle between the sensors installed on a network and the synergyCheck cloud service.
// It takes data reported by the sensors and combines their data, compresses it, and reports it to the
// synergyCheck.com cloud service.
// It also tracks the health of the sensor's.
// The sensors are programs that monitor the interfaces (tcp/ip traffic and/or file-based)
// The sensor report data more often to the agent than the agent reports to synergyCheck.com

const express    = require('express');
const http       = require('http');
const https      = require('https');
const RateLimit  = require('express-rate-limit');
const request    = require('request');
const mkdirp     = require('mkdirp');
const fs         = require('fs');
const path       = require('path');
const jsYaml     = require('js-yaml')
const swaggerUI  = require('swagger-ui-express');
// manage command line arguments
const commander  = require('commander');

// TO DO - real logger!
const logger = {
  info: function(x) { console.log.apply(arguments); },
  error: function(x) { console.error.apply(arguments); }
};

const app = express();

// todo - logging
// api's
// /api/v1/sensor/start
// /api/v1/sensor/stop
// /api/v1/sensor/heartbeat
// /api/v1/sensor/report

const state = {
  release: '0.0.1',
  commandLine: {},
  configFile: './agent.json',
  hostName: 'localhost', // name of host listening on (to inform swagger)
  httpProtocol: 'http', // protocol (to inform swagger)
  port: 19999, // port to listen to requests from sensors
  synergyCheck: 'http://synergyCheck.com/api/v1/',
  swaggerFile: './swagger/swagger.yaml',
  commandLine: {}, // copy of arguments
  verbose: false,
  debug: false
};

let config; // contents of configuration file
let swaggerDocument;

let connectionsAcc = []; // accumulating reports from sensors

let priorReport = false; // intiialize to false so recognize first time

// list of valid top level keys in config file
// todo - add type, required, and deeper paths to validate config oontents
const configKeys = [
    'name', // string
    'httpProtocol', // 'http' or 'https'
    'hostName', // ip4 address, or dns name
    'port', // 1025 - 49151
    'synergyCheck.api', // guid
    'customerId', // string
    'report.period', // integer >= 0
    'report.compress', // boolean
    'sensors' // array of Sensor object
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
    .option('-c, --config [value]', 'The configuration file, overrides "' + state.configFile + '"')
    .option('-s, --swagger [value]', 'the swagger specification, overrides "' + state.swaggerFile + '"')
    .option('-s, --synergyCheck [value]','The protocol://host:port/api overrides "' + state.synegyCheck + '"')
    .option('-p, --port [value]', 'port the web server is listening on, override default of 80 or 443 depending on http or https')
    .option('-b, --verbose', 'output verbose messages for debugging')
    .option('-d, --debug', 'output debug messages for debugging')
    .parse(process.argv);

// @param name - the name of the item in the state object
// @param commanderProp - the optional commander (command line) argument name if different from name
// #param configProp - optional configuration file prop name if different from name
// Note - can be used for item that is not available on the command line, pass false for commanderProp
function processConfigItem(name, commanderProp, configProp) {
  if (!commanderProp && commanderProp !== false) {
    commanderProp = name;
  }
  if (!configProp) {
    configProp = name;
  }
  if (commanderProp !== false && commander[commanderProp]) {
    logger.info(`Using command line parameter - ${commanderProp}, ${commander[commanderProp]}`);
    state[name] = commander[commanderProp]; // command line overrides default
  } else if (config[configProp]) {
    logger.info(`Using config file parameter - ${configProp}, ${config[configProp]}`);
    state[name] = config[configProp]; // config file overrides default
  } else {
    logger.info(`Using default parameter: - ${name}, ${state[name]}`);
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
// Read the configuraton file
try {
  // read the file and parse it as JSON then don't need './filename.json', can just specify 'filename.json'
  let configText = fs.readFileSync(state.configFile, 'utf8');
  config = JSON.parse(configText);
  // config = require(state.configFile); // using require to synchronously load JSON file parsed directly into an object

  // validate TODO
  if (typeof(config.report) !== 'object') {
    config.report = { compress: false, period: 10000 };
  } else {
    config.report.compress = !!config.report.compress;
    config.report.period = config.report.period || 10000;
  }

  // Copy original config file values into state.config
  state.config = {};
  Object.keys(config).forEach((k) => {
    state.config[k] = config[k];
  });
  processConfigItem('verbose');
  if (state.verbose) {
    logger.info(JSON.stringify(config, null, '  '));
  }
} catch (ex1) {
  logger.error(`Cannot load configuration file ${state.configFile}`);
  if (commander.verbose) {
    logger.error(ex1.toString());
  }
  logger.info(`exception loading config file "${state.configFile}": ${ex1}`);
  logger.error('Exiting...');
  process.exit(1);
}

processConfigItem('debug', 'debug', 'debug');

//------------- web server port number -------------------
processConfigItem('httpProtocol');
processConfigItem('hostName');
processConfigItem('port');

const port = process.env.PORT || state.port;
state.protoHostPort = `${state.httpProtocol}://${state.hostName}:${port}`;

//------------- swagger specification document -------------------
processConfigItem('swaggerFile', 'swagger', 'swagger');
try {
  let yamlText = fs.readFileSync(state.swaggerFile, 'utf8');
  yamlText = yamlText.replace(/___HOST_AND_PORT___/g, state.hostName + ':' + state.port)
      .replace(/___PROTOCOL___/g, state.httpProtocol);
  swaggerDocument = jsYaml.safeLoad(yamlText);
} catch (ex2) {
  logger.error('Cannot load the swagger document ', state.swaggerFile);
  if (state.verbose) {
    logger.error(ex2.toString());
  }
  logger.error('exiting...');
  process.exit(1);
}

console.log(JSON.stringify(state, null, '  '));

// Serve only the static files form the dist directory
const distFolder = __dirname + '/dist';
if (!fs.existsSync(distFolder)) {
  console.error("distribution folder does not exist:" + distFolder);
  process.exit(1);
}
app.use(express.static(distFolder));
app.use(express.json());

// Swagger SPA has its own static resources to be served which are found in the installed package
app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDocument));

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
// Sensor reports data
app.post('/api/v1/sensor/report', function (req, res) {
  const errors = [];
  const obj = req.body;
  let sensor;
  let date;
  let timestampDate;
  let isoTimestamp;

  if (obj && typeof(obj.snapshot) === 'object') {
    // de-structure
    let {sensorId, customerId, timestamp, duration, connections} = obj.snapshot;
    console.log(`sensorId=${sensorId}`);
    console.log(`customerId=${customerId}`);
    console.log(`timestamp=${timestamp}`);
    console.log(`duration=${duration}`);

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
    } else if (state.config.customerId !== customerId) {
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
        } else {
          // so all the connection timestamps are the same
          isoTimestamp = timestampDate.toISOString();
        }
      } catch (exDate) {
        errors.push(`invalid format for timestamp "${timestamp}"`);
        timestampDate = undefined;
      }
    }

    // validate duration

    // process and validate each connection update in report
    if (connections && connections.length) {
      connections.forEach(ic => {
        let icId = '' + ic.connectionId; // ensure its a string (guids are string, but we may use >0 integers)
        let charCount;
        if (!/^\d+$/.test(icId)) {
          errors.push(`connectionId not expected form '${icId}'`);
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
        if (typeof(ic.disconnected) !== 'undefined') {
          if (typeof(ic.disconnected) !== 'boolean') {
            errors.push(`disconnected if present must be boolean, but it is ${typeof(ic.disconnected)}`);
          }
        }

        if (errors.length === 0) {
          let connection = connectionsAcc.find(o => o.connectionId === icId);
          if (connection) {
            if (charCount) {
              // have some volume of data to report
              connection.charCount += charCount;
              connection.lastMessageTimestamp = isoTimestamp;
            }
            if (typeof(ic.disconnected) === 'boolean') {
              // sensor reported either true of false (when changed)
              // the last one reported in the reporting period will be passed on
              if (!!connection.disconnected !== ic.disconnected) {
                connection.lastChangeInConnectionTimestamp = isoTimestamp;
              }
              connection.disconnected = ic.disconnected;
            }
            connection.timestamps.push(isoTimestamp);
          } else {
            connectionsAcc.push({
              connectionId: icId,
              charCount: ic.charCount || 0,
              disconnected: ic.disconnected || false,
              timestamps: [isoTimestamp],
              lastMessage: ic.charCount ? isoTimestamp : undefined
            });
          }
          res.status(200).send({ status: 'ok'});
        } else {
          res.status(412).send({ status: 'errors', errors: errors });
        }
      });
    }
  } else {
    res.status(412).send({ status: 'errors', errors: ['no snapshot property']});
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
app.get('/api/v1/sensor/priorReport', function(req, res) {
  res.send(priorReport || {});
});
app.get('/api/v1/sensor/nextReport', function(req, res) {
  res.send(getReport());
});
// return object containing body of post request to be sent to SynergyCheck.com server
function getReport() {
  const snapshot = {
    customerId: state.config.customerId,
    timestamp: new Date().toISOString(),
    duration: state.config.report.period,
    connections: connectionsAcc.map(o => {
      return {
        connectionId: o.connectionId,
        charCount: o.charCount || 0,
        lastMessageTimestamp: o.lastMessageTimestamp,
        disconnected: o.disconnected,
        lastChangeInConnectionTimestamp: o.lastChangeInConnectionTimestamp,
        timestamps: o.timestamps
      };
    })
  };
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
// Start the app by listening on the default Heroku port
app.listen(port);

console.log(`Server listening on port ${port}`);
console.log(`swagger api docs available at ${state.protoHostPort}/api-docs`);
console.log(`service api docs available at ${state.protoHostPort}/api/*`);


