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
  info: function(x) { console.log(x); },
  error: function(x) { console.error(x); }
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
try {
  // todo - alternate is to read the file and parse it as JSON then don't need './filename.json', can just specify 'filename.json'
  config = require(state.configFile); // using require to synchronously load JSON file parsed directly into an object
  // Copy original config file values into state
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
  logger.info('Since we use require to load the file, if a local file, prefix with "./"');
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

// Sensor reports data
app.post('/api/v1/sensor/report', function (req, res) {
  const errors = [];
  const obj = req.body;
  if (obj && typeof(obj.snapshot) === 'object') {
    const snapshot = obj.snapshot;
    let {customerId, timestamp, duration, connections} = obj.snapshot;
    console.log(`customerId=${customerId}`);
    console.log(`timestamp=${timestamp}`);
    console.log(`duration=${duration}`);
    if (connections && connections.length) {
      connections.forEach(ic => {
        let icId = '' + ic.connectionId; // ensure its a string
        let charCount;
        if (!/^\d+$/.test(icId)) {
          errors.push(`connectionId not expected form '${icId}'`);
        }
        // process the character count being reported (if any)
        if (typeof(ic.charCount) !== 'undefined') {
          if (typeof(ic.charCount) === 'number') {
            charCount = ic.char;
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
            }
            if (typeof(ic.disconnected) === 'boolean') {
              // sensor reported either true of false (when changed)
              // the last one reported in the reporting period will be passed on
              connection.disconnected = ic.disconnected;
            }
          } else {
            connectionsAcc.push({
              connectionId: icId,
              charCount: ic.charCount || 0,
              disconnected: ic.disconnected || false
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

// Start the app by listening on the default Heroku port
app.listen(port);

console.log(`Server listening on port ${port}`);
console.log(`swagger api docs available at ${state.protoHostPort}/api-docs`);
console.log(`service api docs available at ${state.protoHostPort}/api/*`);


