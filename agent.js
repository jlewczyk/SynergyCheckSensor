// This program sits in the middle between the sensors installed on a network and the synergyCheck cloud service.
// It takes data reported by the sensors and combines their data, compresses it, and reports it to the
// synergyCheck.com cloud service.
// It also tracks the health of the sensor's.
// The sensors are programs that monitor the connections (tcp/ip traffic and/or file-based)
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
const swaggerTools = require('swagger-tools');
const commander  = require('commander'); // manage command line arguments
const colors     = require('colors');
const durationParser = require('duration-parser');
const commonLib   = require('./lib/common');
const agentRoutes = require('./lib/controllers/agentRoutes');

// TO DO - real logger!
const logger = {
  info: function () {
    console.info.apply(null, Array.from(arguments).map(a => colors.white(a)));
  },
  error: function () {
    console.error.apply(null, Array.from(arguments).map(a => colors.red(a)));
  },
  warning: function() {
    console.log.apply(null, Array.from(arguments).map(a => colors.yellow(a)));
  },
  success: function() {
    console.log.apply(null, Array.from(arguments).map(a => colors.green(a)));
  },
  verbose: function() {
    if (state.verbose || state.debugMode) {
      console.log.apply(null, Array.from(arguments).map(a => colors.gray(a)));
    }
  },
  debug: function() {
    if (state.debugMode) {
      console.log.apply(null, Array.from(arguments).map(a => colors.gray(a)));
    }
  }
};
logger.warn = logger.warning; // compatibility

const app = express();

let config; // contents of configuration file
let swaggerDocument;

let started = new Date();
// used to generate unique transaction number
// by combining this with the id of the sensor and a counter
const startedMills = started.getTime();
// let transactionCounter = 0;

let priorReport = false; // intiialize to false so recognize first time

const state = {
  release: '0.1.0',
  autoConfig: false,
  noauth: false, // default to requiring valid authorization token to be supplied on webapi calls
  commandLine: {}, // copy of arguments
  configFile: './agent.yaml',
  config: undefined, // set when config file read
  startedMills: startedMills,
  pingPeriod: 10000,
  autoConfigUrl: undefined, // set when autoConfig executed
  recentConfig : {}, // timestamp and version of most recent autoConfig
  newAutoConfig: undefined, // received from server as response to POST agentReport

  // agent is a server, this specified how and where it is listening
  httpProtocol: 'http', // protocol (to inform swagger)
  hostName: 'localhost', // name of host listening on (to inform swagger)
  port: 19999, // port to listen to requests from sensors

  // for generating reports to SynergyCheck
  lastTransactionId: '',
  noAuth: false, // disable check for apiKey in requests from agent/swagger
  synergyCheck: { // autoConfig or explcit in config file
    protocol: 'http',
    hostName: 'localHost',
    port: 8080,
    apiBase: '/api/v1/',
    apiKeys: [], // from config file
    weakSSL: false // see --weakSSl
  },
  agent: {}, // autoConfig or explcit in config file
  swagger: {  // autoConfig or explcit in config file
    swaggerFile: './swagger/agent.yaml',
  },
  server: {}, // from autoConfig - synergyCheck thinks this is this agent's server config
  report: {
    autoReport: true,
    period: 60000,
    dur: '60s', // 60 second default
    compress: true // true means leave out configured interfaces that have not reported
  }, // autoConfig or explicit in config file
  sensors: [], // most recent configuration of each sensor - from autoConfig or explicit in config file on startup
  sensorStats: {}, // by sensorId
  started: started.toISOString(),
  sensorsAccum: [], // list of sensors supplying data accumulated for next report to synergyCheck
  connectionsAccum: [], // list of connections reported by sensors accumulated for current report period
  transactionCounter: 0, // incremented for each report to synergyCheck and included in its tx
  agentReports: {
    sent: 0,
    errors: 0,
    retries: 0,
    maxRetries: 10,
    sendDelay: 10000
  },
  memory: '?', // approx memory consumed by this agent process
  agentReportQueue: [],
  verbose: false,
  debug: false
};

// list of valid top level keys in config file
// todo - add type, required, and deeper paths to validate config oontents
const configKeys = [
    'name', // string
    'protocol',
    'hostName',
    'port', // 1025 - 49151
    'noAuth',
    'swagger.swaggerFile', // a yaml file
    'swagger.httpProtocol', // 'http' or 'https'
    'swagger.hostName', // ip4 address, or dns name
    //'swagger.post', // got to be same as port above
    'agent.agentId', // unique id for this agent
    'synergyCheck.protocol',
    'synergyCheck.hostName',
    'synergyCheck.port',
    'synergyCheck.apiBase', // for api calls to synergyCheck.com
    'synergyCheck.customerId', // string
    'synergyCheck.apiKeys', // array of keys
    'synergyCheck.weakSSL', //if specified and truthy, then does not require valid TLS certs
    'report.period', // duration or mills
    'report.compress', // boolean
    'sensors' // array of Sensor objects
  ];
// list of valid arguments in command line
const commanderArgs = [
  'config',
  'auto',
  'swagger',
  'port',
  'autoReport',
  'noauth',
  'weakSSL',
  'verbose',
  'debug'
];
commander
    .version(state.releaseNumber) // THIS IS WRONG!  IT MAY BE OVERRIDDEN BY config file value
    //.usage('[options] ...')
    .option(`-c, --config [value]`, `The configuration file, overrides "${state.configFile}"`)
    .option(`-a, --auto`, `perform auto configuration from synergyCheck server specified`)
    .option(`-s, --swagger [value]`, `the swagger specification file, overrides "${state.swagger.swaggerFile}"`)
    .option(`-p, --port [value]`, `port the web server is listening on, override default of "${state.port}"`)
    .option(`-a, --autoReport [value]`, `automatically start agentReports true/false, overrides default of ${state.report.autoReport}`)
    .option(`-n, --noauth`, `authorization apikey not required (not recommended for production`)
    .option('-w, --weakSSL', 'The tls certificate need not be valid, overrides ' + state.synergyCheck.weakSSL + '"')    .option(`-b, --verbose`, `output verbose messages for debugging`)
    .option(`-d, --debug`, `output debug messages for debugging`)
    .parse(process.argv);


commonLib.setVars(commander, logger, state);
commonLib.readConfig();
const processConfigItem = commonLib.processConfigItem;
const resolvePath = commonLib.resolvePath;
const setPath = commonLib.setPath;

agentRoutes.init(state);

// Copy specified command line arguments into state
commanderArgs.forEach((k) => {
  if (commander[k] !== undefined) {
    state.commandLine[k] = commander[k];
  }
});

processConfigItem('autoConfig', 'auto');

const errors = [];
// Need to copy select set of properties in config.* to state.*
if (state.autoConfig) {
  ['synergyCheck', 'agent', 'swagger'].forEach(name => {
    if (typeof(state.config[name]) !== 'object') {
      errors.push(`for autoConfig, missing ${name} object in config file`);
    } else {
      Object.assign(state[name], state.config[name]);
    }
  });
} else {
  ['synergyCheck', 'agent', 'swagger', 'report', 'sensors'].forEach(name => {
    if (typeof(state.config[name]) !== 'object') {
      errors.push(`for non-autoConfig, missing ${name} object in config file`);
    } else {
      Object.assign(state[name], state.config[name]);
    }
  });
}
processConfigItem('noauth', 'noauth', 'noauth');
processConfigItem('synergyCheck.weakSSL', 'weakSSL', 'synergyCheck.weakSSL');

if (!state.synergyCheck.httpProtocol) {
  errors.push(`Missing state.synergyCheck.httpProtocol property`);
}
if (!state.synergyCheck.hostName) {
  errors.push(`Missing state.synergyCheck.hostName property`);
}
if (!state.synergyCheck.port) {
  errors.push(`Missing state.synergyCheck.port property`);
}
if (!state.synergyCheck.apiBase) {
  errors.push(`Missing state.synergyCheck.apiBase property`);
}
if (!state.synergyCheck.apiKeys) {
  errors.push(`Missing state.synergyCheck.apiKeys property`);
}
// Setup for communicating with SynergyCheck - ping, authenticate, autoConfig, post agentReports,...
commonLib.setProtoHostPort(`${state.synergyCheck.httpProtocol || 'http'}://${state.synergyCheck.hostName}:${state.synergyCheck.port || 80}`);

//------------ validate the properties in the state.agent -------------
//------------------ validate state.agent.agentId ---------------------
if (typeof(state.agent.agentId) === 'undefined') {
  errors.push(`missing agent.agentId`);
}
if (typeof(state.agent.agentId) === 'string' && state.agent.agentId.length === 0) {
  errors.push(`agent.agentId in config file must be a non-empty string string`);
}

//------------ validate the properties in the state.sensors -----------
// todo
if (state.autoConfig) {
  if (typeof(state.config.sensors) !== 'undefined' && state.config.sensors.length) {
    logger.info('state.sensors ignored when autoConfig is enabled. It will be auto configured');
  }
}

//------------ validate the properties in the config.report ------------
if (state.autoConfig) {
  if (typeof(state.config.report) !== 'undefined' && Object.keys(state.config.report).length) {
    logger.info('state.report properties may be overriden when autoConfig is enabled. It will be auto configured');
  }
} else {
  processReportingPeriod(errors);
}
function processReportingPeriod(errors) {
  if (typeof(state.report.period) === 'string') {
    state.report.period = durationParser(state.report.period);
    if (state.report.period <= 0) {
      errors.push(`report.period is not a positive integer "${config.report.period}"`);
    }
  }
  if (Number.isNaN(+state.report.period)) {
    errors.push('cannot accept report.period is not a number');
  }
  if (state.report.period < 1000) {
    errors.push('cannot accept report.period < 1000 ms');
  }
  // This will be in the agentReport, which needs a string
  state.report.dur = `${Math.floor(state.report.period / 1000)}s`; // e.g. '60s'
}

processConfigItem('report.autoReport', 'autoReport', 'report.autoReport');
if (typeof(state.report.autoReport) === 'string') {
  // configured from command line
  state.report.autoReport = (state.report.autoReport.toLowerCase === 'true' ? true : state.report.autoReport.toLowerCase() === 'false' ? false : undefined);
  if (state.report.autoReport == undefined) {
    errors.push(`Expected autoReport to be true or false, but you specified ${state.report.autoReport}`);
  }
}
if (typeof(state.report.autoReport) !== 'boolean') {
  errors.push(`expected report.autoReport to be boolean, it is ${typeof(state.report.autoReport)}`);
}
if (!state.report.autoReport) {
  logger.warning(`Will NOT automatically send agentReports. You need to make web api call to start them`);
}

if (state.config.report && state.config.report.compress !== undefined) {
  state.report.compress = !!state.config.report.compress;
  console.info(`Using config report.compress value of ${state.report.compress}`);
}

if (errors.length) {
  errors.forEach(e => logger.error(e));
  process.exit(1);
}

logger.verbose(JSON.stringify(state, null, '  '));

processConfigItem('debug');

//------------- web server for swagger docs needs to be self aware ------------
processConfigItem('httpProtocol', false, 'swagger.httpProtocol');
processConfigItem('hostName', false, 'swagger.hostName');

processConfigItem('port');

// Start the app by listening on the default Heroku portas port is specified by OS environment variable
// else use the port in the configuration file
state.port = process.env.PORT || state.port;
state.protoHostPort = `${state.httpProtocol || 'http'}://${state.hostName}:${state.port || 80}`;

logger.verbose(`state object...`);
logger.verbose(JSON.stringify(state, null, '  '));

// Serve only the static files form the dist directory for any web site this hosts
const distFolder = __dirname + '/dist';
if (!fs.existsSync(distFolder)) {
  logger.error("distribution folder does not exist:" + distFolder);
  process.exit(1);
}
app.use(express.static(distFolder));
app.use(express.json());
// Most api calls are only usable with a valid shared secret
app.use(function(req, res, next) {
  // auth turned on (default) and accessing api endpoint...
  if (!state.noAuth) {
    if (req.url.indexOf('/api/') !== 0 || req.url === '/api/v1/ping') {
      // ping does not require authorization
      return next();
    }
    // look for api key in either header (or parameter?)
    if (req.headers.authorization) {
      if (req.headers.authorization.toLowerCase().split(' ')[0] === 'bearer') {
        const apiKey = req.headers.authorization.substr(7);
        if (apiKey && state.synergyCheck.apiKeys.includes(req.headers.authorization.substr(7))) {
          // authorized, so on to the next middleware
          logger.debug('authorization check ok');
          return next();
        }
      }
    }
  }
  return res.status(401).send(`unauthorized`);
});

// when state.port is finalized, can set up to server swagger
//------------- swagger specification document -------------------
processConfigItem('swagger.swaggerFile', 'swagger', 'swagger.swaggerFile');
try {
  let yamlText = fs.readFileSync(state.swagger.swaggerFile, 'utf8');
  state.swagger.httpProtocol = state.swagger.httpProtocol || state.httpProtocol;
  state.swagger.hostName = state.swagger.hostName || state.hostName;
  state.swagger.port = state.swagger.port || state.port;
  logger.info(`building swagger to request on ${state.swagger.httpProtocol}://${state.swagger.hostName}:${state.swagger.port}`);
  yamlText = yamlText.replace(/___HOST_AND_PORT___/g, state.swagger.hostName + ':' + state.swagger.port)
    .replace(/https #___PROTOCOL___/, state.swagger.httpProtocol);
  swaggerDocument = jsYaml.safeLoad(yamlText);

  // write out the resulting text to a file so it can be read by other tools
  let newFile = `${path.dirname(state.swagger.swaggerFile)}${path.sep}resolved.${path.basename(state.swagger.swaggerFile)}`;
  fs.writeFileSync(newFile, yamlText, 'utf8');

} catch (ex2) {
  logger.error('Cannot load the swagger document ', state.swagger.swaggerFile);
  logger.error(ex2.toString());
  logger.error('exiting...');
  process.exit(1);
}
// logger.debug(swaggerDocument);

//------------------- Swagger SPA -----------------------
// usage: initializeSwagger(app, swaggerDocument).then(() => { ; });
function initializeSwagger(app, swaggerDoc) {

  // Initialize the Swagger middleware
  // debugging mode is set with environment variable
  // https://github.com/apigee-127/swagger-tools/blob/master/docs/Middleware.md
  //   c:\synergyCheck\synergy-check>set DEBUG
  //    DEBUG=swagger-tools:middleware:*

  return new Promise((fulfill, reject) => {
    if (state.oldSwagger) {
      const swaggerUI = require('swagger-ui-express');
      // Swagger SPA has its own static resources to be served which are found in the installed package
      app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDocument));
      fulfill();
    } else {
      // swaggerRouter configuration
      const optionsRouter = {
        controllers: './lib/controllers',
        useStubs: false
        //useStubs: process.env.NODE_ENV === 'development' ? true : false // Conditionally turn on stubs (mock mode)
      };
      swaggerTools.initializeMiddleware(swaggerDoc, (middleware) => {
        // Interpret Swagger resources and attach metadata to request - must be first in swagger-tools middleware chain
        app.use(middleware.swaggerMetadata());

        // Validate Swagger requests
        app.use(middleware.swaggerValidator());

        // Route validated requests to appropriate controller
        app.use(middleware.swaggerRouter(optionsRouter));
        //------------------- Errors trapped ----------------------------
        app.use(function (err, req, res, next) {
          if (err.failedValidation) {
            res.status(422).send({ error: 'failed validation', code: err.code, details: err});
          } else {
            res.status(422, err);
          }
        });

        // Serve the Swagger documents and Swagger UI
        app.use(middleware.swaggerUi({
          swaggerUi: '/api-docs',
          apiDocs: '/docs'
        }));

        fulfill();
      });
    }
  });
}
// Initial contact with agent is via the *unauthenticated* ping call
// Continue to attempt ping until agent answers, waiting state.pingPeriod millis
// @return promise fulfilled when ping successful
// never calls reject, so will attempt to ping forever
function attemptSynergyCheckPing() {
  return new Promise((fulfill, reject) => {
    function tryOnePing() {
      makeSynergyCheckPingRequest().then(result => {
        // success
        logger.success(`success pinging SynergyCheck at ${state.pingUrl}`);
        fulfill(result);
      }, err => {
        logger.warning(`fail to ping SynergyCheck ${state.pingUrl}, ${err}.  Will try again in ${state.pingPeriod || 30000} millis...`);
        setTimeout(() => {
          // try again
          tryOnePing();
        }, state.pingPeriod || 10000);
      });
    }
    tryOnePing();
  });
}
// @return a promise
function makeSynergyCheckPingRequest() {
  state.pingUrl =
    `${commonLib.getProtoHostPort()}${state.synergyCheck.apiBase}ping`;
  logger.verbose(`ping SynergyCheck with GET ${state.pingUrl}`);
  return request({
    method: 'GET',
    uri: state.pingUrl,
    json: true
  });
}

// Encapsulate fetch and configuration, so can detect fail and retry
// @return a Promise that is fulfilled when config fetches and succesfully processed
//   and rejected if cannot fetch (e.g. synergyCheck is unavailable) or invalid configuration returned
function performAutoConfig() {
  return new Promise((fulfill, reject) => {
    if (state.debug || state.verbose) {
      logger.verbose('autoConfig specified, so server not started until it received valid configuration');
    }
    state.autoConfigUrl = `${commonLib.getProtoHostPort()}${state.synergyCheck.apiBase}agent/${encodeURIComponent(state.agent.agentId)}/config`;
    logger.verbose(`auto configuration call GET ${state.autoConfigUrl}`);
    request({
      method: 'GET',
      uri: state.autoConfigUrl,
      qs: {
        customerId: state.synergyCheck.customerId
      },
      headers: {
        'Authorization': `Bearer ${state.synergyCheck.jwt}`
      },
      json: true // parse body
    }).then(configObj => {
      processAutoConfig(configObj, false).then(() => {
        // note the values we use to determine if subsequent configObj has new values for sensors
        state.recentConfig = {
          timestamp: configObj.timestamp,
          sensors: (configObj.sensors || []).map(sens => {
            return {
              sensor_id: sens.sensor_id,
              version: sens.version,
              timestamp: sens.timestamp
            }
          })
        };
        fulfill();
      }, err => {
        reject(err);
      });
    }).catch(err => {
      logger.error(`error on GET ${state.autoConfigUrl}, err=${err}`);
      // this could have err.statusCode === 401 for unauthorized
      reject(err);
    });
  });
}
// @param configObj from server
// @param refresh - true if received subsequent to boot
function processAutoConfig(configObj, refresh) {
  return new Promise((fulfill, reject) => {
    logger.verbose(`autoConfig data is ${JSON.stringify(configObj, null, '  ')}`);

    const errors = [];
    if (configObj.customer_id !== state.synergyCheck.customerId) {
      errors.push(`expected customerId to be ${state.synergyCheck.customerId} but received ${configObj.customerId}`);
    }
    if (configObj.agent_id !== state.agent.agentId) {
      errors.push(`expected agentId to be ${state.agent.agentId} but received ${configObj.agentid}`);
    }
    if (configObj.timestamp) {
      // todo - is this newer than what we already have?  If not, can ignore it
      // for use when agent polls server for most recent config so can auto update!
    }
    Object.assign(state.server, configObj.server || {});
    Object.assign(state.report, configObj.report || {}); // todo - validate
    processReportingPeriod(errors);
    Object.assign(state.sensors, configObj.sensors || {}); // todo - validate

    // todo - validate configuration data and incorporate
    if (errors.length) {
      logger.error(`Errors detected on incoming data from ${state.autoConfigUrl}`);
      errors.forEach(e => {
        logger.error(e);
      });
      reject(errors);
    } else {
      fulfill();
    }
  });
}

// config read and verified, now this is the active start of the processing
initializeSwagger(app, swaggerDocument).then(() => {
  logger.success(`Swagger initialized`);
  attemptSynergyCheckPing().then(() => {
    logger.success(`pinged synergyCheck server at ${commonLib.getProtoHostPort()}`);
    commonLib.getAuthenticate().then(jwtToken => {
      logger.success(`authenticated with synergyCheck server`);

      if (state.autoConfig) {
        performAutoConfig().then(() => {
          startListening();
          if (state.report.autoReport) {
            agentRoutes.startReporting();
          }
        }, err => {
          // todo - retry
          process.exit(1);
        });
      } else {
        logger.info('NOT auto configuring, using configuration as locally specified...')
        startListening();
        if (state.report.autoReport) {
          agentRoutes.startReporting();
        }
      }
    }, err => {
      logger.error(`Failure to authenticate with server ${commonLib.getProtoHostPort()}`);
      process.exit(1);
    });
  }, err => {
    logger.error(`Fail to ping server ${commonLib.getProtoHostPort()}`);
    process.exit(1);
  })
}, err => {
  logger.error(`Error initializing Swagger ${err}`);
  process.exit(1);
});

function startListening() {
  app.listen(state.port);
  logger.info(`Agent server listening on ${commonLib.getProtoHostPort()}`);
  logger.info(`Agent openAPI docs available at ${commonLib.getProtoHostPort()}/api-docs`);
}


