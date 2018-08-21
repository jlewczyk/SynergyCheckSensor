// run this to simulate a number of Connections (interfaces) with predictable data
// so they can be monitored to check the effectiveness and performance of
// the SynergyCheck server.
// It acts an "agent", sending simulated agentReports to the specified server on behalf of the specified customer.
//
// Provide configuration information in agentTrafficSim.yaml or .json
// >node agentTrafficSim.js --config  agentTrafficSim.yaml

const commander = require('commander');
const net = require('net');
const fs = require('fs');
const jsYaml    = require('js-yaml')
const request   = require('request-promise-native');
const RunQueue = require('run-queue');
const colors    = require('colors');
const common    = require('../lib/common');

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
  debug: function() {
    console.log.apply(null, Array.from(arguments).map(a => colors.gray(a)));
  }
};

// The state of this process.  Includes config file contents, current settings
const state = {
  version: '0.0.1',
  configFile: 'agentTrafficSim.yaml',
  protocol: 'http',
  hostName: 'localhost',
  port: 4200,
  clientid: '',
  secret: '',
  customerid: '', // if specified, must match client's affiliation
  kill: false, // remove agentReport, connectionMeasures, connectionWekkOfVolume documents at start
  maxConcurrent: 2, // maximum concurrent request for selective document (e.g. AgentReport, AgentReportDetail)
  maxAgentReports: 99999999,
  agentReportTxCounter: 0, // for debugging
  report: {
    period: 1000, // millis between reports
    minChars: 0, // minimum reported chars
    maxChars: 1000, // maximum reported chars
    gaps: 0, // fraction (.e.g 0.1) of reports with 0 chars
    count: 0, // # agentReports
    errors: 0 // # of agentReport errors
  },
  maxErrors: 999,
  commandLine: {},
  verbose: false,
  debugMode: false
};

const commanderArgs = [
  'config',
  'protocol',
  'host',
  'port',
  'clientid',
  'secret',
  'maxConcurrent',
  'maxAgentReports',
  'customer',
  'verbose',
  'debug'
];
commander
    .version('0.0.1')
    //.usage('[options] ...')
    .option('-c, --config [value]', 'The configuration file, overrides "' + state.configFile + '"')
    .option('-t, --protocol [value]','The host protocol of the synergycheck server, overrides "' + state.protocol + '"')
    .option('-h, --host [value]','The host name of the synergycheck server, overrides "' + state.hostName + '"')
    .option('-p, --port [value]', 'port of the synergycheck server, override ' + state.port, parseInt)
    .option('-u, --clientid [value]', 'The clientid to authenticate with, overrides "' + state.clientid + '"')
    .option('-s, --secret [value]', 'The client secret to authenticate with, overrides "' + state.secret + '"')
    .option('-m, --maxConcurrent', `maximum concurrent requests made to server (for agentReport, agentReportDetail) default is ${state.maxConcurrent}`, parseInt)
    .option('-z, --maxAgentReports [value]', `maximum agentReport documents to import, overrides ${state.maxAgentReports}`, parseInt)
    .option('-u, --customer [value]', 'The customerid to load into')
    .option('-v, --verbose','output verbose information')
    .option('-d, --debug','output debugging information')
    .parse(process.argv);

// Copy specified command line arguments into state
commanderArgs.forEach((k) => {
  if (commander[k] !== undefined) {
    state.commandLine[k] = commander[k];
  }
});

common.setVars(commander, logger, state);

common.readConfig();
let processConfigItem = common.processConfigItem;

// // enable some "hacks" of the incoming data to complete it
// processConfigItem('hack');
// for experimenting on small data setss
processConfigItem('maxAgentReports');

processConfigItem('maxConcurrent');

//------------- web server protocol -------------------
processConfigItem('protocol');
//------------- web server host name -------------------
processConfigItem('hostName', 'host', 'hostName');
//------------- web server port number -------------------
processConfigItem('port');

//-------------- credentials to supply to SynergyCheck server
processConfigItem('clientid');
processConfigItem('secret');

processConfigItem('customer', 'customerid', 'customerid');

logger.info(`agentTrafficSim version ${state.version}`);

if (state.verbose || state.debug) {
  logger.info(JSON.stringify(state, null, 2));
}

common.setProtoHostPort(`${state.protocol || 'http'}://${state.hostName}:${state.port || 80}`);
const protoHostPort = common.getProtoHostPort();

if (state.verbose) {
  logger.info(JSON.stringify(state, null, '  '));
}
// Delete customer's agentReport, connectionMeasures, connectionWeekOfVolume documents
function killDocuments() {
  return new Promise((fulfill, reject) => {

  });
}
// pingAuthGetCustomer will exit process if any failure
// fetch list of customer's connections, so we can simulate them
common.pingAuthGetCustomer().then((customer) => {
  logger.success(`ready to rock and roll!`);

  common.get('/api/connection').then((result) => {
    if (state.debug || state.verbose) {
      logger.success(`Fetched ${result.data.length} connections`);
    }
    state.connections = result.data;

    common.get('/api/agent').then((result) => {
      if (state.debug || state.verbose) {
        logger.success(`Fetched ${result.data.length} agents`);
      }
      state.agents = result.data;

      if (state.deleteDocuments) {
        common.deleteCustomerData(state.customerid, {
          agentReport: true,
          connectionMeasures: true,
          connectionWeekOfVolume: true
        }).then((result) => {
          // removed documents that we are going to replace with simuiations
          startSimulation();
        }, (err) => {
          logger.error(`Error deleting documents for ${state.customerid}, ${err}`);
          process.exit(1);
        });
      } else {
        startSimulation();
      }
    }, (err) => {

    });
  }, (err) => {
    logger.error(`Error fetching connections for ${state.customerid}, ${err}`);
    process.exit(1);
  });
});

function startSimulation() {
  // At varying random times,
  // For each of the state.connections, start a separate interval, with (state.report.period millis)
  /*
    report: {
      period: 1000, // millis between reports
      minChars: 0, // minimum reported chars
      maxChars: 1000, // maximum reported chars
      gaps: 0 // fraction (.e.g 0.1) of reports with 0 chars
    }
   */

  const range = state.report.maxChars - state.report.minCharts;
  const offset = state.report.minCharts;
  const period = state.report.period;
  const gaps   = state.report.gaps;

  function buildReport() {
    const now = Date.now();
    const data = {
      customer_id: state.customerid,
      agent_id: state.agents[0]._id,
      timestamp: new Date(now).toGMTString(),
      duration: period,
      interfaces: state.connections.map(conn => {
        if (Math.random() > gaps) {
          return {
            interfaceUid: conn.interfaceUid,
            charCount: getCharCount(),
            lastDataTimestamp: getLastDataTimestamp(now)
          };
        }
      }).filter(o => o) // remove the "gaps" generated
    };
    return data;
  }
  function getCharCount() {
    return Math.round((Math.random() * range) + offset);
  }
  function getLastDataTimestamp(now) {
    // some random point of time in the period
    const last = Math.round(now - (Math.random() * period));
    return new Date(last).toGMTString();
  }

  const generators = []; // connectionId -> interval
  function generator(connectionId) {
    setTimeout((connectionId) => {
      state.agentReportTxCounter++;
      const report = buildReport();
      request({
        url: `${protoHostPort}/api/v1/agentReport?tx=${++state.agentReportTxCounter}`,
        method: 'post',
        headers: {
          'Authorization': `Bearer ${state.jwt}`
        },
        json: true,
        body: report
      }).then((newDoc) => {
        state.report.count++;
      }, (err) => {
        state.report.errors++;
      });
    }, period); // start approx one each second
  }
  // start up each generator randomly
}