// Can start sensor in one of 4 different modes.
// --info      Display OS information on ethernet interfaces are present on the machine
// --list      List all ethernet interfaces on this machine
// --find <ip> Find the first device with the specified ip
// --auto      Request configuration from agent server and begin monitoring and reporting
//   other     Use local configuration to begin monitoring and reporting
//
// Capture and decode TCP data packets for specified connections, sampling at specified period
// and reporting to specified concentrator agent at specified period.
// Generate heartbeat call to concentrator agent.
// Upon start, make started call to concentrator agent
// Upon shutdown (expected or not) make ended call to concentrator agent
//
// Uses packet monitoring library (windows & *nix compatible)
// from https://github.com/mscdex/cap
// For Windows, require WinPcap https://www.winpcap.org (free)
// or Npcap https://nmap.org/npcap which has $20K one time license!)
//
// Note for Windows, required VS2015 C++ to install as it compiled withe a VS project.
// For deployment on Linux, require packages `to be installed: ibpcap and libpcap-dev/libpcap-devel

const commander = require('commander');
const os = require('os');
const fs = require('fs');
const Cap = require('cap').Cap;
const decoders = require('cap').decoders;
const PROTOCOL = decoders.PROTOCOL;
const request = require('request-promise-native');
const durationParser = require('duration-parser');
const commonLib   = require('./lib/common');
const colors = require('colors');

const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);

let monitored = {}; // key is `${src}|${dst}|${port}` -> { connection, cap }
// note for a short time window, existingConnections may not equal state.monitor.connections
let existingConnections = []; // what is currently being monitored
// this is re-initialized to empty object for each sample period
const samples = []; // connection data { charCount, packets, disconnected, lastMessageTimestamp }
let samplesIndex = {}; // by interfaceUid -> connection data

let reportTimer; // interval timer for sending reports - stop and restart between re-autoconfigs

var started = new Date();
// used to generate unique transaction number
// by combining this with the id of the sensor and a counter
const startedMills = started.getTime();

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

// todo
const configKeys = [
  'sensor', // object
  'sensor.id', // required
  'agent', // object
  'agent.apiBase', // required url of agent to report to
  'agent.apiKeys', // for security
  'monitor', // object
  'monitor.device', // required ethernet device to monitor
  'monitor.sampleRate', // milliseconds sample rate
  'monitor.connections' // array of connection info
];

const commanderArgs = [
  'config',
  'info',
  'list',
  'find',
  'device',
  'filter',
  'port',
  'content',
  'noReport',
  'release',
  'verbose',
  'debug'
];

const state = {
  release: '0.0.1', // todo
  configFile: 'sensor.yaml',
  pingPeriod: 10000, // 10 seconds between initial pings to server
  pingUrl: '', // set when attempting initial ping with agent
  autoConfig: false, // complete configuration by requesting from agent
  getAutoConfigUrl: '', // set when performing autoConfig fetch
  postReportUrl: '', // when reporting sensor data to agent
  find: '',
  filter: 'tcp and dst port ${this.port}', // can ref values in state object
  commandLine: {},
  config: {}, // copy of the original configuration file properties
  started: started.toISOString(),
  transactionCounter: 0,
  agent: {
    apiKeys: [] // provided by config
    // provided by config or autoConfig
  },
  monitor: {
    sampleRate: 10000,
    version: '?', // supply from config or autoConfig
    name: '?', // supply from config or autoConfig
    device: undefined, // supply by --device, or config.monitor.device or from autoConfig
    deviceName: '', // supply by config or autoConfig (documentation only)
    content: false,
    noReport: false // if true, suppress sending sensorReports
  },
  connections: [], // config or autoConfig - what connections to monitor
  verbose: false,
  debug: false
};

logger.info(`SynergyCheck Sensor ${state.release} started ${started.toISOString()}`);
commander
    .version(state.releas) // THIS IS WRONG!  IT MAY BE OVERRIDDEN BY config file value
    //.usage('[options] ...')
    .option('-c, --config [value]', `The configuration file, overrides "${state.configFile}"`)
    .option('-l, --info', 'display OS information on ethernet interfaces devices on this machine.')
    .option('-l, --list', 'list devices on this machine.  Pick one and run again specifying --device xxxx')
    .option('-f, --find [value]', `find first device with specified ip`)

    .option(`-a, --auto`, `perform auto configuration from synergyCheck server specified`)
    .option('-d, --device [value]', `The ethernet device name to monitor, overrides config "${state.monitor.device}"`)
    .option('-x, --filter [value]', `filter expression ${state.filter}"`)
    .option('-p, --port [value]', 'port the web server is listening on, override default of 80 or 443 depending on http or https')
    .option('-b, --content', `output packet message content for debugging, overrides "${state.monitor.content}"`)
    .option('-n, --noReport', `do not send sensorReports to agent (for local debugging)`)
    .option('-r, --release [value]', `The release of the server software , overrides "${state.release}"`)
    .option('-b, --verbose', `output verbose messages for debugging, overrides "${state.verbose}"`)
    .option('-d, --debug', `output debug messages for debugging, overrides "${state.debugMode}"`)
    .parse(process.argv);

commonLib.setVars(commander, logger, state);
commonLib.readConfig();
const processConfigItem = commonLib.processConfigItem;
const resolvePath = commonLib.resolvePath;
const setPath = commonLib.setPath;

// Copy specified command line arguments into state
commanderArgs.forEach((k) => {
  state.commandLine[k] = commander[k];
});

processConfigItem('release', 'release', 'release');
const errors = [];
try {
  //==================== --info ===========================
  if (commander.info) {
    logger.info('os.networkInterfaces...');
    logger.info(JSON.stringify(os.networkInterfaces(), null, '  '));
    process.exit(0);
  }
  // Can do a list or find a device given ip, else perform monitoring and reporting
  //====================  --list ==========================
  if (commander.list) {
    let devices = Cap.deviceList();
    devices.forEach(d => {
      if (d.flags) {
        logger.info(`${d.name} (${d.description}) flags=${d.flags} ...`);
      } else {
        logger.info(`${d.name} (${d.description})...`);
      }
      if (d.addresses) {
        d.addresses.forEach(a => {
          if (a.addr) {
            logger.info(`    ${a.addr}`);
          }
        });
      }
    });
    logger.debug(JSON.stringify(Cap.deviceList(), null, '  '));
    process.exit(0);
  }
  //====================  --find ==========================
  if (commander.find) {
    let device;
    if (commander.find === true) {
      device = Cap.findDevice();
    } else {
      device = Cap.findDevice(commander.find);
    }
    logger.info(`find "${commander.find}"...`);
    if (device !== undefined) {
      logger.info(`Found device: ${device}`);
    } else {
      logger.info(`device not found: "${commander.find}"`)
    }
    process.exit(0);
  }

  //================================================================================================
  //
  // Not performing any probing options, setup to perform monitoring of interfaces
  // through autoConfig (from associated agent) or local configuration (just the config file)
  //
  processConfigItem('monitor.noReport', 'noReport', 'noReport');

  //============= validate the properties in the config for monitor mode ============
  processConfigItem('autoConfig', 'auto', 'agent.autoConfig');
  if (state.autoConfig) {
    if (typeof(state.config.connections) !== 'undefined' && Object.keys(state.config.connections).length) {
      logger.warning(`for autoConfig, connections is overridden by auto config`);
    }
    if (typeof(state.config.monitor) !== 'undefined' && Object.keys(state.config.monitor).length) {
      logger.warning('config.monitor specified when autoConfig is enabled, may overwriting some autoConfig settings');
    }
    ['synergyCheck','agent','sensor'].forEach(name => {
      if (typeof(state.config[name]) !== 'object') {
        errors.push(`must provide ${name} section of configuration`);
      }
    });
  } else {
    // These sections MUST be provided.  Their content can leave out values that have defaults
    ['synergyCheck', 'agent', 'sensor', 'monitor', 'connections'].forEach(name => {
      if (typeof(state.config[name]) !== 'object') {
        errors.push(`for non-autoConfig, ${name} object in config file is required`);
      }
    });
  }
  // config must have info on the agent it reports to (and optionally gets configuration info from)
  if (!state.config.agent.httpProtocol) {
    errors.push(`Missing state.config.agent.httpProtocol property`);
  }
  if (!state.config.agent.hostName) {
    errors.push(`Missing state.config.agent.hostName property`);
  }
  if (!state.config.agent.port) {
    errors.push(`Missing state.config.agent.port property`);
  }
  if (!state.config.agent.apiBase) {
    errors.push(`Missing state.config.agent.apiBase property`);
  }
  // Setup for communicating with SynergyCheck - ping, authenticate, autoConfig, post agentReports,...
  commonLib.setProtoHostPort(`${state.config.agent.httpProtocol || 'http'}://${state.config.agent.hostName}:${state.config.agent.port || 80}`);

  // sensorReport and autoConfig request require sending a valid apiKey in the authorization header
  // An apiKey is required in the config file
  // More than one can be specified to handle expired apiKeys by retrying with the additional keys
  if (!Array.isArray(state.config.agent.apiKeys) || !state.config.agent.apiKeys.length) {
    errors.push(`Must provided agent.apiKeys array with at lease 1 key`);
  } else {
    state.agent.apiKeys = state.config.agent.apiKeys || [];
  }

  // config MUST have sensor section with the registered id of the sensor
  // validate config.sensor
  if (typeof(state.config.sensor.sensorId) !== 'string') {
    errors.push('missing string sensor.sensorId');
  }
  state.sensorId = state.config.sensor.sensorId;

  // Validate required synergyCheck section of configuration with registered customerId
  if (typeof(state.config.synergyCheck.customerId) !== 'string' || !state.config.synergyCheck.customerId) {
    errors.push('missing string synergyCheck.customerId');
  }
  state.customerId = state.config.synergyCheck.customerId;

  processConfigItem('monitor.device', 'device', 'monitor.device');
  // Validate config.monitor section.  Some values may be overridden by autoConfig
  if (!state.monitor.device) {
    errors.push(`monitor device is required.  Must know what ethernet device to monitor for traffic`);
  } else {
    if (state.autoConfig) {
      logger.warning(`specified device on command when autoConfig, will override autoconfig with device "${commander.device}"`);
    }
  }

  if (state.config.monitor) {
    if (typeof(state.config.monitor.sampleRate) !== 'undefined') {
      // validate state.config.monitor.sampleRate, it is ms report period
      if (typeof(state.config.monitor.sampleRate) === 'string') {
        // recognize '10m', etc.
        state.monitor.sampleRate = parseDuration(state.config.monitor.sampleRate);
      } else if (typeof(state.config.monitor.sampleRate) === 'number') {
        state.monitor.sampleRate = state.config.monitor.sampleRate;
      } else {
        errors.push(`monitor.sampleRate is not a positive integer "${state.config.monitor.sampleRate}"`);
      }
      // assume ms
      // validate sampleRate
      if (typeof(state.monitor.sampleRate) === 'number' && state.monitor.sampleRate < 1000) {
        errors.push(`cannot accept monitor.sampleRate < 1000 ms. You specified ${state.config.monitor.sampleRate}`);
      }
    }

    if (!state.autoConfig) {
      if (!Array.isArray(state.config.monitor.connections)) {
        errors.push('missing config.monitor.connections array - nothing specified to monitor!');
      } else {
        // todo - validate array of connections
        state.connections = state.config.connections;
      }
    } else {
      if (state.config.monitor.connections && state.config.monitor.connections.length) {
        logger.warning(`When autoConfig is specified, connections in config file will be ignored`);
      }
    }
  }

  if (errors.length) {
    errors.forEach(e => logger.error(e));
    process.exit(1);
  }

  // for diagnostic purposes, can specify the filter string for pcap
  // instead of having it generated per connection.
  processConfigItem('filter', 'filter', 'filter');

  // Note - this may expose PHI for unencrypted traffic!
  processConfigItem('monitor.content', 'content', 'content');

  if (state.verbose) {
    logger.info(JSON.stringify(state.config, null, '  '));
  }
} catch (ex1) {

  errors.push(`exception loading and processing config file "${state.configFile}": ${ex1}`);
  errors.push('Exiting...');
  errors.forEach(e => logger.error(e));

  process.exit(1);
}
logger.debug(JSON.stringify(state, null, ' '));

//====================== monitoring =======================
function startMonitoring() {
  return new Promise((monitorFulfill, monitorReject) => {
    if (state.verbose) {
      logger.info(`monitor ${JSON.stringify(state.monitor, null, '  ')}`);
    }
    resetMonitoring(existingConnections, state.connections);
    // remember what we just set up
    existingConnections = state.connections;

    // initiate reporting
    reportTimer = setInterval(function () {
      // if agent has not responded yet to prior report, continue accumulating
      // and don't generate a report (which resets accumulator)

      if (state.agentReportInProgress) {
        return;
      }
      state.agentReportInProgress = new Date();
      const timestampISO = state.agentReportInProgress.toISOString();
      logger.debug(`${timestampISO} time to send sensorReport`);
      report().then(result => {
        state.agentReportInProgress = null;
        if (result.newConfig) {
          monitorFulfill(); // only fulfills when need to reconfigure
        }
      }, err => {
        state.agentReportInProgress = null;
      });

    }, state.monitor.sampleRate); // ms between reporting
  });
}
function stopMonitoring() {
  clearInterval(reportTimer);
  reportTimer = null;
  logger.info(`stopped reporting`);
}

state.postReportUrl = `${commonLib.getProtoHostPort()}${state.config.agent.apiBase}sensor/report`;
logger.info(`Sensor reports to url: ${state.postReportUrl}`);

// send report to the agent, and ready for next sample
function report() {
  // Only calls reject if run out of acceptable apiKeys
  return new Promise((fulfill, reject) => {
    // add to queue and dequeue one at a time until successful
    // handle retry with new apiKey when 401
    // When to give up retrying?
    // What to do with abandoned reports?

    // generate unique transaction number
    // by combining this with the id of the sensor and a counter
    state.transactionCounter++;
    const transactionId = `${state.sensorId}|${startedMills}|${state.transactionCounter}`;
    state.lastTransactionId = transactionId;

    const send = {
      snapshot: {
        sensorId: state.sensorId,
        customerId: state.customerId,
        timestamp: new Date().toISOString(),
        transactionId: transactionId,
        duration: '10s',
        connections: samples.map(s => {
          return {
            interfaceUid: s.interfaceUid,
            charCount: s.charCount,
            packetCount: s.packetCount,
            disconnected: s.disconnected,
            sourceNoPing: s.sourceNoPing,
            targetNoPing: s.targetNoPing,
            lastMessageTimestamp: s.lastMessageTimestamp
          };
        })
      }
    };

    if (state.monitor.noReport) {
      logger.warning(`noReport set, would have sent the following at ${new Date().toLocaleString()}...`);
      logger.verbose(JSON.stringify(send, null, '  '));
      fulfill({});
    } else {
      logger.debug(JSON.stringify(send, null, '  '));
    }

    samples.length = 0; // reset. Will accumulate for new sampling period
    samplesIndex = {};

    if (!state.monitor.noReport) {
      function makeSensorReportRequest() {
        request({
          method: 'POST',
          uri: state.postReportUrl,
          body: send,
          json: true, // automatically stringifies body
          headers: {
            'Authorization': `Bearer ${state.agent.apiKeys[0]}`
          }
        }).then(response => {
          logger.verbose(JSON.stringify(response));
          // response is ok, optional new config available indicator
          fulfill(response);
        }).catch(err => {
          logger.error(err);
          if (err.statusCode === 401) {
            // retry with new apiKey if any left to try, else exit
            const badKey = state.agent.apiKeys.shift();
            if (state.agent.apiKeys.length) {
              // todo - disgard the key, if it expired
              // state.agent.apiKeys.push(badKey);
              setTimeout(() => {
                makeSensorReportRequest();
              }, state.retryPeriod || 3000);
            } else {
              logger.error(`all apiKeys are rejected, quitting after unsuccesful send of sensorReport:`);
              logger.error(JSON.stringify(send, null, '  '));
              reject('no acceptable api keys available');
            }
          } else {
            // not an unauthorized rejection.  Keep trying
            setTimeout(() => {
              // Is there a limit to the retries?
              // What to do if abandon the request and reject?
              makeSensorReportRequest();
            }, state.retryPeriod || 3000);
          }
        });
      }
      makeSensorReportRequest();
    }
  });
}
// If autoConfig, then sensor will request configuration every state.refresh millis
// If the configuration it receives is different from the prior configuration, then adjust
// by editing, removing, or adding new monitors

// resetMonitoring is called with (first, next) configuration.  It compares the
// old set of connections (empty if first time) with the new set of connection definitions,
// using the index of monitored caps (connections) (which is empty if first time)
function resetMonitoring(oldConnections, newConnections) {
  let newOnes = newConnections.filter(conn => {
    return !monitored[`${conn.src}|${conn.dst}|${conn.port}`];
  });
  logger.debug(`newOnes: ${JSON.stringify(newOnes, null, '  ')}`);
  let existingOnes = newConnections.filter(conn => {
    return monitored[`${conn.src}|${conn.dst}|${conn.port}`];
  });
  logger.debug(`existingOnes: ${JSON.stringify(existingOnes, null, '  ')}`);
  let removeThese = oldConnections.filter(oc => {
    return !newConnections.find(nc => {
      return nc.src === oc.src && nc.dst === oc.dst && nc.port === oc.port;
    })
  });
  logger.debug(`removeThese: ${JSON.stringify(removeThese, null, '  ')}`);
  // if existing connections monitored and they are NOT in the new set of connections
  // then close them.
  removeThese.forEach(oc => {
    let monitored =  monitored[`${oc.src}|${oc.dst}|${oc.port}`];
    if (monitored) {
      monitored.cap.close();
    } else {
      throw `expected to find monitored: ${oc.src}|${oc.dst}|${oc.port}`;
    }
  });
  newOnes.forEach(conn => {
    // will update samplesIndex[interfaceUid] and samples array
    monitorThisConnection(conn); // set up to monitor
  });
}
// Establish a monitor for the specified connection
// Sets the filter string for the src and dst ip and the dst port.
// Captures packet count, accumulates charCount of each pack
// Captures timestamp of last packet
// Accumulates in the samples array, indexed by by sampleIndex[conn.interfaceUid]
// to ensure each connection has only one entry in samples
function monitorThisConnection(conn) {

  const cap = new Cap(); // a new instance of Cap for each connection?  Else filter must be enlarged

  // remember so can close if updated configuration obtained
  monitored[`${conn.src}|${conn.dst}|${conn.port}`] = {
    connection: conn,
    cap: cap
  };

  const filter = `tcp and src host ${conn.src} and dst host ${conn.dst} and dst port ${conn.port}`;
  logger.info(`${conn.interfaceUid} monitored on ethernet device ${state.monitor.device} filter '${filter}'`);
  let linkType;
  try {
    linkType = cap.open(state.monitor.device, filter, bufSize, buffer);
  } catch (ex) {
    console.error(`Error opening defined ${state.monitor.device}, ${ex}`);
    console.error(`for ${conn.src}|${conn.dst}|${conn.port}`);
    process.exit(1);
    return;
  }
  logger.info(`${conn.interfaceUid} -> linkType=${linkType}`);

  cap.setMinBytes && cap.setMinBytes(0); // windows only todo

  cap.on('packet', function (nbytes, trunc) {
    logger.verbose(`${conn.interfaceUid} -> ${new Date().toLocaleString()} packet: length ${nbytes} bytes, truncated? ${trunc ? 'yes' : 'no'}`);

    let error;
    const errors = [];
    // raw packet data === buffer.slice(0, nbytes)

    if (linkType === 'ETHERNET') {
      let eth = decoders.Ethernet(buffer);

      if (eth.info.type === PROTOCOL.ETHERNET.IPV4) {
        logger.debug('    Decoding IPv4 ...');

        let ipv4 = decoders.IPV4(buffer, eth.offset);
        logger.debug(`    IPv4 info - from: ${ipv4.info.srcaddr} to ${ipv4.info.dstaddr}`);

        // verify filter works!
        if (conn.src !== ipv4.info.srcaddr) {
          error = `${conn.interfaceUid} expecting src to be ${conn.src} but it is ${ipv4.info.srcaddr}`;
          errors.push(error);
        }
        if (conn.dst !== ipv4.info.dstaddr) {
          error = `${conn.interfaceUid} expecting src to be ${conn.dst} but it is ${ipv4.info.dstaddr}`;
          errors.push(error);
        }

        if (!errors.length) {
          if (ipv4.info.protocol === PROTOCOL.IP.TCP) {
            let datalen = ipv4.info.totallen - ipv4.hdrlen;
            logger.debug('    Decoding TCP ...');

            let tcp = decoders.TCP(buffer, ipv4.offset);
            logger.debug(`    TCP info - from port: ${tcp.info.srcport} to port: ${tcp.info.dstport} length ${datalen}`);

            if (conn.port !== tcp.info.dstport) {
              logger.error(`    ${conn.interfaceUid} expecting port to be ${conn.port} but it is ${tcp.info.dstport}`);
            }

            datalen -= tcp.hdrlen;
            if (state.monitor.content) {
              let content = buffer.toString('binary', tcp.offset, tcp.offset + datalen);
              if (state.verbose) {
                logger.verbose(`    content: ${content}`);
              }
            }
            if (!datalen) {
              return; // filter out empty packets
            }

            if (!state.debugMode && !state.verbose) {
              logger.info(`    IPv4 TCP from ${ipv4.info.srcaddr}:${tcp.info.srcport} to ${ipv4.info.dstaddr}:${tcp.info.dstport} length=${datalen}`);
            }
            // by interfaceUid -> { charCount, packets, disconnected, lastMessageTimestamp }
            let sample = samplesIndex[conn.interfaceUid];
            if (!sample) {
              sample = {
                interfaceUid: conn.interfaceUid,
                charCount: 0,
                packetCount: 0,
                disconnected: false
              };
              samplesIndex[conn.interfaceUid] = sample;
              samples.push(sample); // convenience array
            }
            sample.charCount += datalen;
            sample.packetCount++;
            sample.lastMessageTimestamp = new Date().toISOString();

          } else if (ipv4.info.protocol === PROTOCOL.IP.UDP) {
            if (state.verbose || state.debugMode) {
              logger.info('    Decoding UDP ...');
            }

            let udp = decoders.UDP(buffer, ipv4.offset);
            logger.debug(`    UDP info - from port: ${udp.info.srcport} to port: ${udp.info.dstport}`);
            if (state.monitor.content) {
              let content = buffer.toString('binary', udp.offset, udp.offset + udp.info.length);
              logger.debug(`    ${content}`);
            }
          } else {
            logger.info(`    Unsupported IPv4 protocol: ${PROTOCOL.IP[ipv4.info.protocol]}`);
          }
        } else {
          errors.forEach(error => logger.error(error));
        }
      } else {
          logger.info(`    Unsupported Ethertype: ${PROTOCOL.ETHERNET[eth.info.type]}`);
        }
    } else {
      logger.error(`    Unsupported linkType ${linkType}`);
    }
  });
}

// Initial contact with agent is via the unauthenticated ping call
// Continue to ping until agent answers, waiting state.pingPeriod millis
// @return promise fulfilled when ping successful
// never calls reject, so will attempt to ping forever
function attemptPing() {
  return new Promise((fulfill, reject) => {
    function tryOnePing() {
      pingAgent().then(result => {
        // success
        logger.success(`success pinging agent at ${state.pingUrl}`);
        fulfill(result);
      }, err => {
        logger.warning(`fail to ping agent ${state.pingUrl}, ${err}.  Will try again in ${state.pingPeriod || 30000} millis...`);
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
function pingAgent() {
  state.pingUrl =
    `${commonLib.getProtoHostPort()}${state.config.agent.apiBase}ping`;
  logger.verbose(`ping agent with GET ${state.pingUrl}`);
  return request({
    method: 'GET',
    uri: state.pingUrl,
    json: true
  });
}
// make call to agent for configuration information and reconfigure
// the monitors between stopping and restarting sensorReports
//
function performAutoConfiguration() {
  return new Promise((fulfill, reject) => {
    // Make request of the specified agent for information on what this sensor is supposed to monitor
    state.getAutoConfigUrl =
      commonLib.getProtoHostPort()
      + `${state.config.agent.apiBase}sensor/autoConfig`
      + `?sensorId=${encodeURI(state.sensorId)}`
      + `&agentId=${encodeURI(state.config.agent.agentId)}`
      + `&customerId=${encodeURI(state.customerId)}`;
    logger.info(`auto configuration call GET ${state.getAutoConfigUrl}`);
    request({
      method: 'GET',
      uri: state.getAutoConfigUrl,
      json: true,
      headers: {
        'Authorization': `Bearer ${state.agent.apiKeys[0]}`
      }
    }).then((configObj) => {
      const errors = [];
      // validate contents
      if (configObj.customerId !== state.customerId) {
        errors.push(`unexpected customerId "${configObj.customerId}"`);
      }
      if (configObj.agentId !== state.config.agent.agentId) {
        errors.push(`unexpected agentId "${configObj.agentId}"`);
      }
      if (configObj.sensorId !== state.config.sensor.sensorId) {
        errors.push(`unexpected sensorId "${configObj.sensorId}"`);
      }
      if (errors.length === 0) {
        state.monitor.version = configObj.version;
        state.monitor.name = configObj.name;
        state.monitor.sampleRate = durationParser(configObj.sampleRate);
        state.monitor.device = state.monitor.device || configObj.device; // use command line or config device, else autoconfig
        state.monitor.deviceName = configObj.deviceName;
        state.connections = (configObj.connections || []).map(conn => {
          return {
            connection_id: conn.connection_id,
            interfaceUid: conn.interfaceUid,
            kind: conn.kind,
            // for now, just take first one.  Later, these represent choices!
            // todo - array of ports corresponding to array of dst and src for auto re-routing with high availability setup
            dst: conn.dst[0],
            src: conn.src[0],
            port: conn.port
          };
        });

        fulfill();

      } else {
        console.error('Errors detected in response to autoConfig:');
        errors.forEach(e => logger.error(e));
        reject(errors);
      }
    }, (err) => {
      // todo - status of unauthorized - try other keys
      logger.error(`Error returned from request to agent for configuration ${err}`);
      reject(err);
    });
  });
}
// a autoConfig and run workflow
// run when booting or when sensorReport response says to reconfigure
function performAutoConfigAndStartMonitoring() {
  performAutoConfiguration().then(() => {
    // only fulfilled if agent says to reconfigure
    startMonitoring().then(() => {
      // agent returned indicator that there is new configuration (agentReport response)
      // then re-autoConfig
      stopMonitoring();
      performAutoConfigAndStartMonitoring();
    });
  }, err => {
    // todo if err.statusCode == 401 retry with other apiKeys, quit if none left
    process.exit(1);
  });
}
//
// Here is where we get started!
//
attemptPing().then(result => {
  if (state.autoConfig) {
    performAutoConfigAndStartMonitoring();
  } else {
    // assume all configuration is locally provided via command line args and config file contents
    startMonitoring();
  }
});
