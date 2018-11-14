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

const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);

var config; // loaded configuration file (see also state.config

var monitored = {}; // key is `${src}|${dst}|${port}` -> { connection, cap }
// for a short window, existingConnections may not equal state.config.monitor.connections
var existingConnections = []; // what is currently being monitored
// this is re-initialized to empty object for each sample period
var samples = []; // connection data { charCount, packets, disconnected, lastMessageTimestamp }
var samplesIndex = {}; // by connectionId -> connection data

var started = new Date();
// used to generate unique transaction number
// by combining this with the id of the sensor and a counter
const startedMills = started.getTime();
let transactionCounter = 0;

// TO DO - real logger!
const logger = {
  info: function () {
    console.info.apply(null, arguments);
  },
  error: function () {
    console.error.apply(null, arguments);
  }
};

logger.info(`SynergyCheck Sensor started ${started.toISOString()}`);

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
  'release',
  'verbose',
  'debug'
];

const state = {
  release: '0.0.1', // todo
  configFile: 'sensor.json',
  autoConfig: false, // complete configuration by requesting from agent
  getAutoConfigUrl: '', // when performing autoConfig fetch
  postReportUrl: '', // when reporting sensor data to agent
  find: '',
  filter: 'tcp and dst port ${this.port}', // can ref values in state object
  device: '192.168.1.5',
  port: 80,
  commandLine: {},
  config: {},
  content: false,
  started: started.toISOString(),
  verbose: false,
  debug: false
};
commander
    .version(state.releas) // THIS IS WRONG!  IT MAY BE OVERRIDDEN BY config file value
    //.usage('[options] ...')
    .option('-c, --config [value]', `The configuration file, overrides "${state.configFile}"`)
    .option(`-a, --auto`, `perform auto configuration from synergyCheck server specified`)
    .option('-l, --info', 'display OS information on ethernet interfaces devices on this machine.')
    .option('-l, --list', 'list devices on this machine.  Pick one and run again specifying --device xxxx')
    .option('-f, --find [value]', `find first device with specified ip ${state.find}"`)
    .option('-d, --device [value]', `The device name to monitor, overrides config "${state.device}"`)
    .option('-x, --filter [value]', `filter expression ${state.filter}"`)
    .option('-p, --port [value]', 'port the web server is listening on, override default of 80 or 443 depending on http or https')
    .option('-b, --content', `output packet message content for debugging, overrides "${state.content}"`)
    .option('-r, --release [value]', `The release of the server software , overrides "${state.release}"`)
    .option('-b, --verbose', `output verbose messages for debugging, overrides "${state.verbose}"`)
    .option('-d, --debug', `output debug messages for debugging, overrides "${state.debug}"`)
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
    if (state.debug) {
      logger.info(JSON.stringify(Cap.deviceList(), null, '  '));
    }
    process.exit(0);
  }
  //====================  --find ==========================
  if (state.find !== '') {
    let device;
    if (state.find === true) {
      device = Cap.findDevice();
    } else {
      device = Cap.findDevice(state.find);
    }
    logger.info(`find "${state.find}"`);
    if (device !== undefined) {
      logger.info(`Found device: ${device}`);
    } else {
      logger.info(`device not found: "${state.find}"`)
    }
    process.exit(0);
  }

  //============= validate the properties in the config for monitor mode ============
  processConfigItem('autoConfig', 'auto');
  if (state.autoConfig) {
    ['sensor', 'agent'].forEach(name => {
      if (typeof(config[name]) !== 'object') {
        logger.error(`for autoConfig, missing ${name} object in config file`);
        process.exit(1);
      }
    });
    if (typeof(config.monitor) !== 'undefined') {
      logger.info('config.monitor ignored when autoConfig is enabled. It will be auto configured');
    }
  } else {
    ['sensor', 'agent', 'monitor'].forEach(name => {
      if (typeof(config[name]) !== 'object') {
        logger.error(`for non-autoConfig, missing ${name} object in config file`);
        process.exit(1);
      }
    });
  }

  // Copy original config file values into state.config
  state.config = {};
  Object.keys(config).forEach((k) => {
    state.config[k] = config[k];
  });

  // validate config.sensor
  if (typeof(config.sensor.sensorId) !== 'string') {
    logger.error('missing string sensor.sensorId');
    process.exit(1);
  }
  if (typeof(config.sensor.customerId) !== 'string') {
    logger.error('missing string sensor.customerId');
    process.exit(1);
  }
  if (!state.autoConfig) {
    // validate config.report.period, it is ms report period
    if (typeof(config.monitor.sampleRate) === 'string') {
      // assume ms
      config.monitor.sampleRate = parseDuration(config.monitor.sampleRate);
    } else {
      // todo - recognize '10m', etc.
      logger.error(`monitor.sampleRate is not a positive integer "${config.monitor.sampleRate}"`);
      process.exit(1);
    }

    // validate config.monitor
    if (config.monitor.sampleRate < 1000) {
      logger.error(`cannot accept monitor.sampleRate < 1000 ms. You specified ${config.monitor.sampleRate}`);
      process.exit(1);
    }


    if (!Array.isArray(config.monitor.connections)) {
      logger.error('missing config,monitor.connections array - nothing to monitor!');
      process.exit(1);
    }
    // todo - validate array of connections
  }

  if (typeof(config.agent.apiBase) !== 'string') {
    logger.error('missing config.agent.apiBase');
    process.exit(1);
  }
  //todo: config.agent.apiKeys

  if (state.verbose) {
    logger.info(JSON.stringify(config, null, '  '));
  }
} catch (ex1) {
  logger.error(`exception loading and processing config file "${state.configFile}": ${ex1}`);
  logger.error('Exiting...');
  process.exit(1);
}

// Copy specified command line arguments into state
commanderArgs.forEach(function (k) {
  state.commandLine[k] = commander[k];
});

if (commander.find !== undefined) {
  state.find = commander.find;
}
if (commander.filter !== undefined) {
  state.filter = commander.filter;
}
if (commander.device !== undefined) {
  if (state.autoConfig) {
    logging.error('do not specify device is autoConfig');
    process.exit(1);
  }
  // the ethernet device to monitor
  state.monitor.device = commander.device;
}
if (commander.content !== undefined) {
  // show packet content in log
  state.content = !!commander.content;
}
if (state.debug) {
  logger.info(JSON.stringify(state, null, ' '));
}

//====================== monitoring =======================
function startMonitoring() {
  // state.config.monitor.connections.forEach(conn => {
  //   // will update samplesIndex[connectionId]
  //   monitorConnection(conn); // set up to monitor
  // });
  if (state.verbose) {
    logger.info(`monitor ${JSON.stringify(state.config.monitor, null, '  ')}`);
  }
  resetMonitoring(existingConnections, state.config.monitor.connections)
  // remember what we just set up
  existingConnections = state.config.monitor.connections;

  // initiate reporting
  const timer = setInterval(function () {
    const timestampISO = new Date().toISOString();
    logger.info(`time to report ${timestampISO}`);
    report();

  }, state.config.monitor.sampleRate); // ms between reporting
}

state.postReportUrl = `${state.config.agent.apiBase}sensor/report`;
logger.info(`report to url: ${state.postReportUrl}`);

// send report to the agent, and ready for next sample
function report() {

  // generate unique transaction number
  // by combining this with the id of the sensor and a counter
  transactionCounter++;
  let transactionId = `${state.config.sensor.sensorId}|${startedMills}|${transactionCounter}`
  state.lastTransactionId = transactionId;

  let send = {
    snapshot: {
      sensorId: state.config.sensor.sensorId,
      customerId: state.config.sensor.customerId,
      timestamp: new Date().toISOString(),
      transactionId: transactionId,
      duration: 10000,
      connections: samples.map(s => {
        return {
          interfaceId: s.interfaceId,
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

  if (state.debug) {
    logger.info(JSON.stringify(send, null, '  '));
  }

  samples.length = 0; // reset. Will accumulate for new sampling period
  samplesIndex = {};

  request({
    method: 'POST',
    uri: state.postReportUrl,
    body: send,
    json: true // automatically stringifies body
  }).then(obj => {
    logger.info(JSON.stringify(obj));
  }).catch(err => {
    logger.error(err);
  });
}

// compares old set of connections (empty if first time) with the
// new set of connection definitions,
// using the index of monitored caps (connections), which is empty if first time)
function resetMonitoring(oldConnections, newConnections) {
  let newOnes = newConnections.filter(conn => {
    return !monitored[`${conn.src}|${conn.dst}|${conn.port}`];
  });
  if (state.debug) {
    logger.info(`newOnes: ${JSON.stringify(newOnes, null, '  ')}`);
  }
  let existingOnes = newConnections.filter(conn => {
    return monitored[`${conn.src}|${conn.dst}|${conn.port}`];
  });
  if (state.debug) {
    logger.info(`existingOnes: ${JSON.stringify(existingOnes, null, '  ')}`);
  }
  let removeThese = oldConnections.filter(oc => {
    return !newConnections.find(nc => {
      return nc.src === oc.src && nc.dst === oc.dst && nc.port === oc.port;
    })
  });
  if (state.debug) {
    logger.info(`removeThese: ${JSON.stringify(removeThese, null, '  ')}`);
  }
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
    // will update samplesIndex[connectionId]
    monitorConnection(conn); // set up to monitor
  });
}
// Establish a monitor for a connection
// Sets the filter string for the src and dst ip and the dst port.
// Captures packet count, accumulates charCount of each pack
// Captures timestamp of last packet
function monitorConnection(conn) {

  const cap = new Cap(); // a new instance of Cap for each connection?  Else filter must be enlarged

  // remember so can close if updated configuration obtained
  monitored[`${conn.src}|${conn.dst}|${conn.port}`] = {
    connection: conn,
    cap: cap
  };

  const filter = `tcp and src host ${conn.src} and dst host ${conn.dst} and dst port ${conn.port}`;
  logger.info(`${conn.connectionId} -> monitor device ${conn.device} filter '${filter}'`);
  const linkType = cap.open(state.config.monitor.device, filter, bufSize, buffer);
  logger.info(`${conn.connectionId} -> linkType=${linkType}`);

  cap.setMinBytes && cap.setMinBytes(0); // windows only todo

  cap.on('packet', function (nbytes, trunc) {
    logger.info(`${conn.connectionId} -> ${new Date().toLocaleString()} packet: length ${nbytes} bytes, truncated? ${trunc ? 'yes' : 'no'}`);

    let error;
    const errors = [];
    // raw packet data === buffer.slice(0, nbytes)

    if (linkType === 'ETHERNET') {
      let eth = decoders.Ethernet(buffer);

      if (eth.info.type === PROTOCOL.ETHERNET.IPV4) {
        if (state.debug) {
          logger.info('    Decoding IPv4 ...');
        }

        let ipv4 = decoders.IPV4(buffer, eth.offset);
        if (state.debug || state.verbose) {
          logger.info(`    IPv4 info - from: ${ipv4.info.srcaddr} to ${ipv4.info.dstaddr}`);
        }

        // verify filter works!
        if (conn.src !== ipv4.info.srcaddr) {
          error = `${conn.connectionId} expecting src to be ${conn.src} but it is ${ipv4.info.srcaddr}`;
          errors.push(error);
        }
        if (conn.dst !== ipv4.info.dstaddr) {
          error = `${conn.connectionId} expecting src to be ${conn.dst} but it is ${ipv4.info.dstaddr}`;
          errors.push(error);
        }

        if (!errors.length) {
          if (ipv4.info.protocol === PROTOCOL.IP.TCP) {
            let datalen = ipv4.info.totallen - ipv4.hdrlen;
            if (state.debug) {
              logger.info('    Decoding TCP ...');
            }

            let tcp = decoders.TCP(buffer, ipv4.offset);
            if (state.debug || state.verbose) {
              logger.info(`    TCP info - from port: ${tcp.info.srcport} to port: ${tcp.info.dstport} length ${datalen}`);
            }

            if (conn.port !== tcp.info.dstport) {
              logger.error(`    ${conn.connectionId} expecting port to be ${conn.port} but it is ${tcp.info.dstport}`);
            }

            datalen -= tcp.hdrlen;
            if (state.content) {
              let content = buffer.toString('binary', tcp.offset, tcp.offset + datalen);
              if (state.verbose) {
                logger.info(`    content: ${content}`);
              }
            }
            if (!dataLen) {
              return; // filter out empty packets
            }

            if (!state.debug && !state.verbose) {
              logger.info(`    IPv4 TCP from ${ipv4.info.srcaddr}:${tcp.info.srcport} to ${ipv4.info.dstaddr}:${tcp.info.dstport} length=${datalen}`);
            }
            // by connectionId -> { charCount, packets, disconnected, lastMessageTimestamp }
            let sample = samplesIndex[conn.connectionId];
            if (!sample) {
              sample = {
                connectionId: conn.connectionId,
                charCount: 0,
                packetCount: 0,
                disconnected: false
              };
              samplesIndex[conn.connectionId] = sample;
              samples.push(sample); // convenience array
            }
            sample.charCount += datalen;
            sample.packetCount++;
            sample.lastMessageTimestamp = new Date().toISOString();

          } else if (ipv4.info.protocol === PROTOCOL.IP.UDP) {
            if (state.verbose || state.debug) {
              logger.info('    Decoding UDP ...');
            }

            let udp = decoders.UDP(buffer, ipv4.offset);
            if (state.debug || state.verbose) {
              logger.info(`    UDP info - from port: ${udp.info.srcport} to port: ${udp.info.dstport}`);
            }
            if (state.content) {
              let content = buffer.toString('binary', udp.offset, udp.offset + udp.info.length);
              if (state.debug || state.verbose) {
                logger.info(`    ${content}`);
              }
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

function makeGetConfigRequest() {
  state.getAutoConfigUrl = `${state.config.agent.apiBase}sensor/autoConfig`
      + `?sensorId=${encodeURI(state.config.sensor.sensorId)}`
      + `&agentId=${encodeURI(state.config.agent.agentId)}`
      + `&customerId=${encodeURI(state.config.sensor.customerId)}`;
  if (state.verbose) {
    logger.info(`auto configuration call GET ${state.getAutoConfigUrl}`);
  }
  return request({
    method: 'GET',
    uri: state.getAutoConfigUrl,
    json: true
  })
}

if (state.autoConfig) {
  makeGetConfigRequest().then((obj) => {
    const errors = [];
    // validate contents
    if (obj.customerId !== state.config.sensor.customerId) {
      errors.push(`unexpected customerId "${obj.customerId}"`);
    }
    if (obj.agentId !== state.config.agent.agentId) {
      errors.push(`unexpected agentId "${obj.agentId}"`);
    }
    if (obj.sensorId !== state.config.sensor.sensorId) {
      errors.push(`unexpected customerId "${obj.sensorId}"`);
    }
    if (errors.length === 0) {
      state.config.monitor = state.config.monitor || {};
      state.config.monitor.version = obj.version;
      state.config.monitor.name = obj.name;
      state.config.monitor.sampleRate = durationParser(obj.sampleRate);
      state.config.monitor.device = obj.device;
      state.config.monitor.deviceName = obj.deviceName;
      state.config.monitor.connections = obj.connections;

      startMonitoring();
    }

    if (errors.length) {
      console.error('Errors detected in response to autoConfig:');
      errors.forEach(e => logger.error(e));
    }
  },(err) => {
    logger.error(`Error returned from getConfig(): ${err}`);
  });
}