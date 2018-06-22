// Capture and decode TCP data packets for specified connections, sampling at specified period
// and reporting to specified concentrator agent at specified period.
// Generate heartbeat call to concentrator agent.
// Upon start, make started call to concentrator agent
// Upon shutdown (expected or not) make ended call to concentrator agent
//
// Uses packet monitoring library (windows *nix compatible)
// from https://github.com/mscdex/cap
//
// Note for Windows, required VS2015 C++ to install as it compiled withe a VS project.
// For deployment on Linux, require packages to be installed: ibpcap and libpcap-dev/libpcap-devel

const commander = require('commander');
const fs        = require('fs');
const Cap       = require('cap').Cap;
const decoders  = require('cap').decoders;
const PROTOCOL  = decoders.PROTOCOL;
const request    = require('request-promise-native');

const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);

var config; // loaded configuration file

// this is re-initialized to empty object for each sample period
var samples = {}; // by connectionId -> { charCount, packets, disconnected, lastMessageTimestamp }

// TO DO - real logger!
const logger = {
  info: function() { logger.info.apply(null, arguments); },
  error: function() { console.error.apply(null, arguments); }
};

const configKeys = [
    'sensor', // object
    'sensor.id', // required
    'agent', // object
    'agent.apiBase', // required url of agent to report to
    'agent.apiKeys', // for security
    'monitor', // object
    'monitor.device', // required ethernet device to monitor
    'monitor.sample', // milliseconds sample rate
    'monitor.connections' // array of connection info
];

const commanderArgs = [
    'config',
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
  find: '',
  filter: 'tcp and dst port ${this.port}', // can ref values in state object
  device: '192.168.1.5',
  port: 80,
  commandLine: {},
  config: {},
  content: false,
  verbose: false,
  debug: false
}
commander
    .version(state.releas) // THIS IS WRONG!  IT MAY BE OVERRIDDEN BY config file value
    //.usage('[options] ...')
    .option('-c, --config [value]', 'The configuration file, overrides "' + state.configFile + '"')
    .option('-l, --list','list devices on this machine.  Pick one and run again specifying --device xxxx')
    .option('-f, --find [value]','find first device with specified ip' + state.find + '"')
    .option('-d, --device [value]','The device name to monitor, overrides "' + state.device + '"')
    .option('-x, --filter [value]','filter expression' + state.filter + '"')
    .option('-p, --port [value]', 'port the web server is listening on, override default of 80 or 443 depending on http or https')
    .option('-b, --content', 'output packet message content for debugging, overrides "' + state.content + '"')
    .option('-r, --release [value]', 'The release of the server software , overrides "' + state.release + '"')
    .option('-b, --verbose', 'output verbose messages for debugging, overrides "' + state.verbose + '"')
    .option('-d, --debug', 'output debug messages for debugging, overrides "' + state.debug + '"')
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

  //------------ validate the properties in the config -------------------
  ['sensor','agent','monitor'].forEach(name => {
    if (typeof(config[name]) !== 'object') {
      logger.error(`missing ${name} object in config file`);
      process.exit(1);
    }
  });

  // Copy original config file values into state.config
  state.config = {};
  Object.keys(config).forEach((k) => {
    state.config[k] = config[k];
  });

  // validate config.report.period, it is ms report period
  if (typeof(config.monitor.sample) === 'string') {
    if (/^\d+$/.test(config.report.period)) {
      // assume ms
      config.monitor.sample = Number.parseInt(config.monitor.sample);
    } else {
      // todo - recognize '10m', etc.
      logger.error(`monitor.sample is not a positive integer "${config.monitor.sample}"`);
      process.exit(1);
    }
  }
  if (typeof(config.monitor.sample) === 'number') {
    if (config.monitor.sample < 1000) {
      logger.error('cannot accept monitor.sample < 1000 ms');
      process.exit(1);
    }
  }

  if (!Array.isArray(config.monitor.connections)) {
    logger.error('missing config,monitor.connections array - nothing to monitor!');
    process.exit(1);
  }

  if (typeof(config.agent.apiBase) !== 'string') {
    logger.error('missing config.agent.apiBase');
    process.exit(1);
  }

  processConfigItem('verbose');
  if (state.verbose) {
    logger.info(JSON.stringify(config, null, '  '));
  }
} catch (ex1) {
  logger.error(`Cannot load configuration file ${state.configFile}`);
  if (commander.verbose) {
    logger.error(ex1.toString());
  }
  logger.error(`exception loading config file "${state.configFile}": ${ex1}`);
  logger.error('Exiting...');
  process.exit(1);
}

// Copy specified command line arguments into state
commanderArgs.forEach(function(k) {
  state.commandLine[k] = commander[k];
});

if (commander.find !== undefined) {
  state.find = commander.find;
}
if (commander.filter !== undefined) {
  state.filter = commander.filter;
}
if (commander.device !== undefined) {
  // the ethernet device to monitor
  state.monitor.device = commander.device;
}
if (commander.content !== undefined) {
  // show packet content in log
  state.content = !!commander.content;
}
if (commander.verbose !== undefined) {
  state.verbose = !!commander.verbose;
}
if (commander.debug !== undefined) {
  state.debug = !!commander.debug;
}
if (state.debug) {
  logger.info(JSON.stringify(state, null, ' '));
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

//====================== monitoring =======================
state.config.monitor.connections.forEach(conn => {
  // will update samples[connectionId]
  monitorConnection(conn); // set up to monitor
});

const timer = setInterval(function() {
  const timestampISO = new Date().toISOString();
  logger.info(`time to report ${timestampISO}`);
  report();

}, state.monitor.sample); // ms between reporting

let postReportUrl = `${state.config.agent.apiBase}sensor/report`;
logger.info(`report to url: ${postReportUrl}`);

// send report to the agent, and ready for next sample
function report() {
  let send = samples.map(s => {
    return {
      connectionId: s.connectionId,
      charCount: s.charCount,
      packetCount: s.packetCount,
      lastMessageTimestamp: s.lastMessageTimestamp,
      disconnected: s.disconnected
    };
  });

  samples = {}; // reset. Will accumulate for new sampling period

  request({
    method: 'POST',
    uri: postReportUrl,
    body: send,
    json: true // automatically stringifies body
  }).then(obj => {
    logger.info(JSON.stringify(obj));
  }).catch(err => {
    logger.error(err);
  });
}
// Establish a monitor for a connection
// Sets the filter string for the src and dst ip and the dst port.
// Captures packet count, accumulates charCount of each pack
// Captures timestamp of last packet
function monitorConnection(conn) {

  const cap = new Cap(); // a new instance of Cap for each connection?  Else filter must be enlarged

  const filter = `tcp and src host ${conn.src} and dst host ${conn.dst} and dst port ${conn.port}`;
  logger.info(`${conn.connectionId} -> monitor device ${conn.device} filter '${filter}'`);
  const linkType = c.open(state.device, filter, bufSize, buffer);
  logger.info(`${conn.connectionId} -> linkType=${linkType}`);

  cap.setMinBytes && c.setMinBytes(0); // windows only todo

  cap.on('packet', function(nbytes, trunc) {
    logger.info(`${conn.connectionId} -> ${new Date().toLocaleString()} packet: length ${nbytes} bytes, truncated? ${trunc ? 'yes' : 'no'}`);

    // raw packet data === buffer.slice(0, nbytes)

    if (linkType === 'ETHERNET') {
      let ret = decoders.Ethernet(buffer);

      if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
        if (state.verbose) {
          logger.info('    Decoding IPv4 ...');
        }

        ret = decoders.IPV4(buffer, ret.offset);
        logger.info(`    IPv4 info - from: ${ret.info.srcaddr} to ${ret.info.dstaddr}`);

        // verify filter works!
        if (conn.src !== ret.info.srcaddr) {
          logger.error(`${conn.connectionId} expecting src to be ${conn.src} but it is ${ret.info.srcaddr}`);
        }
        if (conn.dst !== ret.info.dstaddr) {
          logger.error(`${conn.connectionId} expecting src to be ${conn.dst} but it is ${ret.info.dstaddr}`);
        }

        if (ret.info.protocol === PROTOCOL.IP.TCP) {
          let datalen = ret.info.totallen - ret.hdrlen;
          if (state.verbose) {
            logger.info('    Decoding TCP ...');
          }

          ret = decoders.TCP(buffer, ret.offset);
          logger.info(`    TCP info - from port: ${ret.info.srcport} to port: ${ret.info.dstport} length ${datalen}`);

          if (conn.port !== ret.info.dstport) {
            logger.error(`${conn.connectionId} expecting port to be ${conn.port} but it is ${ret.info.dstport}`);
          }

          datalen -= ret.hdrlen;
          if (state.content) {
            let content = buffer.toString('binary', ret.offset, ret.offset + datalen);
            logger.info(`    content: ${content}`);
          }

          // by connectionId -> { charCount, packets, disconnected, lastMessageTimestamp }
          let sample = samples[conn.connectionId];
          if (!sample) {
            sample = {
              connectionId: conn.connectionId,
              charCount: 0,
              packetCount: 0,
              disconnected: false
            };
            samples[conn.connectionId] = sample;
          }
          sample.charCount += datalen;
          sample.packetCount++;
          sample.lastMessageTimestamp = new Date().toISOString();

        } else if (ret.info.protocol === PROTOCOL.IP.UDP) {
          if (state.verbose) {
            logger.info('    Decoding UDP ...');
          }

          ret = decoders.UDP(buffer, ret.offset);
          logger.info(`    UDP info - from port: ${ret.info.srcport} to port: ${ret.info.dstport}`);
          if (state.content) {
            let content = buffer.toString('binary', ret.offset, ret.offset + ret.info.length);
            logger.info(`    ${content}`);
          }
        } else
          logger.info(`    Unsupported IPv4 protocol: ${PROTOCOL.IP[ret.info.protocol]}`);
      } else
        logger.info(`    Unsupported Ethertype: ${PROTOCOL.ETHERNET[ret.info.type]}`);
    } else {
      logger.error(`    Unsupported linkType ${linkType}`);
    }
  });
}
