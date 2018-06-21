// Capture and decode all outgoing TCP data packets destined for port 80 on the interface for 192.168.1.5:
//
// from https://github.com/mscdex/cap
//
// Used VS C++ for 2015 to install. For deployment?
// Says it runs on *nix

const commander = require('commander');
const Cap = require('cap').Cap;
const decoders = require('cap').decoders;
const PROTOCOL = decoders.PROTOCOL;

const c = new Cap();
// const device = Cap.findDevice('192.168.1.5');
var filter;
const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);

const commanderArgs = [
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
  find: '',
  filter: 'tcp and dst port ${this.port}', // can ref values in state object
  device: '192.168.1.5',
  port: 80,
  commandLine: {},
  content: false,
  verbose: false,
  debug: false
}
commander
    .version(state.releas) // THIS IS WRONG!  IT MAY BE OVERRIDDEN BY config file value
    //.usage('[options] ...')
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
  state.device = commander.device;
}
if (commander.port !== undefined) {
  state.port = commander.port;
}
if (commander.content !== undefined) {
  state.content = !!commander.content;
}
if (commander.verbose !== undefined) {
  state.verbose = !!commander.verbose;
}
if (commander.debug !== undefined) {
  state.debug = !!commander.debug;
}

if (state.debug) {
  console.log(JSON.stringify(state, null, ' '));
}
//====================  --list ==========================
if (commander.list) {
  let devices = Cap.deviceList();
  devices.forEach(d => {
    if (d.flags) {
      console.log(`${d.name} (${d.description}) flags=${d.flags} ...`);
    } else {
      console.log(`${d.name} (${d.description})...`);
    }
    if (d.addresses) {
      d.addresses.forEach(a => {
        if (a.addr) {
          console.log(`    ${a.addr}`);
        }
      });
    }
  });
  if (state.debug) {
    console.log(JSON.stringify(Cap.deviceList(), null, '  '));
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
  console.log(`find "${state.find}"`);
  if (device !== undefined) {
    console.log(`Found device: ${device}`);
  } else {
    console.log(`device not found: "${state.find}"`)
  }
  process.exit(0);
}
//====================== monitoring =======================
try {
  filter = new Function('return `' + state.filter + '`;').apply(state);
} catch (ex) {
  console.error('failure to process filter \'' + state.filter + '\'');
  console.error(ex);
  process.exit(1);
}
// filter = `tcp and dst port ${state.port}`;
console.log(`monitor device ${state.device} filter '${state.filter}'`);
let linkType = c.open(state.device, filter, bufSize, buffer);
console.log(`linkType=${linkType}`);

c.setMinBytes && c.setMinBytes(0); // windows only

c.on('packet', function(nbytes, trunc) {
  console.log(`${new Date().toLocaleString()} packet: length ${nbytes} bytes, truncated? ${trunc ? 'yes' : 'no'}`);

  // raw packet data === buffer.slice(0, nbytes)

  if (linkType === 'ETHERNET') {
    let ret = decoders.Ethernet(buffer);

    if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
      if (state.verbose) {
        console.log('    Decoding IPv4 ...');
      }

      ret = decoders.IPV4(buffer, ret.offset);
      console.log('    IPv4 info - from: ' + ret.info.srcaddr + ' to ' + ret.info.dstaddr);

      if (ret.info.protocol === PROTOCOL.IP.TCP) {
        let datalen = ret.info.totallen - ret.hdrlen;
        if (state.verbose) {
          console.log('    Decoding TCP ...');
        }

        ret = decoders.TCP(buffer, ret.offset);
        console.log(`    TCP info - from port: ${ret.info.srcport} to port: ${ret.info.dstport} length ${datalen}`);
        datalen -= ret.hdrlen;
        if (state.content) {
          console.log('    content: ' + buffer.toString('binary', ret.offset, ret.offset + datalen));
        }
      } else if (ret.info.protocol === PROTOCOL.IP.UDP) {
        if (state.verbose) {
          console.log('    Decoding UDP ...');
        }

        ret = decoders.UDP(buffer, ret.offset);
        console.log('    UDP info - from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);
        console.log('    ' + buffer.toString('binary', ret.offset, ret.offset + ret.info.length));
      } else
        console.log('    Unsupported IPv4 protocol: ' + PROTOCOL.IP[ret.info.protocol]);
    } else
      console.log('    Unsupported Ethertype: ' + PROTOCOL.ETHERNET[ret.info.type]);
  }
});