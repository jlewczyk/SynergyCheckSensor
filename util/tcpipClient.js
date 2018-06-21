// https://gist.github.com/tedmiston/5935757
// Or use this example tcp client written in node.js.
// (Originated with example code from
// http://www.hacksparrow.com/tcp-socket-programming-in-node-js.html.)
//
const commander = require('commander');
const net = require('net');

commander
    .version('0.0.1') // THIS IS WRONG!  IT MAY BE OVERRIDDEN BY config file value
    //.usage('[options] ...')
    .option('-h, --host [value]','the host ip address or dns name that is listening for a tcp/ip connection')
    .option('-p, --port <n>','the port on the host which is listening for a tcp/ip connection')
    .option('-m, --message [value]','the message string to send')
    .parse(process.argv);

const host = commander.host ? commander.host : '127.0.0.1';
const port = commander.port ? commander.port : 1337;
const message = commander.message ? commander.message : 'Hello, server! Love, Client.';
var client = new net.Socket();
client.connect(port, host, function() {
  console.log('Connected');
  client.write(message);
  // client.end();
});

client.on('data', function(data) {
  console.log('Received: ' + data);
  // client.destroy(); // kill client after server's response
});

client.on('close', function() {
  console.log('Connection closed');
});