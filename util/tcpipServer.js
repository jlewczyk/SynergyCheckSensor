// from https://gist.github.com/tedmiston/5935757

const net = require('net');
const commander = require('commander');

commander
    .version('0.0.1') // THIS IS WRONG!  IT MAY BE OVERRIDDEN BY config file value
    //.usage('[options] ...')
    .option('-h, --host [value]','the host ip address or dns name that is listening for a tcp/ip connection')
    .option('-p, --port <n>','the port on the host which is listening for a tcp/ip connection')
    .option('-m, --message [value]','the message string to send on connection')
    .parse(process.argv);

const host = commander.host ? commander.host : '127.0.0.1';
const port = commander.port ? commander.port : 1337;
const message = commander.message ? commander.message : 'Echo Win7 server\r\n';

const server = net.createServer(function(socket) {
  socket.write(message);
  socket.pipe(socket);
}).on('error', (err) => {
  // handle errors here
  console.error(err);
});

server.listen(port, host);
// server.listen(1337, '10.157.100.78');
// server.listen(1337, '127.0.0.1');
