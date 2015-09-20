# node-tor-control
A node library to communicate with tor-control

*For basic information about tor-control please read the
[specs](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)*

## How to use

```bash
npm install tor-control --save
```

```js
var TorControl = require('tor-control');

var control = new TorControl({
    password: 'password',                     // Your password for tor-control
    persistent: false                         // Keep connection (persistent)
});

control.signalNewnym(function (err, status) { // Get a new circuit
   if (err) {
      return console.error(err);
   }
   console.log(status.messages[0]); // --> "OK"
});

control.getInfo(['version', 'exit-policy/ipv4'], function (err, status) { // Get info like describe in chapter 3.9 in tor-control specs.
   if (err) {
      return console.error(err);
   }
   console.log(status.messages.join(' - '));
});

```

All commands from spec are supported. For further information take a look at the source-code and the specs.
