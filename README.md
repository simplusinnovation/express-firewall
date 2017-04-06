#Firewall

This package gives a set of firewall functionalities for express

A firewall is a basic middleware that can be user in express


## Install

```
npm install --save @simplus/express-firewall
```


## Usage

```typescript
const fw = require("@simplus/firewall");

app.use(fw.isRoot());

app.get("/test", fw.hasPermission("test/list"), (req, res, next)=>{
	...
});
```
