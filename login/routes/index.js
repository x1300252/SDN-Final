var express = require('express');
var crypto = require('crypto');
var router = express.Router();
var assert = require('assert');
var arp = require('arp');
var getClientAddress = require('client-address')

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/', function(req, res, next) {
  var db = req.con;
  var data = "";
  var ac = req.body.account;
  var pwd = crypto.createHash('sha256').update(req.body.password+"SDNSDN").digest('hex');

  db.query('SELECT id, role FROM account WHERE account=? AND password=?', [ac, pwd], function(err, rows) {
      if (err) {
          console.log(err);
          res.render('user', {title:'Error'});
      }
      else {
        var data = rows;
        var ip = getClientAddress.v4(req);
        console.log(rows, ip);
        
        arp.getMAC("10.0.2.2", function(err, mac) {
          console.log("Mac Address is " + mac);
          mac = parseInt(mac.split(':').join(''), 16);
          db.query('REPLACE INTO macpool SET mac=?, ac_id=?, role=?',
                    [mac, data[0].id, data[0].role], function(err) {
            if (err) {
                console.log(err);
                res.render('user', {status:0});
            }
            else {
              if (data[0].role == 0) {
                db.query('SELECT account.account, macpool.role, macpool.mac FROM macpool INNER JOIN account ON macpool.ac_id=account.id', function(err, row) {
                  if (err) {
                    console.log(err);
                    res.render('user', {status:0});
                  }
                  else {
                    res.render('user', {status:1, user: ac, role:data[0].role, data: row});
                  }
                });
              }
              else {
                res.render('user', {status:1, user: ac, role:data[0].role});
              }
            }
          });
        });
      }
      // use index.ejs
  });

});

module.exports = router;
