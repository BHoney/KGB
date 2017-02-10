var google = require('google');
var whois = require('whois');
var prompt = require('prompt');
var storage = require('node-persist');

//Define Functions

///Used to initiate program
function start() {
    console.log("What target are you performing recon on today? [Please include .com,.net, etc: ]");
    prompt.start();
    prompt.get('target', function (err, result) {
        if (result.target == 'exit') process.exit(0);
        var target = result.target;
        console.log(target);
        storage.initSync()
        options(target);
    });
}

///Select your target and begin your search
function options(selectedTarget) {
    console.log(`Please select your search options from the following list:`);
    console.log(`  0 - Perform All Searches`)
    console.log(`  1 - Perform WHOIS Search [WILL NOT CREATE FILE]`);
    console.log(`  2 - Search for Passwords`);
    console.log(`  3 - Search for Logins`);
    console.log(` 4 - Search for PHP Vulnerablilties`);
    prompt.get('selection', function (err, result) {
        switch (result.selection) {
            case "0":
                searchWHOIS(selectedTarget);
                searchLogin(selectedTarget);
                searchPassword(selectedTarget);
                searchVuln(selectedTarget);
                break;
            case "1":
                searchWHOIS(selectedTarget);
                break;
            case "2":
                searchPassword(selectedTarget);
                break;
            case "3":
                searchLogin(selectedTarget);
                break;
            case "4":
                searchVuln(selectedTarget);
                break;
            default:
                console.log("Please choose from the menu options.");
                options();
                break;
        }
    })
}

//Performs a WHOIS search
function searchWHOIS(addr) {
    var result;
    whois.lookup(`${addr}`, function (err, data) {
        if (err) console.log(err)
        //Save data here
        //result.push(data);
        console.log(data);
    });
}

///Performs a search for logins using Google Hacking Database booleans
function searchLogin(addr) {
    var logins = []
    google(`${addr} inurl:admin inurl:userlist`, function (err, res) {
        if (err) console.log(err)
        else {
            //Save Data Here
            for (var i = 0; i < res.links.length; i++) {
                var entry = {
                    "title": res.links[i].title,
                    "link": res.links[i].href,
                    "desc": res.links[i].description
                }
                logins.push(entry);
            }
        }
    });
    console.log(logins);
    var d = new Date()
    var storeLogins = storage.getItemSync(`${addr}-logins-${d.toDateString()}`);
    if (typeof storeLogins == 'undefined') {
        storeLogins = [];
    }
    storage.setItemSync(`${addr}-logins-${d.toDateString()}`, logins);
    console.log("Saved. Closing");
}

///Performs a search for php vulnerabilities
function searchVuln(addr) {
    var vuln = []
    google(`${addr} inurl:updown.php | intext:"Powered by PHP Uploader Downloader"`, function (err, res) {
        if (err) console.log(err)
        else {
            //Save Data Here
            for (var i = 0; i < res.links.length; i++) {
                var entry = {
                    "title": res.links[i].title,
                    "link": res.links[i].href,
                    "desc": res.links[i].description
                }
                vuln.push(entry);
            }
        }
    });
    console.log(vuln);
    var d = new Date()
    var storeVuln = storage.getItemSync(`${addr}-vuln-${d.toDateString()}`);
    if (typeof storeVuln == 'undefined') {
        storeVuln = [];
    }
    storage.setItemSync(`${addr}-vuln-${d.toDateString()}`, vuln);
    console.log("Saved. Closing");
}

//Performs a search for passwords
function searchPassword(addr) {
    var passwords = [];
    google(`${addr} site:pastebin.com intext:Username`, function (err, res) {
        if (err) console.log(err)
        else {
            //Save Data Here
            for (var i = 0; i < res.links.length; i++) {
                var entry = {
                    "title": res.links[i].title,
                    "link": res.links[i].href,
                    "desc": res.links[i].description
                }
                passwords.push(entry);
            }
            console.log(passwords);
            var d = new Date();
            var storePass = storage.getItemSync(`${addr}-Pass-${d.toDateString()}`);
            if (typeof storePass == 'undefined') {
                storePass = [];
            }
            storage.setItemSync(`${addr}-Pass-${d.toDateString()}`, passwords);
            console.log("Saved. Closing");
        }
    });
}

start();
