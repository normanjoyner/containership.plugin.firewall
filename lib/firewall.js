var fs = require("fs");
var _ = require("lodash");
var async = require("async");
var Tesserarius = require("tesserarius");

function Firewall(options){
    var self = this;

    this.core = options.core;
    this.config = options.config;
    this.core = options.core;

    if(_.isUndefined(options.options))
        options.options = {};

    this.options = _.defaults(options.options, {
        chain: "ContainerShip",
        refresh_interval: (60 * 1000),
        initial_rules: [
            {
                policy: "ACCEPT",
                interface: "lo"
            },
            {
                policy: "ACCEPT",
                state: ["ESTABLISHED", "RELATED"]
            },
            {
                interface: self.core.options["legiond-interface"],
                policy: "ACCEPT",
                protocol: "tcp",
                destination_port: 2666
            },
            {
                interface: self.core.options["legiond-interface"],
                policy: "ACCEPT",
                protocol: "tcp",
                destination_port: 2777
            }
        ]
    });

    this.options.cloud_enabled = fs.existsSync([process.env.HOME, ".containership", "cloud.json"].join("/"));

    if(this.options.cloud_enabled){
        this.options.initial_rules.push({
            policy: "ACCEPT",
            protocol: "tcp",
            destination_port: this.core.options["api-port"],
            source: "52.70.63.224/28",
            mode: "leader"
        });
    }

    if(_.has(this.config, "rules") && _.isArray(this.config.rules)){
        _.each(this.config.rules, function(rule){
            self.options.initial_rules.push(rule);
        });
    }

    this.tesserarius = new Tesserarius();
}

Firewall.prototype.enable = function(){
    var self = this;

    this.reset_rules(function(err){
        if(err){
            self.core.loggers["containership.plugin.firewall"].log("error", "Unable to reset firewall rules");
            self.core.loggers["containership.plugin.firewall"].log("debug", err.message);
        }

        var set_rules = function(){
            async.waterfall([
                function(fn){
                    self.get_initial_rules(fn);
                },
                function(rules, fn){
                    self.get_host_rules(rules, fn);
                }
            ], function(err, rules){
                self.tesserarius.set_rules(self.options.chain, rules, function(err){
                    if(err){
                        self.core.loggers["containership.plugin.firewall"].log("error", "Unable to apply new firewall rules");
                        self.core.loggers["containership.plugin.firewall"].log("debug", err.message);
                    }
                    else
                        self.core.loggers["containership.plugin.firewall"].log("verbose", "Sucessfully applied new firewall rules");
                });
            });
        }

        setInterval(function(){
            self.core.loggers["containership.plugin.firewall"].log("verbose", "Updating firewall rules");
            set_rules();
        }, self.options.refresh_interval);

        set_rules();
    });
}

Firewall.prototype.reset_rules = function(fn){
    var self = this;

    async.series([
        function(fn){
            self.tesserarius.flush(self.options.chain, function(err){
                if(err)
                    self.tesserarius.create_chain(self.options.chain, fn);
                else
                    return fn();
            });
        },
        function(fn){
            self.tesserarius.flush("INPUT", fn);
        },
        function(fn){
            self.tesserarius.set_policy("INPUT", "DROP", fn);
        },
        function(fn){
            self.tesserarius.set_rules("INPUT", [
                {
                    policy: self.options.chain
                }
            ], fn);
        }
    ], fn);
}

Firewall.prototype.get_initial_rules = function(fn){
    var self = this;
    var rules = [];

    _.each(this.options.initial_rules, function(rule){
        if((_.has(rule, "mode") && self.core.options.mode == rule.mode) || !_.has(rule, "mode"))
            rules.push(_.omit(rule, "mode"));
    });

    return fn(undefined, rules);
}

Firewall.prototype.get_host_rules = function(rules, fn){
    var self = this;

    var peers = this.core.cluster.legiond.get_peers();

    _.each(peers, function(peer){
        if(self.core.options.mode == "leader"){
            _.each(_.keys(peer.address), function(scope){
                rules.push({
                    policy: "ACCEPT",
                    protocol: "tcp",
                    destination_port: 8080,
                    source: peer.address[scope]
                });
            });
        }
        else{
            _.each(_.keys(peer.address), function(scope){
                rules.push({
                    policy: "ACCEPT",
                    protocol: "tcp",
                    destination_port: [
                        self.core.scheduler.options.loadbalancer.min_port,
                        self.core.scheduler.options.loadbalancer.max_port
                    ].join(":"),
                    source: peer.address[scope]
                });

                rules.push({
                    policy: "ACCEPT",
                    protocol: "tcp",
                    destination_port: [
                        self.core.scheduler.options.container.min_port,
                        self.core.scheduler.options.container.max_port
                    ].join(":"),
                    source: peer.address[scope]
                });
            });
        }
    });

    return fn(undefined, rules);
}

module.exports = Firewall;
