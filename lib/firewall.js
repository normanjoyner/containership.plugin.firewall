var fs = require("fs");
var _ = require("lodash");
var async = require("async");
var Tesserarius = require("tesserarius");
var request = require("request");
var flat = require("flat");

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

    var build_steps = [
        function(fn){
            self.get_initial_rules(fn);
        },
        function(rules, fn){
            self.get_host_rules(rules, fn);
        }
    ]

    if(this.options.cloud_enabled){
        build_steps.push(function(rules, fn){
            self.get_cloud_rules(rules, fn);
        });
    }

    this.reset_rules(function(err){
        if(err){
            self.core.loggers["containership.plugin.firewall"].log("error", "Unable to reset firewall rules");
            self.core.loggers["containership.plugin.firewall"].log("debug", err.message);
        }

        var set_rules = function(){
            self.core.loggers["containership.plugin.firewall"].log("verbose", "Updating firewall rules");
            async.waterfall(build_steps, function(err, rules){
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

Firewall.prototype.get_cloud_rules = function(rules, fn){
    var self = this;

    if(self.options.mode == "leader")
        return fn(undefined, rules);

    try{
        var cloud_configuration = require([process.env.HOME, ".containership", "cloud.json"].join("/"));
    }
    catch(e){
        return fn(undefined, rules);
    }

    var options = {
        url: ["https://api.containership.io/v1/organizations", cloud_configuration.organization, "clusters", self.core.cluster_id, "firewalls"].join("/"),
        method: "GET",
        json: true,
        headers: {
            "X-ContainerShip-Cloud-API-Key": cloud_configuration.api_key,
            "X-ContainerShip-Cloud-Organization": cloud_configuration.organization
        }
    }

    request(options, function(err, response){
        if(err){
            self.core.loggers["containership.plugin.firewall"].log("error", "Error fetching ContainerShip Cloud defined firewall rules!");
            self.core.loggers["containership.plugin.firewall"].log("verbose", err.message);
        }
        else if(response.statusCode != 200){
            self.core.loggers["containership.plugin.firewall"].log("error", "Error fetching ContainerShip Cloud defined firewall rules!");
            self.core.loggers["containership.plugin.firewall"].log("verbose", ["API returned", response.statusCode, "response code"].join(" "));
        }
        else{
            _.each(response.body, function(firewall){
                var rule = {
                    policy: "ACCEPT",
                    protocol: firewall.protocol,
                    destination_port: firewall.port
                }

                if(firewall.type == "ip"){
                    if(firewall.source != "*")
                        rule.source = firewall.source;

                    rules.push(rule);
                }
                else{
                    var peers = self.core.cluster.legiond.get_peers();

                    var matching_hosts = _.filter(peers, function(peer){
                        var tags = flat.flatten(peer.tags);

                        var tag_name = firewall.source.split("=")[0];
                        var tag_value = firewall.source.split("=")[1];

                        if((_.has(tags, tag_name) && tags[tag_name] == tag_value) || firewall.source == "*"){
                            _.each(_.keys(peer.address), function(scope){
                                var rule_copy = _.clone(rule);
                                rule_copy.source = peer.address[scope]
                                rules.push(rule_copy);
                            });
                        }
                    });
                }
            });
        }

        return fn(undefined, rules);
    });
}

module.exports = Firewall;
