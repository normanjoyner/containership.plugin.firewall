var ContainershipPlugin = require("containership.plugin");
var Firewall = require([__dirname, "lib", "firewall"].join("/"));

module.exports = new ContainershipPlugin({
    type: "core",
    name: "firewall",

    initialize: function(core){
        core.logger.register("containership.plugin.firewall");

        var firewall = new Firewall({
            options: {},
            config: this.get_config("core"),
            core: core
        });

        firewall.enable();
    },

    reload: function(){}
});
