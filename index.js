const Permissions = require('./src/Permissions');

module.exports = function(app, optionsToMerge) {
    const options = Object.assign({ 
      enableCache: true,
      models: {
        RoleMapping: 'RoleMapping',
        ACL: 'ACL'
      }
    }, optionsToMerge);
    app.permissions = new Permissions(app.models, app.remotes(), options);
};
