const PermissionTree = require('./src/PermissionTree');

module.exports = function(app, optionsToMerge) {
    const options = Object.assign({ 
      mountPath: '/getUserPermissionTree', 
      enableCache: true,
      models: {
        RoleMapping: 'RoleMapping',
        ACL: 'ACL'
      }
    }, optionsToMerge);
    app.permissions = new PermissionTree(app.models, app.remotes(), options);
};
