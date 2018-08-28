function Permissions(models, remotes, options) {
  /**
     * Loopback data models
     * @type {Array}
     */
  this.models = models;

  /**
   * Loopback remote methods
   * @type {Array}
   */
  this.remotes = remotes;

  /**
  * Loopback access types
  *
  * @type {Array}
  */
  this.ACCESS_TYPES = ['READ', 'WRITE', 'EXECUTE'];

  /**
     * Component options
     * 
     * @type {object}
     */
  this.options = options || {};
}
module.exports = Permissions;

/**
 * Custom check permissions function that actually works! 
 * @param {*} context - object containing userId, appId and roles
 * @param {*} model - model name
 * @param {*} property - property
 * @param {*} accessType - READ, WRITE, EXECUTE
 * @param {AccessRequest} callback 
 */
Permissions.prototype.checkPermission = function (context, model, property, accessType) {
  var self = this;
  context.roles = context.roles || [];
  if (context.userId !== null && context.userId !== undefined && (typeof context.userId !== 'string')) context.userId = context.userId.toString();
  if (context.appId !== null && context.appId !== undefined && (typeof context.appId !== 'string')) context.appId = context.appId.toString();

  return new Promise(function (resolve, reject) {
    const ACL = self.models[self.options.models.ACL];

    property = property || ACL.ALL;
    var propertyQuery = (property === ACL.ALL) ? undefined : { inq: [property, ACL.ALL] };
    accessType = accessType || ACL.ALL;
    var accessTypeQuery = (accessType === ACL.ALL) ? undefined :
      { inq: [accessType, ACL.ALL, ACL.EXECUTE] };

    var req = {
      model: model,
      property: property,
      accessType: accessType,
      registry: ACL.registry
    };
    var acls = ACL.getStaticACLs(model, property);

    ACL.find({
      where: {
        model: model, property: propertyQuery, accessType: accessTypeQuery
      }
    },
      function (err, dynACLs) {
        if (err) {
          return reject(err);
        }
        var relevantAcls = [];
        acls = acls.concat(dynACLs);
        
        acls.forEach(function (acl) {
          var relevant = true;
          var relevantRole = false;

          if (acl.principalType === ACL.USER && acl.principalId !== context.userId) relevant = false;
          if (acl.principalType === ACL.APP && acl.principalId !== context.appId) relevant = false;

          context.roles.forEach(function(role) {
            if (acl.principalType === ACL.ROLE && acl.principalId === role.name) relevantRole = true;
          });

          if (relevant || relevantRole) relevantAcls.push(acl);
        });

        // resolved is an instance of AccessRequest
        var resolved = ACL.resolvePermission(relevantAcls, req);
        return resolve(resolved);
      });
  });
};

/**
 * Loop through all the app models and methods and check permissions for each access type
 * @param {Model} context - user model instance 
 * @param {*} callback 
 */
Permissions.prototype.buildPermissions = function (context, callback) {
  var self = this;
  var promises = [];
  var permissions = {};
  const ACL = this.models[this.options.models.ACL];

  Object.values(self.models).forEach(function (model) {
    if (model.shared) {
      permissions[model.modelName] = {};
      if (self.remotes._classes[model.modelName]) {
        const methods = self.remotes._classes[model.modelName]._methods;
        Object.values(methods).forEach(function (method) {
          permissions[model.modelName][method.name] = {};

          self.ACCESS_TYPES.forEach(function (accessType) {
            promises.push(self.checkPermission(context, model.modelName, method.name, accessType));
          });
        });
      }
    }
  });

  callback(promises, permissions);
};

/**
 * Get a user's permissions
 * @param {Model} context - user model instance 
 * @param {*} callback 
 */
Permissions.prototype.getPermissions = function (context, callback) {
  this.buildPermissions(context, function (promises, permissions) {
    Promise.all(promises)
      .then(function (results) {
        results.forEach(function (accessRequest) {
          permissions[accessRequest.model][accessRequest.property][accessRequest.accessType] = accessRequest.isAllowed();
        });
        callback(null, permissions);
      })
      .catch(function (err) {
        callback(err);
      });
  });
};