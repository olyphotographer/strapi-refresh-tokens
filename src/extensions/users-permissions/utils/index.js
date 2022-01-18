'use strict';

const getService = name => {
  return strapi.plugin('users-permissions').service(name);
  return 
};

module.exports = {
  getService,
};
