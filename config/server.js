module.exports = ({ env }) => ({
  proxy: true,
  host: env('HOST', '0.0.0.0'),
  port: env.int('PORT', 1338),
  url: env('', 'http://localhost:1338'),
});
