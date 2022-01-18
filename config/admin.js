module.exports = ({ env }) => ({
  auth: {
    secret: env('ADMIN_JWT_SECRET', '89e9e1c1c0ccd30032788d1574bb5ab3'),
  },
});
