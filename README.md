# 🚀 Getting started with Strapi

---

# Add refresh cookies to Strapi V4

You need a running Strapi Instance with admin access and at least one user.

### `.env`

Add new entries to the .env file

```
REFRESH_SECRET=   add a new secret
REFRESH_TOKEN_EXPIRES=14d
JWT_SECRET_EXPIRES=360s
NODE_ENV=development
```

### `new folders and files`

```

1. add the folder "users-permissions" to the existing folder "extensions"
2. in this new folder create the file "strapi-server.js"
3. add a folder "controllers/validation" under the folder "users-permissions"
   inside of this folder create a file named "auth.js"
```

inside of this file add the following code, I made a few changes because I added a password check and some other fields to the user collection:

```
'use strict';

const { yup, validateYupSchema } = require('@strapi/utils');

const callbackBodySchema = yup.object().shape({
  identifier: yup.string().required(),
  password: yup.string().required(),
});

const registerBodySchema = yup.object().shape({
  email: yup
    .string()
    .email()
    .required(),
  username: yup
    .string()
    .min(3)
    .required(),
  password: yup.string().required().matches(
    /^.*(?=.{8,})((?=.*[!@#$%^&*()\-_=+{};:,<.>]){1})(?=.*\d)((?=.*[a-z]){1})((?=.*[A-Z]){1}).*$/,
    "Password must be min 8 characters, and have 1 Special Character, 1 Uppercase, 1 Number and 1 Lowercase"
  ),
  firstname: yup.string().required().min(3),
  lastname: yup.string().required().min(3).max(30)
});

const sendEmailConfirmationBodySchema = yup.object().shape({
  email: yup
    .string()
    .email()
    .required(),
});

module.exports = {
  validateCallbackBody: validateYupSchema(callbackBodySchema),
  validateRegisterBody: validateYupSchema(registerBodySchema),
  validateSendEmailConfirmationBody: validateYupSchema(sendEmailConfirmationBodySchema),
};
```

add the folder "utils" to the folder "user-permissions" and inside of this folder the file "index.js" with the following content :

```
'use strict';

const getService = name => {
  return strapi.plugin('users-permissions').service(name);
  return
};

module.exports = {
  getService,
};
```

### `add content to the file "strapi-server.js`

add the following content at the top of the file

```
const utils = require('@strapi/utils');
const { getService } = require('../users-permissions/utils');
const jwt = require('jsonwebtoken');

const {
    validateCallbackBody,
    validateRegisterBody,
    validateSendEmailConfirmationBody,
} = require('../users-permissions/controllers/validation/auth');
const { setMaxListeners } = require('process');

const { sanitize } = utils;
const { ApplicationError, ValidationError } = utils.errors;

const emailRegExp = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

const sanitizeUser = (user, ctx) => {
    const { auth } = ctx.state;
    const userSchema = strapi.getModel('plugin::users-permissions.user');

    return sanitize.contentAPI.output(user, userSchema, { auth });
};

module.exports = (plugin) => {
```

and at the bottom of the file

```
    return plugin

}
```

now we will add a copy of the existing "login" procedure from Strapi, which can be found in the node-modules folder under @strapi/plugin-users-permissions/server/controllers/auth.js

we will copy the whole part of

```
async callback(ctx) {
    ....
}
```

but we need to rename the procedure in the file "strapi-server.js"

It should look like:

```
   // replace the following code line
    //  async callback(ctx) {

    // with
    plugin.controllers.auth.callback = async (ctx) => {
        .........
```

to check if your procedure is being called instead of the Strapi ones place a console log inside a make a request with PostMan.

---

### `Now we need to modify the login procedure.`

lets add the following code to top of the plugin under the function "sanitizeUser"

```
// issue a JWT
const issueJWT = (payload, jwtOptions = {}) => {
    _.defaults(jwtOptions, strapi.config.get('plugin.users-permissions.jwt'));
    return jwt.sign(
        _.clone(payload.toJSON ? payload.toJSON() : payload),
        strapi.config.get('plugin.users-permissions.jwtSecret'),
        jwtOptions
    );
}

// verify the refreshToken by using the REFRESH_SECRET from the .env
const verifyRefreshToken = (token) => {
    return new Promise(function (resolve, reject) {
        jwt.verify(token, process.env.REFRESH_SECRET, {}, function (
            err,
            tokenPayload = {}
        ) {
            if (err) {
                return reject(new Error('Invalid token.'));
            }
            resolve(tokenPayload);
        });
    });
}

// issue a Refresh token
const issueRefeshToken = (payload, jwtOptions = {}) => {
    _.defaults(jwtOptions, strapi.config.get('plugin.users-permissions.jwt'));
    return jwt.sign(
        _.clone(payload.toJSON ? payload.toJSON() : payload),
        process.env.REFRESH_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRES }
    );
}

```

lets modify the follwing part :

```
  if (!validPassword) {
                throw new ValidationError('Invalid identifier or password');
            } else {
                ctx.send({
                    jwt: getService('jwt').issue({
                        id: user.id,
                    }),
                    user: await sanitizeUser(user, ctx),
                });
            }
```

we will implemnt our own create jwt token procedure, because we want to define the expiration time in our .env file. The key is to have a much shorter exp. time
an we will also create a refresh cookie
In a production environment you also have to change the value "domain"
you can use something like:

```
  domain:
     process.env.NODE_ENV === "development"
       ? "localhost"
       : process.env.PRODUCTION_URL,
```

the code looks now like

```
            if (!validPassword) {
                throw new ValidationError('Invalid identifier or password');
            } else {


                ctx.cookies.set("refreshToken", issueRefeshToken({ id: user.id }), {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production" ? true : false,
                    maxAge: 1000 * 60 * 60 * 24 * 14, // 14 Day Age
                    domain: "localhost",
                    sameSite: "strict"
                });
                ctx.send({
                    jwt: issueJWT({ id: user.id }, { expiresIn: process.env.JWT_SECRET_EXPIRES }),
                    /*                     jwt: getService('jwt').issue({
                                            id: user.id,
                                        }), */
                    user: await sanitizeUser(user, ctx),
                });



            }
        } else {
```

Add the following code after the callback procedure, we need a procedure to refresh the jwt

```
    /**
     * Creating a new token based on the refreshCookie
     *
     *
     * @param {*} ctx
     * @returns
     */
    plugin.controllers.auth['refreshToken'] = async (ctx) => {
        // get token from the POST request
        const store = await strapi.store({ type: 'plugin', name: 'users-permissions' });
        const refreshCookie = ctx.cookies.get("refreshToken")
        console.log(refreshCookie)
        if (!refreshCookie) {
            return ctx.badRequest("no Authorization");
        }
        try {
            const obj = await verifyRefreshToken(refreshCookie);
            console.log(obj)
            // Check if the user exists.
            const user = await strapi.query('plugin::users-permissions.user').findOne({ where: { id: obj.id } });
            console.log(user)
            if (!user) {
                throw new ValidationError('Invalid identifier or password');
            }

            if (
                _.get(await store.get({ key: 'advanced' }), 'email_confirmation') &&
                user.confirmed !== true
            ) {
                throw new ApplicationError('Your account email is not confirmed');
            }

            if (user.blocked === true) {
                throw new ApplicationError('Your account has been blocked by an administrator');
            }
            ctx.send({
                jwt: issueJWT({ id: obj.id }, { expiresIn: process.env.JWT_SECRET_EXPIRES }),
                /*                     jwt: getService('jwt').issue({
                                        id: user.id,
                                    }), */
            });
        }
        catch (err) {
            return ctx.badRequest(err.toString());
        }
    }
```

We also need a route to refresh our jwt. Add the following code to the file "strape-server.js" before the "return plugin" statement.

```
    plugin.routes['content-api'].routes.push({
        method: 'POST',
        path: '/token/refresh',
        handler: 'auth.refreshToken',
        config: {
            policies: [],
            prefix: '',
        }
    });
```

<b>You need to change the settings in the Roles for public user and allow the endpoint refreshToken.</b>

When you now create a login request with PostMan you should not only get a jwt but also a refreshCookie.

How to check if it works?

Create a collection in Strapi e.g. Post and add some fields.

Change the settings in the Roles for public user to allow find and findOne and for the authenticated user to allow find, findOne, create, update and delete.

Inside Postman call the login request (localhost:1337/api/auth/local) and copy the jwt which you are getting back. Check if you also received the cookie.

Now create a new request to create a post, paste the jwt into the header/auth bearer field. You should be able to create a post. Now wait until your jwt has been expired and try again. You get now an unauthorized response.
Something like:

```
{
    "data": null,
    "error": {
        "status": 401,
        "name": "UnauthorizedError",
        "message": "Missing or invalid credentials",
        "details": {}
    }
}
```

now create a new request in Postman for the route "localhost:1337/api/token/refresh", it's important the Postman uses your refresh cookie when calling this endpoint.

you should get a response like :

```
{
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNjQyNDk3MjE2LCJleHAiOjE2NDI0OTc1NzZ9.AXOgyUEQsW8RjMMno9w4PiSK4i9pWYSdA7uOD3BcGJ4"
}
```

which is the new jwt.

You can also delete your refresh cookie in Postman, now you will get a response with a failure message.

---

Refresh cookies will also open a way to create a logout route. You can simply delete the refresh cookie when calling this route (and of course the jwt on the client side),

Of course the jwt will be valid until the expiration date/time. But because we have a much shorter exp. time an existing jwt will expire soon.

There is only one way to invalidate a jwt - by changing the secret on the server. but this will invalidate all jwts.

---

## How to handle the refresh tokens on the client side

I store the jwt in the localstorage. Maybe not the best way, but because we have now a very short lifetime of this jwt, should this not be a problem. Of course you can store it also in the state of your app, but thenone has to handle the "refresh button". When a user clicks on the refresh button, all of your data in the state will be cleared. One can retrieve the jwt again, though - as long as you have the refresh cookie.

In my client app I add some code like:

````

  import axios from "axios";

  ......

  export const axiosJWT = axios.create()

  .......



  const getRefreshToken = async () => {
    try {
      //   console.log("getRefreshToken");
      let API = process.env.REACT_APP_BACKEND_URL

      const res = await axios.post(`${API}/token/refresh`, { withCredentials: true });

      return res.data;
    } catch (err) {
      console.log(err);
    }
  };

  axiosJWT.interceptors.request.use(
    async (config) => {
      const accessToken = getAccessToken()    // from local storage
      if (accessToken) {
        let currentDate = new Date();
        const decodedToken = jwt_decode(accessToken);
        if (decodedToken.exp * 1000 < currentDate.getTime()) {
          // console.log("get a new accesstoken")
          const data = await getRefreshToken();
          if (data) {
            storeJWTToken(data.jwt)   // to the local storage
            config.headers["authorization"] = "Bearer " + data.jwt;
          } else {
            // no auth header
          }
        } else {
          config.headers["authorization"] = "Bearer " + accessToken;
        }
      }
      return config;
    },
    (error) => {
      return Promise.reject(error);
    }
  );
  ```
````

For every authenticated request I use now "axiosJWT" instead of "axios"

## Further Strapi modifications

In Strapi we need to configure CORS by changing the file config/middleware.js

```
module.exports = [
  'strapi::errors',
  'strapi::security',
  // 'strapi::cors',
  {
    name: 'strapi::cors',
    config: {
      enabled: true,
      headers: ['Access-Control-Allow-Headers', 'withCredentials', 'Origin', 'Authorization', 'Accept', 'X-Requested-With', 'Content-Type', 'Access-Control-Request-Method', 'Access-Control-Request-Headers'],
      origin: ['http://localhost:3000', 'http://localhost:1337']
    }
  },
  'strapi::poweredBy',
  'strapi::logger',
  'strapi::query',
  'strapi::body',
  'strapi::favicon',
  'strapi::public',
];
```

---

Strapi comes with a full featured [Command Line Interface](https://docs.strapi.io/developer-docs/latest/developer-resources/cli/CLI.html) (CLI) which lets you scaffold and manage your project in seconds.

### `develop`

Start your Strapi application with autoReload enabled. [Learn more](https://docs.strapi.io/developer-docs/latest/developer-resources/cli/CLI.html#strapi-develop)

```
npm run develop
# or
yarn develop
```

### `start`

Start your Strapi application with autoReload disabled. [Learn more](https://docs.strapi.io/developer-docs/latest/developer-resources/cli/CLI.html#strapi-start)

```
npm run start
# or
yarn start
```

### `build`

Build your admin panel. [Learn more](https://docs.strapi.io/developer-docs/latest/developer-resources/cli/CLI.html#strapi-build)

```
npm run build
# or
yarn build
```

## ⚙️ Deployment

Strapi gives you many possible deployment options for your project. Find the one that suits you on the [deployment section of the documentation](https://docs.strapi.io/developer-docs/latest/setup-deployment-guides/deployment.html).

## 📚 Learn more

- [Resource center](https://strapi.io/resource-center) - Strapi resource center.
- [Strapi documentation](https://docs.strapi.io) - Official Strapi documentation.
- [Strapi tutorials](https://strapi.io/tutorials) - List of tutorials made by the core team and the community.
- [Strapi blog](https://docs.strapi.io) - Official Strapi blog containing articles made by the Strapi team and the community.
- [Changelog](https://strapi.io/changelog) - Find out about the Strapi product updates, new features and general improvements.

Feel free to check out the [Strapi GitHub repository](https://github.com/strapi/strapi). Your feedback and contributions are welcome!

## ✨ Community

- [Discord](https://discord.strapi.io) - Come chat with the Strapi community including the core team.
- [Forum](https://forum.strapi.io/) - Place to discuss, ask questions and find answers, show your Strapi project and get feedback or just talk with other Community members.
- [Awesome Strapi](https://github.com/strapi/awesome-strapi) - A curated list of awesome things related to Strapi.

---

<sub>🤫 Psst! [Strapi is hiring](https://strapi.io/careers).</sub>
