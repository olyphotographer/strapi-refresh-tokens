const utils = require('@strapi/utils');
const { getService } = require('../users-permissions/utils');
const jwt = require('jsonwebtoken');

const _ = require('lodash');

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


module.exports = (plugin) => {

    // replace the following code line
    //  async callback(ctx) {

    // with
    plugin.controllers.auth.callback = async (ctx) => {

        const provider = ctx.params.provider || 'local';
        const params = ctx.request.body;

        const store = await strapi.store({ type: 'plugin', name: 'users-permissions' });
        console.log("login")
        if (provider === 'local') {
            if (!_.get(await store.get({ key: 'grant' }), 'email.enabled')) {
                throw new ApplicationError('This provider is disabled');
            }

            await validateCallbackBody(params);

            const query = { provider };

            // Check if the provided identifier is an email or not.
            const isEmail = emailRegExp.test(params.identifier);

            // Set the identifier to the appropriate query field.
            if (isEmail) {
                query.email = params.identifier.toLowerCase();
            } else {
                query.username = params.identifier;
            }

            // Check if the user exists.
            const user = await strapi.query('plugin::users-permissions.user').findOne({ where: query });

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

            // The user never authenticated with the `local` provider.
            if (!user.password) {
                throw new ApplicationError(
                    'This user never set a local password, please login with the provider used during account creation'
                );
            }

            const validPassword = await getService('user').validatePassword(
                params.password,
                user.password
            );

            if (!validPassword) {
                throw new ValidationError('Invalid identifier or password');
            } else {
                /*                 ctx.cookies.set("jwt", data.jwt, {
                                    httpOnly: true,
                                    secure: process.env.NODE_ENV === "production" ? true : false,
                                    maxAge: 1000 * 60 * 60 * 24 * 14, // 14 Day Age
                                    domain:
                                        process.env.NODE_ENV === "development"
                                            ? "localhost"
                                            : process.env.PRODUCTION_URL,
                                }); */



                ctx.cookies.set("refreshToken", issueRefeshToken({ id: user.id }), {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production" ? true : false,
                    maxAge: 1000 * 60 * 60 * 24 * 14, // 14 Day Age
                    domain:
                        process.env.NODE_ENV === "development"
                            ? "localhost"
                            : process.env.PRODUCTION_URL,
                    SameSite: "restrict"
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
            if (!_.get(await store.get({ key: 'grant' }), [provider, 'enabled'])) {
                throw new ApplicationError('This provider is disabled');
            }

            // Connect the user with the third-party provider.
            let user;
            let error;
            try {
                [user, error] = await getService('providers').connect(provider, ctx.query);
            } catch ([user, error]) {
                throw new ApplicationError(error.message);
            }

            if (!user) {
                throw new ApplicationError(error.message);
            }

            ctx.send({
                jwt: getService('jwt').issue({ id: user.id }),
                user: await sanitizeUser(user, ctx),
            });
        }
    }

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

    plugin.controllers.auth['logout'] = async (ctx) => {
        console.log("logout")
        // delete the refresh cookie
        ctx.cookies.set("refreshToken", "", {
            httpOnly: true,
            secure: false,
            maxAge: 1000 * 60 * 60 * 24 * 14, // 14 Day Age
            domain: "localhost",
            SameSite: "restrict"
        });
        ctx.send({
            "message": "ok"
        });
    }

    plugin.routes['content-api'].routes.push({
        method: 'POST',
        path: '/token/refresh',
        handler: 'auth.refreshToken',
        config: {
            policies: [],
            prefix: '',
        }
    });

    plugin.routes['content-api'].routes.push({
        method: 'GET',
        path: '/auth/logout',
        handler: 'auth.logout',
        config: {
            policies: [],
            prefix: '',
        }
    });


    return plugin

}