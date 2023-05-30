const express = require('express')
const session = require('express-session')
const { Issuer, Strategy: OpenIDConnectStrategy } = require('openid-client');
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const JwtStrategy = require('passport-jwt').Strategy
//const ExtractJwt = require('passport-jwt').ExtractJwt
const JsonDB = require('node-json-db').JsonDB;
const Config = require('node-json-db/dist/lib/JsonDBConfig').Config;
const argon2 = require('argon2');
//const { time } = require('console')
const scryptMcf = require('scrypt-mcf')
//oauth2
const Client = require('node-radius-client');
const dotenv = require('dotenv')
dotenv.config()

const axios = require('axios')


async function main () {

  const app = express()
  const port = 3000

  app.use(logger('dev'))
  app.use(session({
    secret: require('crypto').randomBytes(32).toString('base64url'), // This is the secret used to sign the session cookie. We are creating a random base64url string with 256 bits of entropy.
    resave: false, // Default value is true (although it is going to be false in the next major release). We do not need the session to be saved back to the session store when the session has not been modified during the request.
    saveUninitialized: false // Default value is true (although it is going to be false in the next major release). We do not need sessions that are "uninitialized" to be saved to the store
  }))

  //FIXME 6.5. Add a strong key derivation function to the login process
  const db = new JsonDB(new Config("users.db", true, false, '/'));

  register = async(user, password, kdfstrong)=>{
          
          if(kdfstrong==true){
            console.time("hashsuperseguro")
            let hash= await scryptMcf.hash(password, { derivedKeyLength: 64, scryptParams: { logN: 19, r: 8, p: 2 } })//slower version more secure
            console.timeEnd("hashsuperseguro")
            db.push('/'+user, {username: user,password:hash})
          }else{
            console.time("hashmenosrapido")
            let hash=await scryptMcf.hash(password )//faster version
            console.timeEnd("hashmenosrapido")
            db.push('/'+user, {username: user,password:hash})
          }
          
  }
  //FIXME 6.5. Add a strong key derivation function to the login process
  //register('walrus','walrus',false)
  //register('nestor','123456',true)

  /*
  Configure the local strategy for using it in Passport.
  The local strategy requires a `verify` function which receives the credentials
  (`username` and `password`) submitted by the user.  The function must verify
  that the username and password are correct and then invoke `done` with a user
  object, which will be set at `req.user` in route handlers after authentication.
  */

  passport.use('username-password', new LocalStrategy(
    {
      usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
      passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
      session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
    },
    async function (username, password, done) {
      //FIXME 6.5. Add a strong key derivation function to the login process
      try {
        const theuser = await db.getData('/' + username)
        console.log(theuser)
      
        if (await scryptMcf.verify(password, theuser.password)) {
          const user = { 
            username: username,
            description: 'the only users that deserves to contact the fortune teller'
          }
          //var hash = await argon2.hash(password)
          console.log(username,password)//,hash)
          return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
        }
        return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
      } catch (err) {
        console.error(err)//error when can't find any data in db
        //res.status(500).send('Internal Server Error')
        return done(null, false)
      }
      //FIXME 6.5. Add a strong key derivation function to the login process
    }
  ))

  app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
  // We will store in the session the complete passport user object
  passport.serializeUser(function (user, done) {
    return done(null, user)
  })

  // The returned passport user is just the user object that is stored in the session
  passport.deserializeUser(function (user, done) {
    return done(null, user)
  })
  app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.
  app.use(cookieParser())
  //OPTIMIZE ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++6.3. Create the fortune-teller endpoint
  var cookieExtractor = function(req) {
    var token = null;
    if (req && req.cookies)
    {
        token = req.cookies['access_token'];
    }
    return token;
  };
  //res.send('hello world')
  var opts = {}
  opts.jwtFromRequest = cookieExtractor
  opts.secretOrKey = jwtSecret
  console.log(opts)
  passport.use(new JwtStrategy(opts, async function(jwt_payload, done) {
    try {
      // Check if the user is authenticated through Github OAuth
      if ((jwt_payload.iss === 'github.com' || jwt_payload.iss === 'google.es') && jwt_payload.key === 'exam' && jwt_payload.value === 'garcia') {
        return done(null, {username: jwt_payload.sub});
      }
      const theuser = await db.getData('/' + jwt_payload.sub)
      console.log("hasta el user")
      //return done(null,{username:jwt_payload.sub})
      if (theuser) {
        console.log("hasta el user")
        return done(null,{username:jwt_payload.sub})
      } else {
        console.log("no user")
        return done(null, false);
      }
    } catch (err) {
      console.error(err)//error when can't find any data in db
      //res.status(500).send('Internal Server Error')
      return done(null, false)
    }
  }));


  app.get('/',passport.authenticate('jwt',{session:false}) ,(req, res) => {
    console.log("ultima esperanza")
    res.send(fortune.fortune())
  })
  //OPTIMIZE +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++6.3. Create the fortune-teller endpoint
  // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++6.4. Add a logout endpoint----------------------------------------------------------
  app.get('/logout',(req, res) => {
    res
    .clearCookie("access_token")
    .status(200)
    .json({ message: "Successfully logged out 😏 🍀" });
  })
  // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++6.4. Add a logout endpoint----------------------------------------------------------
  app.get('/login',
    (req, res) => {
      res.sendFile('login.html', { root: __dirname })
    }
  )
  //FIXME 6.5. Add a strong key derivation function to the login process
  app.get('/signup',
    (req, res) => {
      res.sendFile('signup.html', { root: __dirname })
    }
  )
  app.post('/signup', async (req,res)=>{
      const {username,password,kdf}=req.body
      console.log(username,password,kdf)
      if(kdf=='true'){
        register(username,password,true)
      }else{
        register(username,password,kdf)
      }    
      res.redirect('/login')
      res.end()

  })
  //FIXME 6.5. Add a strong key derivation function to the login process
  /*app.get('/login', async (req, res) => {
    try {
      const us = 'walrus'
      const user = await db.getData('/' + us)
      console.log(user.password)
      res.sendFile('login.html', { root: __dirname })
    } catch (err) {
      console.error(err)
      res.status(500).send('Internal Server Error')
    }
  })*/






  app.get('/oauth2cb', async (req, res) => { // watchout the async definition here. It is necessary to be able to use async/await in the route handler
    try{
      /**
       * 1. Retrieve the authorization code from the query parameters
       */
      const code = req.query.code // Here we have the received code
      if (code === undefined) {
        console.log('nooooooooo funca')
        const err = new Error('no code provided')
        err.status = 400 // Bad Request
        throw err
      }

      /**
       * 2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
       */
      console.log('---------------------------------------------------------------------------------')
      console.log(code)
    
      const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.OAUTH2_CLIENT_ID,
      client_secret: process.env.OAUTH2_CLIENT_SECRET,
      code: code
      })
      /*const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.OAUTH2_CLIENT_ID,
      client_secret: process.env.OAUTH2_CLIENT_SECRET,
      code: code
      })*/
      console.log(tokenResponse.data) // response.data contains the params of the response, including access_token, scopes granted by the use and type.
    
    /**'https://github.com/login/oauth/access_token',
     * 3. Use the access token to retrieve the user email from the USER_API endpointprocess.env.OAUTH2_TOKEN_URL
     */
      
      // Let us parse them ang get the access token and the scope
      const params = new URLSearchParams(tokenResponse.data)
      const accessToken = params.get('access_token')
      const scope = params.get('scope')
      //console.log(params.toString());

      // if the scope does not include what we wanted, authorization fails
      if (scope !== 'user:email') {
        const err = new Error('user did not consent to release email')
        err.status = 401 // Unauthorized
        throw err
      }

      /**
       * 3. Use the access token to retrieve the user email from the USER_API endpoint/emails
       */
      const userDataResponse = await axios.get('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${accessToken}` // we send the access token as a bearer token in the authorization header
        }
      })
      console.log(userDataResponse.data+'---------++++++')
    

      /**
       * 4. Create our JWT using the github email as subject, and set the cookie.
       */
      // just copy and paste or invoke the function you used for creating the JWT for a user logging in with username and password.
      // get the user's email from GitHub[0].email
      const email = userDataResponse.data[0].email;
      console.log('--------------------------------------------')
      console.log(email)
      // This is what ends up in our JWT
      const jwtClaims = {
        sub: email, // use email as the subject
        iss: 'github.com',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user',// just to show a private JWT field
        key: 'exam',
        value: 'garcia'
      }

      // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
      const token = jwt.sign(jwtClaims, jwtSecret)

      // Set the cookie with the JWT and redirect
      res.cookie("access_token", token, {
        httpOnly: true,
        secure: true,
      }).redirect('/')

      // And let us log a link to the jwt.io debugger, for easy checking/verifying:
      console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
      console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    }catch (error) {
    console.error('An error occurred:', error)
    }

  })
  //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

  // 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
  const oidcIssuer = await Issuer.discover('https://accounts.google.com')

  // 2. Setup an OIDC client/relying party.
  const oidcClient = new oidcIssuer.Client({
    client_id: process.env.OIDC_CLIENT_ID,
    client_secret: process.env.OIDC_CLIENT_SECRET,
    redirect_uris: ['http://localhost:3000/oidc/cb'],
    response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
  })

  /*passport.use('oidc', new Strategy({
    client: oidcClient,
    usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
  }, (tokenSet, userInfo, done) => {
    console.log(tokenSet, userInfo)
    if (tokenSet === undefined || userInfo === undefined) {
      return done('no tokenSet or userInfo')
    }
    return done(null, userInfo)
  }))*/
  

  // 3. Configure the strategy.
  passport.use('oidc', new OpenIDConnectStrategy({
    client: oidcClient,
    usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
  }, (tokenSet, userInfo, done) => {
    console.log(tokenSet, userInfo)
    if (tokenSet === undefined || userInfo === undefined) {
      return done('no tokenSet or userInfo')
    }
    return done(null, userInfo)
  }))

  app.get('/oidc/login',
  passport.authenticate('oidc', { scope: 'openid email' })
  )

  app.get('/oidc/cb', 
  passport.authenticate('oidc', { failureRedirect: '/login', failureMessage: true }), 
  (req, res) => {
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.email,
      iss: 'google.es',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user',// just to show a private JWT field
      key: 'exam',
      value: 'garcia'
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // Set the cookie with the JWT and redirect
    res.cookie("access_token", token, {
      httpOnly: true,
      secure: true,
    }).redirect('/')

    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
  );

  const radclient = new Client({ 
    host: '127.0.0.1'
  })
  passport.use('local-radius', new LocalStrategy(
    {
      usernameField: "username",
      passwordField: "password"
    },
    async function (username, password, done) { 
      radclient.accessRequest({
        secret: 'testing123',
        attributes: [
          ["User-Name", username],
          ["User-Password", password]
        ]
      }).then((val) => {
        return done (null, {username: username})
      },
      (err) => {
        return done (null, false)
      })
    }
  ))
  // We will store in the session the complete 'username-password' passport user object local-radius

  app.post('/login', 
    passport.authenticate('local-radius', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
    (req, res) => { 
      // This is what ends up in our JWT
      const jwtClaims = {
        sub: req.user.username,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user',// just to show a private JWT field
        key: 'exam',
        value: 'garcia'
      }

      // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
      const token = jwt.sign(jwtClaims, jwtSecret)

      // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
      //TODO res.json(token)+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++6.2. Exchange the JWT using cookies
      res.cookie("access_token", token, {
        httpOnly: true,
        secure: true,
      }).redirect('/')//status(200).json({ message: "Logged in successfully 😊 👌 http://localhost:3000/" });
      //res.redirect('/')
      //TODO +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++6.2. Exchange the JWT using cookies
      
      // And let us log a link to the jwt.io debugger, for easy checking/verifying:
      console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
      console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
      res.end()
    }
  )

  app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
  })

  app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
  })
}main().catch(e => { console.log(e) })
