const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail, getUserById) {

    passport.use(new LocalStrategy({
        usernameField: 'email'
    },
        async function (email, password, done) {

            const user = getUserByEmail(email)
            if (user == null) {
                return done(null, false, { message: 'No user with that email' })
            }
            try {
                if (await bcrypt.compare(password, user.password)) {
                    //Authenticated user
                    return done(null, user)

                } else { //Password did not match
                    return done(null, false, { message: 'Password incorrect' })
                }
            } catch (e) {
                return done(e)

            }

        }
    ))


    passport.serializeUser((user, done) => {
        return done(null, user.id)
    })

    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id))
    })
}

module.exports = initialize