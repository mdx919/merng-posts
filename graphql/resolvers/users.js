const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const { UserInputError } = require('apollo-server')

const { validateRegisterInput, validateLoginInput } = require('../../util/validators')
const User = require('../../models/User')
const { SECRET_KEY } = require('../../config')

function generateToken(user) {
    return jwt.sign({
        id: user.id,
        email: user.email,
        userName: user.userName
    }, SECRET_KEY, { expiresIn: '1hr' })
}

module.exports = {
     Mutation: {
         async login(_, { userName, password }){
             const { errors, valid } = validateLoginInput(userName, password)
             const user = await User.findOne({ userName })
            if(!valid){
                throw new UserInputError('Errors', { errors })
            }
             if(!user) {
                 errors.general = 'User not found'
                 throw new UserInputError('User not found', { errors })
             }

             const match = await bcrypt.compare(password, user.password)
             if(!match){
                 errors.general = 'Wrong Credentials'
                 throw new UserInputError('Wrong Credentials', { errors })
             }

             const token = generateToken(user)

             return {
                ...user._doc,
                id: user._id,
                token
            }
         },
         async register(_, { registerInput: { userName, email, password, confirmPassword} }, context, info) {
             //validate user data
             const { valid, errors } = validateRegisterInput(userName, email, password, confirmPassword)
             if(!valid) {
                 throw new UserInputError('Errors', { errors })
             }
             //make sure user doesnt exist already
             const user = await User.findOne({ userName })
             if(user) {
                throw new UserInputError('Username is taken', { errors: {
                    username: 'This username is staken'
                }})
                    
             }
             //hash password and create an auth token
             password = await bcrypt.hash(password, 12)

             const newUser = new User({
                 email,
                 userName,
                 password,
                 createdAt: new Date().toISOString()
             })

             const res = await newUser.save()
             const token = generateToken(res)

             return {
                 ...res._doc,
                 id: res._id,
                 token
             }
         }
     }
}